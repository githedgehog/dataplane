// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![warn(missing_docs)]

//! PID 1 inside the initramfs, for guest kernels whose root filesystem
//! transport is a module.
//!
//! # Why this exists at all
//!
//! A kernel with `CONFIG_VIRTIO_FS=y` mounts the workspace itself and boots
//! straight into [`n-it`]; no initramfs is involved and this binary never
//! runs.  A kernel with virtiofs as a *module* cannot, and the reason is
//! circular: mounting the workspace needs virtiofs, virtiofs is a module,
//! and the module tree lives on the workspace.
//!
//! The initramfs is the only way out, because the kernel unpacks it itself,
//! from memory, before any driver loads.  This is what runs from it.
//!
//! # Why it is separate from `n-it`
//!
//! `n-it` is dynamically linked against `/nix/store`, which is itself only
//! reachable *after* virtiofs is mounted.  It therefore cannot be the thing
//! that mounts virtiofs.  Splitting the job leaves this binary with a
//! dependency surface of syscalls alone, so linking it statically is
//! uncontroversial, and leaves `n-it` unconstrained -- which matters,
//! because that is where the interesting logic lives.
//!
//! # What it does *not* do
//!
//! No dependency resolution, no `modules.dep` parsing, no uevent handling.
//! The nix build already resolved the closure and its order with the real
//! `modprobe` against the real module tree, and wrote the answer to
//! [`MODULES_LOAD`].  Rediscovering it here would be reimplementing udev to
//! answer a question we know the answer to: this VM's device set is fixed,
//! because we built it.
//!
//! [`n-it`]: https://github.com/githedgehog/dataplane

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;

use nix::kmod::{ModuleInitFlags, finit_module};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::pivot_root;

use n_vm_protocol::{INIT_BINARY_PATH, VIRTIOFS_ROOT_TAG};

/// Ordered list of modules to load, one absolute path per line.
///
/// Written by the `mk-initramfs` derivation from `modprobe --show-depends`,
/// so dependencies already precede their dependents.
const MODULES_LOAD: &str = "/modules.load";

/// Where the real root is mounted before pivoting onto it.
const NEW_ROOT: &str = "/newroot";

fn main() {
    // Errors are reported by hand rather than by returning `Result` from
    // `main`, because the default formatting is `Debug` and this output is
    // read on a serial console, often by someone who does not yet know
    // which of the three tiers failed.  The prefix makes it greppable.
    if let Err(err) = run() {
        eprintln!("n-preinit: FATAL: {err}");
        eprintln!("n-preinit: the kernel will now panic, because PID 1 exited");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    // Before anything that can fail interestingly, so that what follows is
    // visible.  Best-effort by design -- see `open_console`.
    open_console();

    load_modules(Path::new(MODULES_LOAD))?;
    mount_new_root()?;
    pivot()?;
    exec_init()
}

/// Mounts `devtmpfs` and reopens stdio on the console.
///
/// The kernel does *not* auto-mount devtmpfs on this path: `devtmpfs_mount`
/// is called from `prepare_namespace`, which is skipped when a cpio supplies
/// the root.  So `/dev` starts empty, `/dev/console` does not exist, and the
/// kernel's own attempt to open an initial console has already failed with
/// "unable to open an initial console" -- leaving this process with no
/// usable stdio.
///
/// Best-effort: if it fails there is nowhere to report that it failed, and
/// giving up here would trade a silent boot for a silent boot that also does
/// not work.  The subsequent steps still run, and their failures still panic
/// the kernel, which is at least a signal.
fn open_console() {
    if std::fs::create_dir_all("/dev").is_err() {
        return;
    }
    if mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .is_err()
    {
        return;
    }

    let Ok(console) = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/console")
    else {
        return;
    };
    let fd = console.as_raw_fd();
    // SAFETY: `fd` is open for the duration of this block, and 0/1/2 are
    // valid descriptor numbers.  `dup2` onto an open descriptor closes it
    // first, which is the intent.
    for target in 0..=2 {
        unsafe {
            libc_dup2(fd, target);
        }
    }
}

/// `dup2(2)` without taking a `libc` dependency for one call.
///
/// # Safety
///
/// `oldfd` must be an open descriptor.
unsafe fn libc_dup2(oldfd: i32, newfd: i32) {
    unsafe extern "C" {
        fn dup2(oldfd: i32, newfd: i32) -> i32;
    }
    unsafe {
        dup2(oldfd, newfd);
    }
}

/// Loads every module named in `list`, in the order given.
///
/// A missing list is not an error: a kernel that needs no modules to reach
/// its root can still boot through an initramfs, and refusing to would make
/// the two boot paths gratuitously different.
fn load_modules(list: &Path) -> Result<(), String> {
    let contents = match std::fs::read_to_string(list) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("cannot read module list {}: {err}", list.display())),
    };

    for path in contents.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let module = File::open(path).map_err(|err| format!("cannot open module {path}: {err}"))?;
        // `finit_module` rather than `init_module`: the kernel reads the
        // image from the descriptor itself, so this never has to hold a
        // module in memory.  Empty parameter string -- anything needing
        // parameters would belong in the list format, not hardcoded here.
        finit_module(&module, c"", ModuleInitFlags::empty())
            .map_err(|err| format!("cannot load module {path}: {err}"))?;
    }
    Ok(())
}

/// Mounts the virtiofs root share at [`NEW_ROOT`].
///
/// Read-only, matching the direct boot path: the share is served by a
/// `--readonly` virtiofsd, and `root_filesystem_in_vm_is_read_only` asserts
/// the guest sees it that way.
fn mount_new_root() -> Result<(), String> {
    std::fs::create_dir_all(NEW_ROOT).map_err(|err| format!("cannot create {NEW_ROOT}: {err}"))?;

    mount(
        Some(VIRTIOFS_ROOT_TAG),
        NEW_ROOT,
        Some("virtiofs"),
        MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|err| {
        format!(
            "cannot mount virtiofs tag `{VIRTIOFS_ROOT_TAG}` at {NEW_ROOT}: {err}; \
             is the virtiofs module in {MODULES_LOAD}?"
        )
    })
}

/// Makes [`NEW_ROOT`] the root and detaches the initramfs.
///
/// Uses the `pivot_root(".", ".")` idiom rather than a separate `put_old`
/// directory: it needs no writable directory under the new root, which
/// matters because the new root is mounted read-only.  After the call the
/// old root is stacked over the new one at `.`, and detaching it there frees
/// the initramfs memory.
fn pivot() -> Result<(), String> {
    std::env::set_current_dir(NEW_ROOT)
        .map_err(|err| format!("cannot chdir to {NEW_ROOT}: {err}"))?;

    pivot_root(".", ".").map_err(|err| format!("pivot_root onto {NEW_ROOT} failed: {err}"))?;

    umount2(".", MntFlags::MNT_DETACH)
        .map_err(|err| format!("cannot detach the old root: {err}"))?;

    std::env::set_current_dir("/").map_err(|err| format!("cannot chdir to the new root: {err}"))
}

/// Replaces this process with the real init.
///
/// Forwards argv unchanged apart from `argv[0]`.  That is load-bearing: the
/// kernel hands everything after `--` on its command line to init as
/// arguments, and `n-it` reads them (`n-it/src/child.rs`) to learn which
/// test binary to run and which test to select.  Dropping them would boot a
/// VM that runs nothing.
///
/// Only returns on failure; on success this process no longer exists.
fn exec_init() -> Result<(), String> {
    let init = CString::new(INIT_BINARY_PATH)
        .map_err(|err| format!("{INIT_BINARY_PATH} is not a valid C string: {err}"))?;

    let mut argv = Vec::new();
    argv.push(init.clone());
    for arg in std::env::args_os().skip(1) {
        let bytes = arg.into_vec();
        argv.push(
            CString::new(bytes)
                .map_err(|err| format!("argument contains an interior NUL: {err}"))?,
        );
    }

    let err = nix::unistd::execv(&init, &argv).unwrap_err();
    Err(format!("cannot exec {INIT_BINARY_PATH}: {err}"))
}
