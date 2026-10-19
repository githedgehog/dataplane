// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End to end: the gateway image's init starts FRR under `--supervise-frr`, and takes all of it
//! down again.
//!
//! Runs the image itself rather than this build's binaries: FRR is compiled with the image's
//! absolute paths (`/libexec/frr`, `/lib/frr/modules`, `/etc/frr`), so it only runs from that
//! layout. The guest's root is read-only, so the layout is assembled on a tmpfs in a private mount
//! namespace and init is chrooted into it. The guest has no PID namespace, so init is not PID 1
//! here, which is the case where shutdown cannot fall back on `kill(-1)`.

use std::ffi::CString;
use std::fs;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::Duration;

use n_vm::config::VmConfig;
use n_vm::features;
use nix::mount::{MsFlags, mount};
use nix::net::if_::if_nametoindex;
use nix::sched::{CloneFlags, unshare};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rtnetlink::{LinkUnspec, LinkVeth};

/// The unpacked gateway image, compiled in by the nix test build.
const ROOTFS: Option<&str> = option_env!("DATAPLANE_TEST_GATEWAY_ROOTFS");

/// FRR, the agent and the dataplane together outgrow the default guest.
const VM: VmConfig = VmConfig::DEFAULT
    .to_builder()
    .memory_mib(2048)
    .kernel_features(&[features::VETH, features::TUN])
    .build();

/// Where the gateway's root is assembled. `/tmp` is the guest's writable tmpfs.
const ROOT: &str = "/tmp/gateway";

/// The gateway's port, and its peer, which stays behind to stand in for the fabric.
const PORT: &str = "dp0";
const FABRIC: &str = "fabric0";

/// What init has to stop: everything it starts, and every daemon watchfrr starts.
const GATEWAY_PROCESSES: &[&str] = &[
    "dataplane",
    "dataplane-init",
    "watchfrr",
    "zebra",
    "mgmtd",
    "staticd",
    "bgpd",
    "bfdd",
    "frr-agent",
];

/// Generous: a debug dataplane, and FRR, starting in a small VM.
const STARTUP: Duration = Duration::from_secs(120);

/// Init's own budget is 8 s of grace and 1 s for `SIGKILL`; leave room around it.
const SHUTDOWN: Duration = Duration::from_secs(20);

fn rootfs() -> PathBuf {
    PathBuf::from(ROOTFS.expect(
        "built without DATAPLANE_TEST_GATEWAY_ROOTFS; run this through `just test init`, which \
         builds the gateway image, or set it to the output of \
         `nix build -f default.nix gateway-rootfs`",
    ))
}

fn bind(source: &Path, target: &Path, flags: MsFlags) {
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | flags,
        None::<&str>,
    )
    .unwrap_or_else(|e| panic!("bind {} on {}: {e}", source.display(), target.display()));
}

fn mount_fs(kind: &str, target: &Path, data: Option<&str>) {
    mount(Some(kind), target, Some(kind), MsFlags::empty(), data)
        .unwrap_or_else(|e| panic!("mount {kind} on {}: {e}", target.display()));
}

/// Copy a directory tree, keeping symlinks as symlinks.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let (source, target) = (entry.path(), to.join(entry.file_name()));
        let kind = entry.file_type().unwrap();
        if kind.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(&source).unwrap(), &target).unwrap();
        } else if kind.is_dir() {
            copy_tree(&source, &target);
        } else {
            fs::copy(&source, &target).unwrap();
        }
    }
}

/// Lay the image out at [`ROOT`], in a mount namespace of this thread's own.
///
/// Children forked from this thread inherit it, which is how init sees it.
fn assemble_root(image: &Path) -> PathBuf {
    unshare(CloneFlags::CLONE_NEWNS).expect("a private mount namespace");
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .unwrap();

    let root = PathBuf::from(ROOT);
    fs::create_dir_all(&root).unwrap();
    // A fresh tmpfs, because the guest's /tmp is mounted noexec.
    mount_fs("tmpfs", &root, Some("mode=0755"));
    for dir in [
        "bin",
        "lib",
        "libexec",
        "nix/store",
        "proc",
        "sys",
        "dev",
        "run",
        "tmp",
        "var",
        "home",
    ] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }

    // As the image has them: read-only, and mostly symlinks into the store.
    for dir in ["bin", "lib", "libexec"] {
        bind(&image.join(dir), &root.join(dir), MsFlags::empty());
    }
    bind(
        Path::new("/nix/store"),
        &root.join("nix/store"),
        MsFlags::empty(),
    );
    // Writable, as in the image: FRR's configuration and the users it drops to live here.
    copy_tree(&image.join("etc"), &root.join("etc"));

    mount_fs("proc", &root.join("proc"), None);
    mount_fs("sysfs", &root.join("sys"), None);
    bind(Path::new("/dev"), &root.join("dev"), MsFlags::MS_REC);
    mount_fs("tmpfs", &root.join("run"), Some("mode=0755"));
    mount_fs("tmpfs", &root.join("tmp"), Some("mode=1777"));
    std::os::unix::fs::symlink("/run", root.join("var/run")).unwrap();
    for dir in ["run/frr/hh", "run/dataplane", "run/netns", "run/config"] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }
    root
}

/// Create the gateway's port and the fabric's end of it, both up.
fn create_port() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        let connection = tokio::spawn(connection);
        handle
            .link()
            .add(LinkVeth::new(PORT, FABRIC).up().build())
            .execute()
            .await
            .expect("a veth pair");
        let peer = if_nametoindex(FABRIC).unwrap();
        handle
            .link()
            .set(LinkUnspec::new_with_index(peer).up().build())
            .execute()
            .await
            .unwrap();
        connection.abort();
    });
}

/// A command run inside the gateway's root.
fn in_root(program: &str) -> Command {
    let root = CString::new(ROOT).unwrap();
    let mut command = Command::new(program);
    command.env_clear().env("PATH", "/bin");
    // SAFETY: chroot and chdir are async-signal-safe system calls, given strings made before fork.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            if libc::chroot(root.as_ptr()) != 0 || libc::chdir(c"/".as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

fn log(path: &Path) -> String {
    let mut text = String::new();
    if let Ok(mut file) = fs::File::open(path) {
        let _ = file.read_to_string(&mut text);
    }
    text
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = clock::deadline(timeout);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if clock::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Gateway processes still alive anywhere in the guest, by name.
fn gateway_processes() -> Vec<String> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").unwrap().flatten() {
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // `pid (comm) state ...`; comm may hold spaces and parentheses, so split at the last ')'.
        let Some((head, tail)) = stat.rsplit_once(')') else {
            continue;
        };
        let comm = head.split_once('(').map_or("", |(_, comm)| comm);
        let zombie = tail.trim_start().starts_with('Z');
        if !zombie && GATEWAY_PROCESSES.contains(&comm) {
            found.push(format!("{comm} ({})", entry.file_name().to_string_lossy()));
        }
    }
    found
}

#[cfg_attr(
    instrumented,
    ignore = "instrumented builds leave the gateway image out (see `wants-gateway` in default.nix)"
)]
#[cfg_attr(
    all(emulated, not(instrumented)),
    ignore = "the whole gateway, FRR included, under qemu-user is too slow to start within init's \
              readiness timeouts"
)]
#[n_vm::test(config = VM)]
fn supervised_frr_starts_and_stops_with_the_gateway() {
    let image = rootfs();
    let root = assemble_root(&image);
    create_port();

    let log_path = PathBuf::from("/tmp/gateway.log");
    let log_file = fs::File::create(&log_path).unwrap();
    let mut init = in_root("/bin/dataplane-init")
        .args([
            "--driver",
            "kernel",
            "--interface",
            PORT,
            "--supervise-frr",
            "--config-dir",
            "/run/config",
            "--name",
            "test-gw",
        ])
        .stdout(log_file.try_clone().unwrap())
        .stderr(log_file)
        .spawn()
        .expect("init should start");
    let fail = |what: &str| -> ! { panic!("{what}\n--- gateway log ---\n{}", log(&log_path)) };

    // Startup: the dataplane's control-plane socket, zebra serving, zebra's hh_dplane connected
    // to the dataplane, and the agent listening.
    let ready = [
        "run/frr/hh/dataplane.sock",
        "run/frr/zebra.vty",
        "run/frr/hh/plugin.sock",
        "run/frr/frr-agent.sock",
    ];
    let deadline = clock::deadline(STARTUP);
    while !ready.iter().all(|path| root.join(path).exists()) {
        if let Some(status) = init.try_wait().unwrap() {
            fail(&format!("init exited during startup: {status}"));
        }
        if clock::now() >= deadline {
            let missing: Vec<_> = ready.iter().filter(|p| !root.join(p).exists()).collect();
            fail(&format!("the gateway did not come up; missing {missing:?}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // The port left this namespace for the datapath's.
    assert!(
        if_nametoindex(PORT).is_err(),
        "{PORT} should have moved into the datapath namespace"
    );

    // FRR, in init's control namespace, sees the tap standing in for the port, and vtysh reaches
    // it there over loopback.
    let control = fs::File::open(format!("/proc/{}/ns/net", init.id())).unwrap();
    let control_fd = control.as_raw_fd();
    let mut vtysh = in_root("/bin/vtysh");
    vtysh.args(["-c", &format!("show interface {PORT}")]);
    // SAFETY: setns is an async-signal-safe system call on a descriptor opened before fork. It runs
    // after `in_root`'s chroot, which does not matter: the namespace is named by descriptor.
    #[allow(unsafe_code)]
    unsafe {
        vtysh.pre_exec(move || {
            if libc::setns(control_fd, libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let shown = vtysh.output().expect("vtysh should run");
    let stdout = String::from_utf8_lossy(&shown.stdout);
    if !stdout.contains(&format!("Interface {PORT}")) {
        fail(&format!(
            "vtysh did not show {PORT}: {}\nstdout: {stdout}\nstderr: {}",
            shown.status,
            String::from_utf8_lossy(&shown.stderr)
        ));
    }
    drop(control);

    // Shutdown: init stops on SIGTERM, successfully, within its budget.
    kill(
        Pid::from_raw(i32::try_from(init.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    match wait_with_timeout(&mut init, SHUTDOWN) {
        Some(status) if status.success() => {}
        Some(status) => fail(&format!("init exited {status} on SIGTERM")),
        None => {
            let _ = init.kill();
            fail("init did not stop on SIGTERM")
        }
    }

    // Nothing it started outlives it -- FRR's daemons included, which leave watchfrr's process
    // group and which, outside PID 1, nothing but init's own sweep can reach.
    let left = gateway_processes();
    if !left.is_empty() {
        fail(&format!("processes outlived the gateway: {left:?}"));
    }

    // And nothing holds the datapath namespace: when it goes, the kernel deletes the veth in it,
    // and the fabric's end with it.
    let deadline = clock::deadline(Duration::from_secs(10));
    while if_nametoindex(FABRIC).is_ok() {
        if clock::now() >= deadline {
            fail("the datapath namespace outlived the gateway: its veth is still here");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
