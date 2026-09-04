// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK Environment Abstraction Layer (EAL)
use crate::{dev, lcore, mem, socket};
use alloc::ffi::CString;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::ffi::c_int;
use core::fmt::{Debug, Display};
use core::marker::PhantomData;
use dpdk_sys;
use tracing::{error, info, warn};

/// Safe wrapper around the DPDK Environment Abstraction Layer (EAL).
///
/// Owns the EAL for the process: dropping it releases every registered mempool and then calls
/// [`rte_eal_cleanup`](dpdk_sys::rte_eal_cleanup).
///
/// # Thread affinity
///
/// `Eal` is `!Send` and `!Sync`, so the handle stays on the thread that created it. That thread is
/// the main lcore by DPDK's own contract -- `rte_eal_init` "is to be executed on the MAIN lcore
/// only", and the thread that calls it *becomes* the main lcore -- so pinning the handle there
/// keeps teardown on a predictable thread rather than wherever the value happened to be moved.
///
/// To use EAL services from another thread, take a [`shared`](Self::shared) projection. That is
/// the point of the split: `Eal` will grow state that genuinely cannot be shared (a QSBR publisher
/// is `!Sync` by design, and the pool registry wants a single owner), and this type previously
/// carried a bare `unsafe impl Sync` with no justification at all. Nothing reachable through it
/// was unsound at the time, but the assertion pre-approved every future field, which is exactly
/// backwards. [`EalShared`] instead exposes a subset chosen because each operation in it has a
/// thread-safety argument.
#[derive(Debug)]
#[non_exhaustive]
pub struct Eal {
    /// The memory manager.
    ///
    /// You can find memory services here, including memory pools and mem buffers.
    pub mem: mem::Manager,
    /// The device manager.
    ///
    /// You can find ethernet device services here.
    pub dev: dev::Manager,
    /// Socket manager.
    ///
    /// You can find socket services here.
    pub socket: socket::Manager,

    /// LCore manager
    ///
    /// You can manage logical cores and task dispatch here.
    pub lcore: lcore::Manager,
    /// Pins the handle to its creating thread; see the type documentation.
    ///
    /// Not [`Local<Eal>`](concurrency::local::Local) only because the manager fields above are
    /// public and reached as `eal.dev`, which a wrapper would turn into `eal.as_ref().dev` at
    /// every call site for no gain here. `Local` remains the right tool for wrapping a value whose
    /// interior is not a public namespace.
    _local: PhantomData<*const ()>,
    // TODO: queue
    // TODO: flow
}

/// The subset of EAL services that are safe to use from any thread.
///
/// Obtained from [`Eal::shared`], `Copy`, and `Send + Sync` -- not by assertion, but because every
/// operation reachable through it is a read-only DPDK query:
///
/// - [`dev`](Self::dev): `rte_eth_dev_info_get`, `rte_eth_dev_count_avail` and
///   `rte_eth_find_next_owned_by`, which read ethdev's port table without mutating it. Note this
///   is deliberately *only* the query surface -- configuring a device goes through
///   [`DevConfig::apply`](crate::dev::DevConfig::apply), which is not reachable from here.
/// - [`socket`](Self::socket): NUMA and lcore-to-socket lookups, all reads of static topology.
/// - [`has_pci`](Self::has_pci): `rte_eal_has_pci`, a read of a flag fixed at init.
///
/// - [`mem`](Self::mem): mempool creation. `rte_pktmbuf_pool_create` is internally locked and the
///   pool registry is behind a mutex, so this is safe from any thread. Note it was *absent* from
///   this projection while `mem::Manager` owned a `!Sync` reclaimer; the reclaimer is gone, so the
///   manager is shareable again -- and pool creation needs to be reachable from a thread that does
///   not own the `Eal`, since a test cannot know which thread initialised it.
///
/// Releasing pools is deliberately *not* here: it happens once, from the owning `Eal`'s `Drop`.
/// The `lcore` manager is absent because it has no public methods at all.
///
/// The projection borrows the [`Eal`], so it cannot outlive the EAL it describes.
///
/// It is `Send + Sync + Copy`, so it can be handed to every worker:
///
/// ```
/// # use dataplane_dpdk::eal::EalShared;
/// fn assert_shareable<T: Send + Sync + Copy>() {}
/// assert_shareable::<EalShared<'static>>();
/// ```
///
/// whereas the owning [`Eal`] cannot cross a thread boundary at all:
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::eal::Eal;
/// fn assert_send<T: Send>() {}
/// assert_send::<Eal>();
/// ```
#[derive(Debug, Copy, Clone)]
pub struct EalShared<'eal> {
    dev: &'eal dev::Manager,
    socket: &'eal socket::Manager,
    mem: &'eal mem::Manager,
}

impl<'eal> EalShared<'eal> {
    /// Ethernet device *queries*. See the type documentation for why only queries.
    #[must_use]
    pub fn dev(&self) -> &'eal dev::Manager {
        self.dev
    }

    /// Socket (NUMA) topology queries.
    #[must_use]
    pub fn socket(&self) -> &'eal socket::Manager {
        self.socket
    }

    /// Memory pool creation. See the type documentation for why this is shareable.
    #[must_use]
    pub fn mem(&self) -> &'eal mem::Manager {
        self.mem
    }

    /// Returns `true` if the [`Eal`] is using the PCI bus.
    #[must_use]
    pub fn has_pci(&self) -> bool {
        // SAFETY: reads a flag fixed during `rte_eal_init`; no mutation, no thread affinity.
        unsafe { dpdk_sys::rte_eal_has_pci() != 0 }
    }

    /// The **calling thread's** DPDK error number.
    ///
    /// `rte_errno` is thread-local, so this reports the errno of whichever thread asks -- which is
    /// what a caller wants, but note it is not a property of the EAL shared between threads.
    pub fn errno(&self) -> errno::ErrorCode {
        errno::ErrorCode::parse_i32(unsafe { dpdk_sys::rte_errno_get() })
    }
}

/// Error type for EAL initialization failures.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error(transparent)]
    InvalidArguments(IllegalEalArguments),
    #[error("The EAL has already been initialized")]
    AlreadyInitialized,
    #[error("The EAL initialization failed")]
    InitializationFailed(errno::Errno),
    /// [`dpdk_sys::rte_eal_init`] returned an error code other than `0` (success) or `-1`
    /// (failure).
    /// This likely represents a bug in the DPDK library.
    #[error("Unknown error {0} when initializing the EAL")]
    UnknownError(i32),
}

#[repr(transparent)]
#[derive(Debug)]
struct ValidatedEalArgs(Vec<CString>);

#[derive(Debug, thiserror::Error)]
pub enum IllegalEalArguments {
    #[error("Too many EAL arguments: {0} is too many")]
    TooLong(usize),
    #[error("Found non ASCII characters in EAL arguments")]
    NonAscii,
    #[error("Found interior null byte in EAL arguments")]
    NullByte,
}

impl ValidatedEalArgs {
    #[cold]
    #[tracing::instrument(level = "info", skip(args), ret)]
    fn new(
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<ValidatedEalArgs, IllegalEalArguments> {
        let args: Vec<_> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
        let len = args.len();
        // Reserve one slot for the argv[0] placeholder that `init` prepends
        // before calling rte_eal_init.  Without this, len == c_int::MAX as
        // usize would pass validation here and then overflow the i32 cast
        // when computing argc for rte_eal_init.
        const MAX_USER_ARGS: usize = (c_int::MAX as usize).saturating_sub(1);
        if len > MAX_USER_ARGS {
            return Err(IllegalEalArguments::TooLong(len));
        }
        match args.iter().find(|s| !s.is_ascii()) {
            None => {}
            Some(_) => return Err(IllegalEalArguments::NonAscii),
        }
        let args_as_c_strings: Result<Vec<_>, _> =
            args.iter().map(|s| CString::new(s.as_bytes())).collect();

        // Account for the possibility of an illegal null byte in the arguments.
        let args_as_c_strings = match args_as_c_strings {
            Ok(c_strs) => c_strs,
            Err(_null_err) => return Err(IllegalEalArguments::NullByte),
        };

        Ok(ValidatedEalArgs(args_as_c_strings))
    }
}

/// Returns a DPDK `--lcores` argument value (e.g. `"0@(0,2,4,6)"`) that maps
/// lcore 0 to every CPU currently allowed for the calling thread.
///
/// Without an explicit `-l`/`-c`/`--lcores` argument, `rte_eal_init` derives
/// a default main-lcore cpuset containing exactly one CPU (see
/// `eal_common_lcore.c`), and then calls `rte_thread_set_affinity_by_id` to
/// pin the *calling* thread to that single-CPU cpuset. Since every thread
/// dataplane spawns afterward (tokio workers, driver workers, ...) inherits
/// the calling thread's affinity mask at creation time, that default narrows
/// the whole process down to one core. Passing this value as `--lcores`
/// keeps the main lcore's cpuset equal to the CPUs actually available to the
/// process (respecting cgroup cpusets, `taskset`, `isolcpus`, etc.) instead
/// of DPDK's single-CPU default.
///
/// # Panics
///
/// - Panics if the calling thread's CPU affinity cannot be queried.
/// - Panics if there are no available CPUs in the result of `sched_getaffinity`.
#[must_use]
#[allow(clippy::expect_used)]
pub fn main_lcore_arg() -> String {
    use nix::sched::{CpuSet, sched_getaffinity};
    use nix::unistd::Pid;
    // Startup-only helper; failure to query thread affinity is unrecoverable
    let set = sched_getaffinity(Pid::from_raw(0)).expect("sched_getaffinity");
    let cpus = (0..CpuSet::count())
        .filter(|&i| set.is_set(i).unwrap_or(false))
        .collect::<Vec<_>>();
    assert_ne!(cpus.len(), 0, "CPU affinity empty!");
    let cpu_list = cpus
        .iter()
        .map(|&x| x.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("0@({cpu_list})")
}

/// Initialize the DPDK Environment Abstraction Layer (EAL).
///
/// # Panics
///
/// Panics if
///
/// 1. There are more than `c_int::MAX - 1` arguments (the `-1` reserves a
///    slot for the `argv[0]` placeholder).
/// 2. The arguments are not valid ASCII strings.
/// 3. The EAL initialization fails.
/// 4. The EAL has already been initialized.
#[cold]
pub fn init(args: impl IntoIterator<Item = impl AsRef<str>>) -> Eal {
    let mut args = ValidatedEalArgs::new(args).unwrap_or_else(|e| {
        Eal::fatal_error(e.to_string());
    });
    // EAL treats argv[0] as the program name and ignores it; this
    // slot would otherwise eat the first real flag.  We sidestep
    // this by prepending a placeholder program name as the first
    // owned CString.
    args.0.insert(0, c"dataplane".to_owned());

    // Move every CString into a raw `*mut c_char` via
    // `CString::into_raw`.  This is the only safe way to obtain a
    // pointer with full mutable provenance for FFI: `as_ptr()` on
    // a `CString` (or `&CString` reborrowed from `&mut CString`)
    // carries SharedReadOnly provenance under Stacked / Tree
    // Borrows, and any write through `as_ptr().cast_mut()` would
    // be UB even though the allocation is writable.
    //
    // The pinned DPDK source (`rte_eal_init` + its getopt-based
    // option parser) only permutes the argv **pointer array** --
    // it does not modify the bytes of any individual argv string
    // and does not change any string's NUL-terminated length.
    // The `CString::from_raw` cleanup below depends on that:
    // `from_raw` is only sound if the string length is unchanged
    // from what `into_raw` produced.
    //
    // We still use `into_raw` (rather than `as_ptr().cast_mut()`)
    // because `rte_eal_init`'s public contract permits the EAL or
    // any argument parser it calls to modify argv strings in
    // place (`setproctitle`-style program-name manipulation,
    // `getopt_long`-style `optarg` rewrites).  Our pinned DPDK
    // does not exercise that allowance, but `into_raw` gives us
    // mut-clean pointer provenance regardless.  If a future DPDK
    // upgrade ever started rewriting argv strings in place, the
    // round-trip here is still pointer-provenance-sound but the
    // reclamation path would need to switch to a non-length-
    // dependent strategy (e.g. `libc::free` on the original
    // pointers, then `mem::forget` the CStrings).
    //
    // Reclamation note: `rte_eal_init` does getopt-style permutation
    // on the argv array, so the order in `c_args` after the FFI
    // call is **not** the order on entry.  We snapshot the
    // pre-init pointer list in `original_ptrs` to reclaim each
    // CString exactly once with `CString::from_raw`, regardless
    // of how DPDK reorders `c_args`.
    let mut c_args: Vec<*mut core::ffi::c_char> = args.0.drain(..).map(CString::into_raw).collect();
    let original_ptrs: Vec<*mut core::ffi::c_char> = c_args.clone();
    let ret = unsafe { dpdk_sys::rte_eal_init(c_args.len() as _, c_args.as_mut_ptr() as _) };
    // SAFETY: each pointer in `original_ptrs` came from
    // `CString::into_raw` above; we have not transferred ownership
    // elsewhere (DPDK does not retain pointers from argv after
    // `rte_eal_init` returns).  Using the pre-init snapshot avoids
    // aliasing if DPDK permuted `c_args`.
    let _reclaimed: Vec<CString> = original_ptrs
        .into_iter()
        .map(|p| unsafe { CString::from_raw(p) })
        .collect();
    if ret < 0 {
        EalErrno::assert(unsafe { dpdk_sys::rte_errno_get() });
    }
    Eal {
        mem: mem::Manager::init(),
        dev: dev::Manager::init(),
        socket: socket::Manager::init(),
        lcore: lcore::Manager::init(),
        _local: PhantomData,
    }
}

impl Eal {
    /// A shareable projection of the EAL services that are safe to use from any thread.
    ///
    /// This is how a worker thread gets at device and socket queries: the `Eal` handle itself is
    /// `!Send`, but [`EalShared`] is `Copy + Send + Sync` and borrows from it.
    #[must_use]
    pub fn shared(&self) -> EalShared<'_> {
        EalShared {
            dev: &self.dev,
            socket: &self.socket,
            mem: &self.mem,
        }
    }

    /// Returns `true` if the [`Eal`] is using the PCI bus.
    ///
    /// This is mostly a safe wrapper around [`dpdk_sys::rte_eal_has_pci`]
    /// which simply converts the return value to a [`bool`] instead of a [`c_int`].
    #[cold]
    #[tracing::instrument(level = "trace", skip(self), ret)]
    pub fn has_pci(&self) -> bool {
        unsafe { dpdk_sys::rte_eal_has_pci() != 0 }
    }

    /// Exits the DPDK application with an error message, cleaning up the [`Eal`] as gracefully as
    /// possible (by way of [`dpdk_sys::rte_exit`]).
    ///
    /// This function never returns as it exits the application.
    ///
    /// # Panics
    ///
    /// Panics if the error message cannot be converted to a `CString`.
    #[cold]
    pub fn fatal_error<T: Display + AsRef<str>>(message: T) -> ! {
        error!("{message}");
        let message_cstring = CString::new(message.as_ref()).unwrap_or_else(|_| unsafe {
            dpdk_sys::rte_exit(1, c"Failed to convert exit message to CString".as_ptr())
        });
        unsafe { dpdk_sys::rte_exit(1, message_cstring.as_ptr()) }
    }

    /// Get the DPDK `rte_errno` and parse it as an [`errno::ErrorCode`].
    #[tracing::instrument(level = "trace", skip(self), ret)]
    pub fn errno(&self) -> errno::ErrorCode {
        errno::ErrorCode::parse_i32(unsafe { dpdk_sys::rte_errno_get() })
    }
}

impl Drop for Eal {
    /// Clean up the DPDK Environment Abstraction Layer (EAL).
    ///
    /// This is called automatically when the `Eal` is dropped and generally should not be called
    /// manually.
    ///
    /// # Panics
    ///
    /// Panics if the EAL cleanup fails for some reason.
    /// EAL cleanup failure is potentially serious as it can leak hugepage file descriptors and
    /// make application restart complex.
    ///
    /// Failure to clean up the EAL is almost certainly an unrecoverable error anyway.
    #[cold]
    #[allow(clippy::panic)]
    #[tracing::instrument(level = "info", skip(self))]
    fn drop(&mut self) {
        info!("waiting on EAL threads");
        unsafe { dpdk_sys::rte_eal_mp_wait_lcore() };

        // Retire every mempool and wait for the workers to release them.
        //
        // This lives here, in the `Drop` *body*, rather than in `mem::Manager`'s `Drop`, because a
        // struct's `Drop` body runs before its fields are dropped: on the field it would run
        // *after* `rte_eal_cleanup` below, which is far too late.
        //
        // Unlike the unconditional free this replaced, it no longer has to *assume* that nothing
        // still references the pools -- it waits until every worker has said so, and leaks loudly
        // if one never does.  Devices are covered separately and earlier: a `Dev` cannot outlive
        // the borrow a worker holds on it, and its own `Drop` stops and closes the port, which is
        // what returns the PMD's mbufs to their pools.
        // SAFETY: every device is already closed -- a `Dev` borrows this `Eal`, so it cannot
        // still be alive here -- and no `Pool` handle can exist either, for the same reason.  A
        // stray handle outliving the EAL, which previously needed a runtime guard to stop it
        // freeing a mempool against a dismantled EAL, is now unrepresentable.
        unsafe { self.mem.release_all() };

        info!("Closing EAL");
        let ret = unsafe { dpdk_sys::rte_eal_cleanup() };
        if ret != 0 {
            let panic_msg = format!("Failed to cleanup EAL: error {ret}");
            error!("{panic_msg}");
            panic!("{panic_msg}");
        }
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct EalErrno(c_int);

impl EalErrno {
    #[allow(clippy::expect_used)]
    #[inline]
    pub fn assert(ret: c_int) {
        if ret == 0 {
            return;
        }
        let ret_msg = unsafe { dpdk_sys::rte_strerror(ret) };
        let ret_msg = unsafe { CStr::from_ptr(ret_msg) };
        let ret_msg = ret_msg.to_str().expect("dpdk message is not valid unicode");
        Eal::fatal_error(ret_msg)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::with_eal;

    /// The point of the projection: EAL queries work from a thread that does not and cannot hold
    /// the `Eal` itself.
    #[test]
    #[with_eal]
    fn the_projection_answers_queries_from_another_thread() {
        let shared = crate::test_support::start_eal();

        let here_sockets = shared.socket().count();
        let here_devices = shared.dev().num_devices();
        assert!(here_sockets >= 1, "a running EAL has at least one socket");

        // `EalShared` is `Copy + Send`, so it moves into the thread by value.
        let (there_sockets, there_devices) =
            std::thread::spawn(move || (shared.socket().count(), shared.dev().num_devices()))
                .join()
                .expect("far thread panicked");

        assert_eq!(here_sockets, there_sockets);
        assert_eq!(here_devices, there_devices);
    }

    /// `errno` is per-thread, and the projection's documentation promises exactly that -- so the
    /// promise is tested rather than asserted.
    ///
    /// `rte_errno` is set by provoking a real DPDK failure (creating a pool whose name is already
    /// taken), since `rte_errno_set` is not exported. A thread that has not failed at anything
    /// must not see it.
    #[test]
    #[with_eal]
    fn errno_is_reported_per_thread() {
        use crate::mem::{PoolConfig, PoolParams};

        let shared = crate::test_support::start_eal();
        let params = PoolParams {
            size: 63,
            cache_size: 0,
            ..Default::default()
        };
        let config = |()| {
            PoolConfig::new("errno_probe_pool", params).unwrap_or_else(|e| panic!("config: {e:?}"))
        };
        let _first = shared
            .mem()
            .new_pkt_pool(config(()))
            .expect("first create should succeed");
        // Same name again: DPDK refuses and sets this thread's `rte_errno`.
        shared
            .mem()
            .new_pkt_pool(config(()))
            .expect_err("a duplicate pool name must be refused");

        let here = shared.errno();
        assert_ne!(
            here,
            errno::ErrorCode::parse_i32(0),
            "the failed create should have set this thread's rte_errno"
        );

        let there = std::thread::spawn(move || shared.errno())
            .join()
            .expect("far thread panicked");
        assert_ne!(
            here, there,
            "rte_errno is thread-local, so a thread that has not failed must not observe ours"
        );
    }

    /// `has_pci` reads a flag fixed at init, so it is the same everywhere.
    #[test]
    #[with_eal]
    fn has_pci_agrees_across_threads() {
        let shared = crate::test_support::start_eal();
        let here = shared.has_pci();
        let there = std::thread::spawn(move || shared.has_pci())
            .join()
            .expect("far thread panicked");
        assert_eq!(here, there);
        // The test EAL is started with `--no-pci`.
        assert!(!here, "the test EAL should have no PCI bus");
    }
}
