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

/// Owns the EAL and its resources on the initializing thread.
/// Use [`Eal::shared`] to access services from other threads.
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
    /// Port ownership and teardown failures; see [`Eal::claim`].
    port_owner: dev::Ownership,
    /// Pins the handle to its creating thread; see the type documentation.
    _local: PhantomData<*const ()>,
    // TODO: queue
    // TODO: flow
}

/// Shared EAL services, valid while the owning [`Eal`] remains alive.
/// Socket queries are read-only; pool creation uses DPDK synchronization
/// and a locked registry. Teardown remains on the owning thread.
///
/// Device queries stay on the EAL thread to prevent races with port teardown.
/// Other threads can query a borrowed [`Dev`](crate::dev::Dev), which keeps its port open.
///
/// ```compile_fail,E0599
/// # use dataplane_dpdk::eal::EalShared;
/// fn query_any_port(shared: EalShared<'_>) { let _ = shared.dev(); }
/// ```
///
/// ```
/// # use dataplane_dpdk::eal::EalShared;
/// fn assert_shareable<T: Send + Sync + Copy>() {}
/// assert_shareable::<EalShared<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::eal::Eal;
/// fn assert_send<T: Send>() {}
/// assert_send::<Eal>();
/// ```
#[derive(Debug, Copy, Clone)]
pub struct EalShared<'eal> {
    /// Test-only, see [`EalShared::dev`].
    #[cfg(test)]
    dev: &'eal dev::Manager,
    socket: &'eal socket::Manager,
    mem: &'eal mem::Manager,
}

impl<'eal> EalShared<'eal> {
    /// Device queries for unit tests, serialized with port teardown by `test_support::PORT_LOCK`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn dev(&self) -> &'eal dev::Manager {
        self.dev
    }

    /// Socket (NUMA) topology queries.
    #[must_use]
    pub fn socket(&self) -> &'eal socket::Manager {
        self.socket
    }

    /// Shared memory pool creation.
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
/// Register the mbuf META field before exposing resources to workers.
/// Registration failure terminates startup through [`Eal::fatal_error`].
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
    // DPDK's OS thread-local state and C synchronization cannot be modelled; see `crate::sync`.
    // Gate EAL initialization rather than compilation so packages with a DPDK dev-dependency
    // can still model-check their pure Rust code.
    concurrency::with_shuttle! {
        panic!(
            "the DPDK EAL cannot be initialised under the shuttle backend: DPDK's per-thread state \
             is OS-thread-local and shuttle multiplexes its threads onto one OS thread. Nothing \
             here is model-checkable; see dpdk::sync."
        );
    }
    concurrency::with_loom! {
        panic!(
            "the DPDK EAL cannot be initialised under the loom backend: DPDK's per-thread state is \
             OS-thread-local and loom does not model OS threads. Nothing here is model-checkable; \
             see dpdk::sync."
        );
    }
    let mut args = ValidatedEalArgs::new(args).unwrap_or_else(|e| {
        Eal::fatal_error(e.to_string());
    });
    // EAL ignores argv[0]; reserve it so the first flag is parsed.
    args.0.insert(0, c"dataplane".to_owned());

    // `into_raw` gives the FFI mutable pointer provenance. The pinned DPDK
    // permutes argv but preserves string lengths and retains no pointers.
    // Save the original pointers so each allocation is reclaimed once.
    let mut c_args: Vec<*mut core::ffi::c_char> = args.0.drain(..).map(CString::into_raw).collect();
    let original_ptrs: Vec<*mut core::ffi::c_char> = c_args.clone();
    let ret = unsafe { dpdk_sys::rte_eal_init(c_args.len() as _, c_args.as_mut_ptr() as _) };
    // SAFETY: these are the original `into_raw` pointers. DPDK has returned,
    // retains none of them, and has not changed their NUL-terminated lengths.
    let _reclaimed: Vec<CString> = original_ptrs
        .into_iter()
        .map(|p| unsafe { CString::from_raw(p) })
        .collect();
    if ret < 0 {
        EalErrno::assert(unsafe { dpdk_sys::rte_errno_get() });
    }
    // SAFETY: EAL is initialized and no Rust resources have been exposed. Registration
    // writes process-global offset/mask values that remain fixed while workers use mbufs.
    let ret = unsafe { dpdk_sys::rte_flow_dynf_metadata_register() };
    if ret != 0 {
        Eal::fatal_error(format!(
            "failed to register RX metadata: {}",
            errno::ErrorCode::parse_i32(ret)
        ));
    }
    let port_owner = dev::Ownership::new().unwrap_or_else(|e| {
        Eal::fatal_error(format!("failed to allocate a port owner id: {e:?}"));
    });
    Eal {
        mem: mem::Manager::init(),
        dev: dev::Manager::init(),
        socket: socket::Manager::init(),
        lcore: lcore::Manager::init(),
        port_owner,
        _local: PhantomData,
    }
}

impl Eal {
    /// Claim a port on the EAL thread for [`DevConfig::apply`](dev::DevConfig::apply).
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`](dev::ClaimError) if the port does not exist or something else (a
    /// device built from an earlier claim, a bonding PMD, another process) already owns it.
    pub fn claim(&self, index: dev::DevIndex) -> Result<dev::PortClaim<'_>, dev::ClaimError> {
        dev::PortClaim::claim(&self.port_owner, &self.dev, index)
    }

    /// A shareable projection of the EAL services that are safe to use from any thread.
    ///
    /// Workers can query sockets and create pools while borrowing the EAL.
    #[must_use]
    pub fn shared(&self) -> EalShared<'_> {
        EalShared {
            #[cfg(test)]
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

        // DPDK waits for ROLE_RTE lcores, but LCore registers ROLE_NON_EAL threads.
        // Callers must join those before cleanup detaches memory and frees per-lcore storage.
        // Scoped workers borrowing EAL-branded ports satisfy this ordering.
        let stragglers = (0..dpdk_sys::RTE_MAX_LCORE)
            .filter(|id| unsafe {
                dpdk_sys::rte_lcore_has_role(*id, dpdk_sys::rte_lcore_role_t::ROLE_NON_EAL) != 0
            })
            .count();
        if stragglers > 0 {
            error!(
                "{stragglers} thread(s) are still registered with the EAL as it is torn down. \
                 Every registered thread must be joined first: cleanup detaches DPDK memory and \
                 frees per-lcore storage, so anything still running will read freed memory. This \
                 is a bug in whatever spawned them."
            );
        }

        // Close ports before freeing pools; recorded close failures require retaining the pools.
        let abandoned = self.port_owner.close_abandoned();
        if self.port_owner.teardown_failed() {
            error!(
                "{stuck} abandoned port(s) could not be closed, or an earlier close \
                 failed; leaking every mempool rather than freeing memory a driver may still use",
                stuck = abandoned.stuck
            );
        } else {
            // SAFETY: every port this EAL claimed closed successfully -- by its `Dev`, or just
            // above -- so no driver holds mbufs from these pools, and no `Pool` handle can still
            // exist since every handle borrows this `Eal`.
            unsafe { self.mem.release_all() };
        }
        self.port_owner.release_all();

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
