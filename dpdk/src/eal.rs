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
use dpdk_sys;
use tracing::{error, info, warn};

/// Safe wrapper around the DPDK Environment Abstraction Layer (EAL).
///
/// This is a zero-sized type that is used for lifetime management and to ensure that the Eal is
/// properly initialized and cleaned up.
#[derive(Debug)]
#[repr(transparent)]
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
    // TODO: queue
    // TODO: flow
}

unsafe impl Sync for Eal {}

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
    Eal {
        mem: mem::Manager::init(),
        dev: dev::Manager::init(),
        socket: socket::Manager::init(),
        lcore: lcore::Manager::init(),
    }
}

impl Eal {
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
