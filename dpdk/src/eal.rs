// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK Environment Abstraction Layer (EAL)
use crate::mem::RteAllocator;
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
    // NOTE: We need to be careful about freeing memory here!
    // After _init is called, we swap to another memory allocator (the dpdk allocator).
    // We can't free memory from the system allocator using the DPDK allocator.
    // The easiest way around this issue is
    // to make sure the memory used for initialization is completely freed
    // before swapping allocators.
    // The easiest way I know how to do that is by bundling the pre-shift logic into its own scope.
    // The system memory will be free by the time this scope closes.
    let eal = {
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
        // of how DPDK reorders `c_args`.  The `_reclaimed` Vec must
        // drop **before** the scope exits (and therefore before the
        // `RteAllocator::mark_initialized` allocator swap below) so
        // the system allocator that produced each CString is the one
        // that frees it.
        let mut c_args: Vec<*mut core::ffi::c_char> =
            args.0.drain(..).map(CString::into_raw).collect();
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
        }
    };
    // Shift to the DPDK allocator
    RteAllocator::mark_initialized();
    eal
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
