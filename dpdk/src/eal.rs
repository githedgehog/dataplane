// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK Environment Abstraction Layer (EAL)

use crate::{dev, lcore, mem, socket};
use alloc::ffi::CString;
use alloc::format;
use alloc::vec::Vec;
use core::ffi::c_int;
use core::fmt::{Debug, Display};
use dpdk_sys;
use std::alloc::{Allocator, Layout, System};
use std::ffi::CStr;
use std::os::raw::c_char;
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

#[derive(Debug)]
pub struct EalArgs {
    pub argc: c_int,
    pub argv: *mut *mut c_char,
}

#[derive(Debug, thiserror::Error)]
pub enum IllegalEalArguments {
    #[error("Too many EAL arguments: {0} is too many")]
    TooLong(usize),
    #[error("Found non ASCII characters in EAL arguments")]
    NonAscii,
    #[error("Found interior null byte in EAL arguments")]
    NullByte,
}

impl EalArgs {
    #[cold]
    pub fn new(args: &rkyv::Archived<Vec<CString>>) -> EalArgs {
        let mut system_args: Vec<*mut i8, System> = Vec::with_capacity_in(args.len(), System);
        for arg in args.iter() {
            let bytes = arg.as_bytes_with_nul();
            // args are over-aligned to (hopefully) make debug easier if we need to disect memory
            const EAL_ARG_ALIGNMENT: usize = 64;
            let layout = Layout::from_size_align(bytes.len(), EAL_ARG_ALIGNMENT)
                .unwrap_or_else(|e| unreachable!("invalid layout: {e}"));

            #[allow(clippy::expect_used)] // very unlikely and a fatal error in any case.
            let mut x = System
                .allocate_zeroed(layout)
                .expect("unable to allocate memory for eal arguments");
            unsafe { x.as_mut() }.copy_from_slice(bytes);
            system_args
                .push(Box::leak(unsafe { Box::from_raw_in(x.as_ptr(), System) }).as_mut_ptr() as *mut i8)
        }
        let boxed_slice = system_args.into_boxed_slice();
        let argc = boxed_slice.len() as c_int;
        let argv = Box::leak(boxed_slice).as_mut_ptr();
        EalArgs { argc, argv }
    }
}

/// Initialize the DPDK Environment Abstraction Layer (EAL).
///
/// # Panics
///
/// Panics if
///
/// 1. There are more than `c_int::MAX` arguments.
/// 2. The arguments are not valid ASCII strings.
/// 3. The EAL initialization fails.
/// 4. The EAL has already been initialized.
#[cold]
pub fn init(args: EalArgs) -> Eal {
    let ret = unsafe { dpdk_sys::rte_eal_init(args.argc, args.argv) };
    if ret < 0 {
        EalErrno::assert(unsafe { dpdk_sys::rte_errno_get() });
    }
    lcore::ServiceThread::register_thread_spawn_hook();
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
