// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK Environment Abstraction Layer (EAL)
use crate::{dev, mem, socket};
use alloc::ffi::CString;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::c_int;
use core::fmt::{Debug, Display};
use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use dpdk_sys::*;
use errno::Errno;
use std::ffi::{c_char, CStr};
use allocator_api2::alloc::Allocator;
use tracing::{error, info};

type SystemVec<T> = allocator_api2::vec::Vec<T, System>;

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
    // TODO: queue
    // TODO: flow
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
    /// [`rte_eal_init`] returned an error code other than `0` (success) or `-1` (failure).
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
        if len > c_int::MAX as usize {
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
/// # Errors
///
/// Returns an `Err` if
///
/// 1. There are more than `c_int::MAX` arguments.
/// 2. The arguments are not valid ASCII strings.
/// 3. The EAL initialization fails.
/// 4. The EAL has already been initialized.
#[cold]
#[tracing::instrument(level = "info", skip(args), ret)]
pub fn init(args: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Eal, InitError> {
    let mut args = ValidatedEalArgs::new(args).map_err(InitError::InvalidArguments)?;
    let mut c_args: Vec<_> = args.0.iter_mut().map(|s| s.as_ptr().cast_mut()).collect();
    let ret = unsafe { rte_eal_init(c_args.len() as c_int, c_args.as_mut_ptr()) };
    if ret < 0 {
        let rte_errno = unsafe { wrte_errno() };
        let error = errno::Errno::from(rte_errno);
        error!("EAL initialization failed: {error:?} (rte_errno: {rte_errno})");
        Err(InitError::InitializationFailed(error))
    } else {
        info!("EAL initialized successfully");
        Ok(Eal {
            mem: mem::Manager::init(),
            dev: dev::Manager::init(),
            socket: socket::Manager::init(),
        })
    }
}

impl Eal {
    /// Returns `true` if the [`Eal`] is using the PCI bus.
    ///
    /// This is mostly a safe wrapper around [`rte_eal_has_pci`]
    /// which simply converts the return value to a [`bool`] instead of a [`c_int`].
    #[tracing::instrument(level = "trace", ret)]
    pub fn has_pci(&self) -> bool {
        unsafe { rte_eal_has_pci() != 0 }
    }

    /// Exits the DPDK application with an error message, cleaning up the [`Eal`] as gracefully as
    /// possible (by way of [`rte_exit`]).
    ///
    /// This function never returns as it exits the application.
    ///
    /// # Panics
    ///
    /// Panics if the error message cannot be converted to a `CString`.
    #[allow(clippy::expect_used)]
    pub(crate) fn fatal_error<T: Display + AsRef<str>>(message: T) -> ! {
        error!("{message}");
        let message_cstring = CString::new(message.as_ref())
            .unwrap_or_else(|_| unsafe {
                rte_exit(1, c"Failed to convert message to CString".as_ptr())
            });
        unsafe { rte_exit(1, message_cstring.as_ptr()) }
    }

    /// Get the DPDK `rte_errno` and parse it as an [`errno::ErrorCode`].
    pub fn errno(&self) -> errno::ErrorCode {
        errno::ErrorCode::parse_i32(unsafe { wrte_errno() })
    }
}

impl Drop for Eal {
    #[tracing::instrument(level = "info")]
    #[allow(clippy::panic)]
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
    fn drop(&mut self) {
        info!("Closing EAL");
        let ret = unsafe { rte_eal_cleanup() };
        if ret != 0 {
            let panic_msg = format!("Failed to cleanup EAL: error {ret}");
            error!("{panic_msg}");
            panic!("{panic_msg}");
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct EalErrno(c_int);

impl EalErrno {
    #[allow(clippy::expect_used)]
    pub fn assert(ret: c_int) {
        if ret == 0 {
            return;
        }
        let ret_msg = unsafe { rte_strerror(ret) };
        let ret_msg = unsafe { CStr::from_ptr(ret_msg) };
        let ret_msg = ret_msg.to_str().expect("dpdk message is not valid unicode");
        Eal::fatal_error(ret_msg)
    }

}
