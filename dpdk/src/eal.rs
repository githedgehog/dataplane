// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK Environment Abstraction Layer (EAL)
use crate::{dev, mem, socket};
use alloc::ffi::CString;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_int;
use core::fmt::{Debug, Display};
use dpdk_sys::*;
use tracing::{error, info};

/// Safe wrapper around the DPDK Environment Abstraction Layer (EAL).
///
/// This is a zero-sized type that is used for lifetime management and to ensure that the Eal is
/// properly initialized and cleaned up.
#[derive(Debug)]
#[repr(transparent)]
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
    // ensure that this type can't be constructed outside of this module
    _private: EalPrivate,
}

#[repr(transparent)]
#[derive(Debug)]
struct EalPrivate {}

impl Drop for EalPrivate {
    fn drop(&mut self) {
        info!("EAL runtime environment closed");
    }
}

#[derive(Debug)]
/// Error type for EAL initialization failures.
///
/// TODO: improve error type, this is a little sloppy
pub enum InitError {
    /// Invalid arguments were passed to the EAL initialization.
    InvalidArguments(Vec<String>, String),
    /// The EAL has already been initialized.
    AlreadyInitialized,
    /// The EAL initialization failed.
    InitializationFailed(errno::Errno),
    /// [`rte_eal_init`] returned an error code other than `0` (success) or `-1` (failure).
    /// This likely represents a bug in the DPDK library.
    UnknownError(i32),
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
#[tracing::instrument(level = "debug", ret)]
pub fn init<T: Debug + AsRef<str>>(args: Vec<T>) -> Result<Eal, InitError> {
    let len = args.len();
    if len > c_int::MAX as usize {
        return Err(InitError::InvalidArguments(
            args.iter().map(|s| s.as_ref().to_string()).collect(),
            format!("Too many arguments: {len}"),
        ));
    }

    let len = args.len() as c_int;

    let args_as_c_strings: Result<Vec<_>, _> =
        args.iter().map(|s| CString::new(s.as_ref())).collect();

    // Account for the possibility of an illegal null byte in the arguments.
    let args_as_c_strings = match args_as_c_strings {
        Ok(c_strs) => c_strs,
        Err(_null_err) => {
            return Err(InitError::InvalidArguments(
                args.iter().map(|s| s.as_ref().to_string()).collect(),
                "Null byte in argument".to_string(),
            ))
        }
    };

    let mut args_as_pointers = args_as_c_strings
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .collect::<Vec<_>>();

    let ret = unsafe { rte_eal_init(len, args_as_pointers.as_mut_ptr()) };

    if ret < 0 {
        let rte_errno = unsafe { rte_errno_get() };
        let error = errno::Errno::from(rte_errno);
        error!("EAL initialization failed: {error:?} (rte_errno: {rte_errno})");
        Err(InitError::InitializationFailed(error))
    } else {
        info!("EAL initialized successfully");
        Ok(Eal {
            mem: mem::Manager::init(),
            dev: dev::Manager::init(),
            socket: socket::Manager::init(),
            _private: EalPrivate {},
        })
    }
}

impl Eal {
    #[tracing::instrument(level = "trace", ret)]
    /// Returns `true` if the [`Eal`] is using the PCI bus.
    ///
    /// This is mostly a safe wrapper around [`rte_eal_has_pci`]
    /// which simply converts the return value to a [`bool`] instead of a [`c_int`].
    pub fn has_pci(&self) -> bool {
        unsafe { rte_eal_has_pci() != 0 }
    }

    #[allow(clippy::expect_used)]
    /// Exits the DPDK application with an error message, cleaning up the [`Eal`] as gracefully as
    /// possible (by way of [`rte_exit`]).
    ///
    /// This function never returns as it exits the application.
    ///
    /// # Panics
    ///
    /// Panics if the error message cannot be converted to a `CString`.
    /// This is a serious error as it means there is fundamental logic bug in DPDK.
    pub(crate) fn fatal_error<T: Display + AsRef<str>>(message: T) -> ! {
        error!("{message}");
        let message_cstring = CString::new(message.as_ref()).expect("invalid error message!");
        unsafe { rte_exit(1, message_cstring.as_ptr()) }
    }

    /// Get the DPDK `rte_errno` and parse it as an [`errno::ErrorCode`].
    ///
    /// # Note
    ///
    /// If the err
    pub fn errno() -> errno::ErrorCode {
        errno::ErrorCode::parse_i32(unsafe { rte_errno_get() })
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
