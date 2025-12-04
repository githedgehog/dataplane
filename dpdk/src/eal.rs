// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK Environment Abstraction Layer (EAL)

use crate::{dev, lcore, mem, socket};
use core::ffi::c_int;
use core::fmt::{Debug, Display};
use std::alloc::{Allocator, Layout, System};
use std::convert::Infallible;
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::raw::c_char;
use tracing::{error, info};

#[repr(u8)]
enum EalState {
    Configured,
    Started,
    Stopped,
}

// sealed
trait State {
    const STATE: EalState;
}

/// Safe wrapper around the DPDK Environment Abstraction Layer (EAL).
///
/// This is a zero-sized type that is used for lifetime management and to ensure that the Eal is
/// properly initialized and cleaned up.
#[derive(Debug)]
#[repr(transparent)]
#[non_exhaustive]
pub struct Eal<S: State> {
    // todo: make private
    pub state: S,
}

#[non_exhaustive]
pub struct Started {
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

#[non_exhaustive]
pub struct Stopped;

impl State for Configured {
    const STATE: EalState = EalState::Configured;
}

impl State for Started {
    const STATE: EalState = EalState::Started;
}

impl State for Stopped {
    const STATE: EalState = EalState::Stopped;
}

unsafe impl Sync for Eal<Started> {}

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
    pub fn new(args: &rkyv::Archived<Vec<std::ffi::CString>>) -> EalArgs {
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
            system_args.push(
                Box::leak(unsafe { Box::from_raw_in(x.as_ptr(), System) }).as_mut_ptr() as *mut i8,
            )
        }
        let boxed_slice = system_args.into_boxed_slice();
        let argc = boxed_slice.len() as c_int;
        let argv = Box::leak(boxed_slice).as_mut_ptr();
        EalArgs { argc, argv }
    }
}

// TODO: absorb into state machine
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
pub fn init(args: EalArgs) -> Started {
    let ret = unsafe { dpdk_sys::rte_eal_init(args.argc, args.argv) };
    if ret < 0 {
        EalErrno::assert(unsafe { dpdk_sys::rte_errno_get() });
    }
    // lcore::ServiceThread::register_thread_spawn_hook();
    Started {
        mem: mem::Manager::init(),
        dev: dev::Manager::init(),
        socket: socket::Manager::init(),
        lcore: lcore::Manager::init(),
    }
}

impl Eal<Started> {
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

pub struct Configured {
    args: EalArgs,
}

impl driver::Configure for Eal<Configured> {
    type Configuration = EalArgs;
    type Configured = Eal<Configured>;
    type Error = Infallible; // TODO: real error types

    // memory allocation ok after this call if Ok
    // thread creation ok after this call if Ok
    fn configure(configuration: Self::Configuration) -> Result<Self::Configured, Infallible> {
        // TODO: proper validation of args or construct EalArgs from something more friendly
        Ok(Eal {
            state: Configured {
                args: configuration,
            },
        })
    }
}

impl driver::Start for Eal<Configured> {
    type Started = Eal<Started>;
    type Error = Infallible;

    // Start the Eal.
    fn start(self) -> Result<Self::Started, Self::Error> {
        let ret = unsafe { dpdk_sys::rte_eal_init(self.state.args.argc, self.state.args.argv) };
        if ret < 0 {
            EalErrno::assert(unsafe { dpdk_sys::rte_errno_get() });
        }
        let ret = unsafe { dpdk_sys::rte_mp_disable() };
        if !ret {
            error!("multi-process not currently supported");
            unsafe { libc::_exit(1) };
        }
        Ok(Eal {
            state: Started {
                mem: mem::Manager::init(),
                dev: dev::Manager::init(),
                socket: socket::Manager::init(),
                lcore: lcore::Manager::init(),
            },
        })
    }
}

impl driver::Stop for Eal<Started> {
    type Outcome = Eal<Stopped>;
    type Error = Infallible;

    #[allow(clippy::unwrap_used)]
    fn stop(self) -> Result<Self::Outcome, Self::Error> {
        std::io::stdout().flush().unwrap();
        std::io::stderr().flush().unwrap();
        info!("waiting on EAL threads");
        unsafe { dpdk_sys::rte_eal_mp_wait_lcore() };
        if unsafe { dpdk_sys::rte_eal_cleanup() } != 0 {
            eprintln!("failed to clean up EAL");
            std::io::stdout().flush().unwrap();
            std::io::stderr().flush().unwrap();
            unsafe {
                // _exit explicitly does not call exit handlers
                libc::_exit(1);
            }
        }
        info!("eal closed successfully");
        Ok(Eal { state: Stopped })
    }
}

impl<S> Drop for Eal<S>
where
    S: State,
{
    fn drop(&mut self) {
        match S::STATE {
            EalState::Configured => {
                // EAL not started so nothing to shut down
            }
            EalState::Started => {
                error!("EAL dropped while in started state");
                // This is an exceptional situation so we take some extra defensive steps here.
                // try to make sure we have written out all our log messages before we crash.
                std::io::stdout()
                    .flush()
                    .unwrap_or_else(|_| std::process::abort());
                std::io::stderr()
                    .flush()
                    .unwrap_or_else(|_| std::process::abort());
                unsafe {
                    libc::_exit(1);
                }
            }
            EalState::Stopped => {
                std::io::stdout()
                    .flush()
                    .unwrap_or_else(|_| std::process::abort());
                std::io::stderr()
                    .flush()
                    .unwrap_or_else(|_| std::process::abort());
                info!("EAL dropped");
                std::io::stdout()
                    .flush()
                    .unwrap_or_else(|_| std::process::abort());
                std::io::stderr()
                    .flush()
                    .unwrap_or_else(|_| std::process::abort());
            }
        }
    }
}
