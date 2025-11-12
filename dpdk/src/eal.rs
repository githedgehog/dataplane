// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK Environment Abstraction Layer (EAL)

use crate::mem::SwitchingAllocator;
use crate::{dev, lcore, mem, socket};
use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::c_int;
use core::fmt::{Debug, Display};
use std::alloc::{Allocator, Layout, System};
use std::convert::Infallible;
use std::ffi::CStr;
use std::io::Write;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::os::raw::c_char;
use std::time::Duration;
use tracing::{error, info};

#[global_allocator]
static mut GLOBAL_ALLOCATOR: crate::mem::SwitchingAllocator =
    crate::mem::SwitchingAllocator::System;

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
#[non_exhaustive]
pub struct Eal<'eal, S: State> {
    // todo: make private
    pub state: S,
    lifetime: PhantomData<&'eal ()>,
}

#[non_exhaustive]
pub struct Started<'a> {
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
    _lifetime: PhantomData<&'a ()>,
}

#[non_exhaustive]
pub struct Stopped<'a> {
    _ghost: ManuallyDrop<Eal<'a, Started<'a>>>,
}

impl State for Configured {
    const STATE: EalState = EalState::Configured;
}
impl<'a> State for Started<'a> {
    const STATE: EalState = EalState::Started;
}
impl<'a> State for Stopped<'a> {
    const STATE: EalState = EalState::Stopped;
}

unsafe impl<'a> Sync for Eal<'a, Started<'a>> {}

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
pub fn init<'a>(args: EalArgs) -> Started<'a> {
    let ret = unsafe { dpdk_sys::rte_eal_init(args.argc, args.argv) };
    if ret < 0 {
        EalErrno::assert(unsafe { dpdk_sys::rte_errno_get() });
    }
    lcore::ServiceThread::register_thread_spawn_hook();
    Started {
        mem: mem::Manager::init(),
        dev: dev::Manager::init(),
        socket: socket::Manager::init(),
        lcore: lcore::Manager::init(),
        _lifetime: PhantomData,
    }
}

impl<'a> Eal<'a, Started<'a>> {
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

// impl<T> Drop for Eal<T> {
//     /// Clean up the DPDK Environment Abstraction Layer (EAL).
//     ///
//     /// This is called automatically when the `Eal` is dropped and generally should not be called
//     /// manually.
//     ///
//     /// # Panics
//     ///
//     /// Panics if the EAL cleanup fails for some reason.
//     /// EAL cleanup failure is potentially serious as it can leak hugepage file descriptors and
//     /// make application restart complex.
//     ///
//     /// Failure to clean up the EAL is almost certainly an unrecoverable error anyway.
//     #[cold]
//     #[allow(clippy::panic)]
//     #[tracing::instrument(level = "info", skip(self))]
//     fn drop(&mut self) {
//         info!("waiting on EAL threads");
//         unsafe { dpdk_sys::rte_eal_mp_wait_lcore() };
//         info!("Closing EAL");
//         let ret = unsafe { dpdk_sys::rte_eal_cleanup() };
//         if ret != 0 {
//             let panic_msg = format!("Failed to cleanup EAL: error {ret}");
//             error!("{panic_msg}");
//             panic!("{panic_msg}");
//         }
//     }
// }

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

impl<'eal> driver::Configure for Eal<'eal, Configured> {
    type Configuration = EalArgs;
    type Configured = Eal<'eal, Configured>;
    type Error = Infallible; // TODO: real error types

    // memory allocation ok after this call if Ok
    // thread creation ok after this call if Ok
    fn configure(configuration: EalArgs) -> Result<Eal<'eal, Configured>, Self::Error> {
        // TODO: proper validation of args or construct EalArgs from something more friendly
        Ok(Eal {
            state: Configured {
                args: configuration,
            },
            lifetime: PhantomData,
        })
    }
}

impl<'eal> driver::Start for Eal<'eal, Configured> {
    type Started = Eal<'eal, Started<'eal>>;
    type Error = Infallible;

    fn start(self) -> Result<Self::Started, Self::Error> {
        let ret = unsafe { dpdk_sys::rte_eal_init(self.state.args.argc, self.state.args.argv) };
        if ret < 0 {
            EalErrno::assert(unsafe { dpdk_sys::rte_errno_get() });
        }
        // lcore::ServiceThread::register_thread_spawn_hook();
        unsafe {
            GLOBAL_ALLOCATOR = SwitchingAllocator::Rte;
        };
        Ok(Eal {
            state: Started {
                mem: mem::Manager::init(),
                dev: dev::Manager::init(),
                socket: socket::Manager::init(),
                lcore: lcore::Manager::init(),
                _lifetime: PhantomData,
            },
            lifetime: PhantomData,
        })
    }
}

impl<'eal> driver::Stop for Eal<'eal, Started<'eal>> {
    type Outcome = Eal<'eal, Stopped<'eal>>;

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
        eprintln!("eal closed successfully: process exiting; bye bye");
        // This is the one and only successful exit condition for the program.
        // We very deliberately skip exit handlers because they are
        //
        // 1. unreliable,
        // 2. un-necessary,
        // 3. conceptually broken,
        //
        // on the best of days.
        // But all of that gets turned up to 11 when you have swapped memory allocators mid process (which is admittedly
        // a wild thing to do).
        unsafe {
            // _exit explicitly does not call exit handlers
            libc::_exit(0);
        }
    }
}

impl<'eal, S> Drop for Eal<'eal, S>
where
    S: State,
{
    fn drop(&mut self) {
        match S::STATE {
            EalState::Configured => {
                // nothing to do here, EAL not even started so nothing to shut down
            }
            EalState::Started => {
                error!("EAL dropped while in started state: process must abort");
                // This is a very unusual situation so we take some extra defensive steps here.
                // try to make sure we have written out all our log messages before we melt
                std::io::stdout()
                    .flush()
                    .unwrap_or_else(|_| std::process::abort());
                std::io::stderr()
                    .flush()
                    .unwrap_or_else(|_| std::process::abort());
                // Final sleep just to make it more likely we get any tracing / diagnostics out before
                // we abort
                std::thread::sleep(Duration::from_millis(100));
                std::process::abort();
            }
            EalState::Stopped => {
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
