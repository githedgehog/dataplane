// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::eal::EalErrno;
use crate::mem::RteAllocator;
use core::ffi::{c_int, c_uint, c_void};
use core::fmt::Debug;
use errno::Errno;
use std::panic::UnwindSafe;
use tracing::{info, warn};

#[repr(transparent)]
#[derive(Debug)]
#[non_exhaustive]
pub struct Manager;

impl Manager {
    pub(crate) fn init() -> Manager {
        Manager
    }
}

impl Drop for Manager {
    #[tracing::instrument(level = "info")]
    fn drop(&mut self) {
        info!("Shutting down RTE LCore manager");
    }
}

#[repr(u32)]
pub enum LCorePriority {
    Normal = dpdk_sys::rte_thread_priority::RTE_THREAD_PRIORITY_NORMAL as c_uint,
    RealTime = dpdk_sys::rte_thread_priority::RTE_THREAD_PRIORITY_REALTIME_CRITICAL as c_uint,
}

/// An iterator over the available [`LCoreId`] values.
///
/// # Note
///
/// This iterator deliberately skips the main LCore.
#[derive(Debug)]
#[repr(transparent)]
struct LCoreIdIterator {
    current: LCoreId,
}

impl LCoreIdIterator {
    /// Start an iterator which loops over all available [`LCoreId`]
    ///
    /// This is internal and should not be directly exposed to the end user of this crate.
    ///
    /// # Note
    ///
    /// We start the [`LCoreId`] in an invalid condition as a signal to DPDK to
    /// return the first actual [`LCoreId`] on the first call to `.next()`.
    /// This value is never supposed to be exposed to the user as `u32::MAX` is
    /// an invalid [`LCoreId`].
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            current: LCoreId::INVALID,
        }
    }
}

impl Iterator for LCoreIdIterator {
    type Item = LCoreId;

    #[tracing::instrument(level = "trace")]
    fn next(&mut self) -> Option<Self::Item> {
        let next = unsafe { dpdk_sys::rte_get_next_lcore(self.current.0 as c_uint, 1, 0) };
        if next >= dpdk_sys::RTE_MAX_LCORE {
            return None;
        }
        self.current = LCoreId(next);
        Some(LCoreId(next))
    }
}

/// An iterator over the available [`LCoreIndex`] values.
#[derive(Debug)]
#[repr(transparent)]
struct LCoreIndexIterator {
    inner: LCoreIdIterator,
}

#[allow(unused)]
pub struct ServiceThread<'scope> {
    thread_id: RteThreadId,
    handle: std::thread::ScopedJoinHandle<'scope, ()>,
}

// TODO: take stack size as an EAL argument instead of hard coding it
const STACK_SIZE: usize = 8 << 20;

/// RAII guard that unregisters the calling thread from the EAL on
/// drop.  Used inside [`ServiceThread`] so the unregister side runs
/// whether `run()` returns normally or panics; without this the
/// `panic!` after `catch_unwind` would skip past
/// [`unregister_thread`] and leak an EAL TLS slot.
struct EalRegistration;

impl Drop for EalRegistration {
    fn drop(&mut self) {
        unregister_thread();
    }
}

impl ServiceThread<'_> {
    #[cold]
    #[allow(clippy::expect_used)]
    #[tracing::instrument(level = "debug", skip(run))]
    pub fn new<'scope>(
        scope: &'scope std::thread::Scope<'scope, '_>,
        name: impl AsRef<str> + Debug,
        run: impl FnOnce() + 'scope + Send + UnwindSafe,
    ) -> ServiceThread<'scope> {
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::Builder::new()
            .name(name.as_ref().to_string())
            .stack_size(STACK_SIZE)
            .spawn_scoped(scope, move || {
                let thread_id = register_thread().expect("service thread failed to register");
                // Hold the registration until this closure returns OR a
                // panic unwinds past it.  Either way, `unregister_thread()`
                // runs exactly once via the guard's Drop.
                let _registration = EalRegistration;
                send.send(thread_id).expect("could not send thread id");
                // better to crash than silently continue with a dead control / management plane
                #[allow(clippy::panic)]
                if std::panic::catch_unwind(run).is_err() {
                    panic!("service worker panicked");
                }
            })
            .expect("could not create EalThread");
        let thread_id = recv.recv().expect("could not receive thread id");
        ServiceThread { thread_id, handle }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn join(self) -> std::thread::Result<()> {
        self.handle.join()
    }
}

/// Reasons [`register_thread`] can fail.
///
/// `rte_thread_register` fails when DPDK cannot allocate space in
/// its per-thread TLS table.  In practice that is always `ENOMEM`,
/// but we keep an `Unknown` variant so an unexpected `rte_errno`
/// value is surfaced rather than silently mapped.
#[derive(Debug, thiserror::Error)]
pub enum RegisterThreadError {
    /// DPDK returned `ENOMEM` -- no space in the TLS table for
    /// another registered thread.
    #[error("not enough memory to register thread (rte_thread_register: ENOMEM)")]
    OutOfMemory,
    /// `rte_thread_register` returned an unexpected `rte_errno`
    /// value.
    #[error("unknown error registering thread: {0:?}")]
    Unknown(Errno),
}

/// Register the calling OS thread with the EAL.
///
/// Required before the calling thread can perform DPDK operations
/// that touch rte_malloc'd memory (notably the `rte_acl_*` family,
/// `rte_flow_*` family, and most other DPDK control APIs).  Lcore
/// worker threads are registered automatically by EAL; threads
/// spawned by Rust code (mgmt runtime workers, custom build worker
/// threads) must call this once at startup.
///
/// Pair with [`unregister_thread`] before the thread exits.
///
/// # Errors
///
/// See [`RegisterThreadError`].
#[cold]
pub(crate) fn register_thread() -> Result<RteThreadId, RegisterThreadError> {
    info!("registering thread with EAL");
    // SAFETY: rte_thread_register has no Rust-side preconditions; it
    // operates on the calling thread's TLS.
    let ret = unsafe { dpdk_sys::rte_thread_register() };
    if ret == 0 {
        let thread_id = unsafe { dpdk_sys::rte_thread_self() };
        return Ok(RteThreadId(thread_id));
    }
    // SAFETY: rte_errno_get reads thread-local errno; always valid.
    let raw = unsafe { dpdk_sys::rte_errno_get() };
    Err(match raw {
        errno::ENOMEM => RegisterThreadError::OutOfMemory,
        other => RegisterThreadError::Unknown(Errno(other)),
    })
}

/// Unregister the calling thread from the EAL.
///
/// Pair with [`register_thread`].  Idempotent in the sense that
/// calling it on an unregistered thread is a no-op at the DPDK
/// level (rte_thread_unregister tolerates this).
#[cold]
pub(crate) fn unregister_thread() {
    unsafe { dpdk_sys::rte_thread_unregister() };
}

#[allow(unused)]
pub struct WorkerThread {
    lcore_id: LCoreId,
}

impl WorkerThread {
    #[allow(clippy::expect_used)] // this is only called at system launch where crash is still ok
    pub fn launch<T: Send + FnOnce()>(lcore: LCoreId, f: T) {
        RteAllocator::assert_initialized();
        #[inline]
        unsafe extern "C" fn _launch<Task: Send + FnOnce()>(arg: *mut c_void) -> c_int {
            RteAllocator::assert_initialized();
            let task = unsafe {
                Box::from_raw(
                    arg.as_mut().expect("null argument in worker setup") as *mut _ as *mut Task,
                )
            };
            task();
            0
        }
        let task = Box::new(f);
        EalErrno::assert(unsafe {
            dpdk_sys::rte_eal_remote_launch(
                Some(_launch::<T>),
                Box::leak(task) as *mut _ as _,
                lcore.0 as c_uint,
            )
        });
    }
}

pub struct LCoreParams {
    priority: LCorePriority,
    name: String,
}

pub trait LCoreParameters {
    fn priority(&self) -> &LCorePriority;
    fn name(&self) -> &String;
}

#[allow(unused)]
pub struct LCore {
    params: LCoreParams,
    id: RteThreadId,
}

impl LCoreParameters for LCoreParams {
    fn priority(&self) -> &LCorePriority {
        &self.priority
    }

    fn name(&self) -> &String {
        &self.name
    }
}

impl LCoreParameters for LCore {
    fn priority(&self) -> &LCorePriority {
        &self.params.priority
    }

    fn name(&self) -> &String {
        &self.params.name
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct LCoreId(u32);

impl core::fmt::Display for LCoreId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl LCoreId {
    /// [`LCoreId`] in an invalid condition is used as a signal to DPDK to
    /// return the first actual [`LCoreId`] in the [`LCoreIdIterator`].
    /// This value is also used to indicate that iteration over `LCoreId`s is complete.
    const INVALID: LCoreId = LCoreId(u32::MAX);
}

#[repr(transparent)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct LCoreIndex(u32);

pub mod err {
    #[derive(thiserror::Error, Debug)]
    pub enum LCoreIdError {
        #[error("illegal lcore id: {0} (too large)")]
        IllegalId(u32),
    }
}

impl LCoreId {
    pub const MAX: u32 = dpdk_sys::RTE_MAX_LCORE;

    #[tracing::instrument(level = "trace")]
    pub fn iter() -> impl Iterator<Item = LCoreId> {
        LCoreIdIterator::new()
    }

    pub(crate) fn as_u32(&self) -> u32 {
        self.0
    }

    #[tracing::instrument(level = "trace")]
    pub fn current() -> LCoreId {
        LCoreId(unsafe { dpdk_sys::rte_lcore_id_w() })
    }

    #[tracing::instrument(level = "trace")]
    pub fn main() -> LCoreId {
        LCoreId(unsafe { dpdk_sys::rte_get_main_lcore() })
    }
}

impl LCoreId {
    /// Try to convert the [`LCoreId`] to an [`LCoreIndex`].
    ///
    /// This should always return `Some` but will return None if lcore indexes are not enabled.
    #[tracing::instrument(level = "trace")]
    fn to_index(self) -> Option<LCoreIndex> {
        let index = unsafe { dpdk_sys::rte_lcore_index(self.as_u32() as c_int) as u32 };
        if index == u32::MAX {
            None
        } else {
            Some(LCoreIndex(index))
        }
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
pub struct RteThreadId(pub(crate) dpdk_sys::rte_thread_t);

impl RteThreadId {
    #[tracing::instrument(level = "trace")]
    pub fn current() -> RteThreadId {
        RteThreadId(unsafe { dpdk_sys::rte_thread_self() })
    }
}

impl PartialEq for RteThreadId {
    #[tracing::instrument(level = "trace")]
    fn eq(&self, other: &Self) -> bool {
        unsafe { dpdk_sys::rte_thread_equal(self.0, other.0) != 0 }
    }
}

impl Eq for RteThreadId {}

impl LCoreIndex {
    /// Return an iterator which loops over all available [`LCoreIndex`] values.
    ///
    /// # Note
    ///
    /// This iterator deliberately skips the main LCore.
    #[tracing::instrument(level = "debug")]
    pub fn list() -> impl Iterator<Item = LCoreIndex> {
        LCoreIndexIterator::new()
    }

    /// Return the current [`LCoreIndex`] if enabled.  Returns `None` otherwise.
    #[tracing::instrument(level = "debug")]
    pub fn current() -> Option<LCoreIndex> {
        let index = unsafe { dpdk_sys::rte_lcore_index(-1) as u32 };
        if index == u32::MAX {
            None
        } else {
            Some(LCoreIndex(index))
        }
    }
}

impl LCoreIndexIterator {
    /// Start an iterator which loops over all available [`LCoreIndex`] values.
    ///
    /// This is internal and should not be directly exposed to the end user of this crate.
    ///
    /// # Note
    ///
    /// This iterator deliberately skips the main [`LCoreIndex`].
    #[tracing::instrument(level = "trace")]
    pub fn new() -> Self {
        Self {
            inner: LCoreIdIterator::new(),
        }
    }
}

impl Iterator for LCoreIndexIterator {
    type Item = LCoreIndex;

    #[tracing::instrument(level = "trace", skip(self))]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()?.to_index()
    }
}
