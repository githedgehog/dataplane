use crate::eal::{Eal, EalErrno};
use core::ffi::{c_int, c_uint, c_void};
use std::thread::Thread;
use crossbeam::channel::{RecvError, SendError};
use dpdk_sys::*;
use tracing::{info, warn};
use crate::mem::RteAllocator;

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
    Normal = rte_thread_priority::RTE_THREAD_PRIORITY_NORMAL as c_uint,
    RealTime = rte_thread_priority::RTE_THREAD_PRIORITY_REALTIME_CRITICAL as c_uint,
}

/// An iterator over the available [`LCoreId`] values.
///
/// # Note
///
/// This iterator deliberately skips the main LCore.
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
    fn new() -> Self {
        Self {
            current: LCoreId::INVALID,
        }
    }
}

impl Iterator for LCoreIdIterator {
    type Item = LCoreId;

    fn next(&mut self) -> Option<Self::Item> {
        let next = unsafe { rte_get_next_lcore(self.current.0 as c_uint, 1, 0) };
        if next >= RTE_MAX_LCORE {
            return None;
        }
        self.current = LCoreId(next);
        Some(LCoreId(next))
    }
}

/// An iterator over the available [`LCoreIndex`] values.
#[repr(transparent)]
struct LCoreIndexIterator {
    inner: LCoreIdIterator,
}

pub struct ServiceThread<'scope> {
    thread_id: RteThreadId,
    priority: LCorePriority,
    handle: std::thread::ScopedJoinHandle<'scope, ()>,
}

// TODO: take stack size as an EAL argument instead of hard coding it
const STACK_SIZE: usize = 8 << 20;

impl ServiceThread<'_> {
    #[cold]
    #[allow(clippy::expect_used)]
    pub fn new<'scope>(
        scope: &'scope std::thread::Scope<'scope, '_>,
        name: impl AsRef<str>,
        run: impl FnOnce() + 'scope + Send,
    ) -> ServiceThread<'scope> {
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::Builder::new()
            .name(name.as_ref().to_string())
            .stack_size(STACK_SIZE)
            .spawn_scoped(scope, move || {
                info!("Initializing RTE Lcore");
                let ret = unsafe { rte_thread_register() };
                if ret != 0 {
                    let errno = unsafe { wrte_errno() };
                    let msg = format!("rte thread exited with code {ret}, errno: {errno}");
                    Eal::fatal_error(msg)
                }
                let thread_id = unsafe { rte_thread_self() };
                send.send(thread_id).expect("could not send thread id");
                run();
                unsafe { rte_thread_unregister() };
            })
            .expect("could not create EalThread");
        let thread_id = RteThreadId(recv.recv().expect("could not receive thread id"));
        ServiceThread {
            thread_id,
            priority: LCorePriority::RealTime,
            handle,
        }
    }

    #[allow(clippy::expect_used)]
    pub fn join(self) {
        self.handle.join().expect("failed to join LCore");
    }
}

pub struct WorkerThread {
    lcore_id: LCoreId,
}


impl WorkerThread {
    #[cold]
    pub fn launch<T: Send + FnOnce()>(lcore: LCoreId, f: T) {
        RteAllocator::assert_initialized();
        #[cold]
        unsafe extern "C" fn _launch<Task: Send + FnOnce()>(arg: *mut c_void) -> c_int {
            RteAllocator::assert_initialized();
            let task = Box::from_raw(
                arg.as_mut().expect("null argument in worker setup") as *mut _ as *mut Task,
            );
            task();
            0
        }
        let task = Box::new(f);
        EalErrno::assert(unsafe {
            rte_eal_remote_launch(
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
pub struct LCoreId(pub u32);

impl LCoreId {
    /// [`LCoreId`] in an invalid condition is used as a signal to DPDK to
    /// return the first actual [`LCoreId`] in the [`LCoreIdIterator`].
    /// This value is also used to indicate that iteration over `LCoreId`s is complete.
    const INVALID: LCoreId = LCoreId(u32::MAX);
}

#[repr(transparent)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct LCoreIndex(pub u32);

pub mod err {
    #[derive(thiserror::Error, Debug)]
    pub enum LCoreIdError {
        #[error("illegal lcore id: {0} (too large)")]
        IllegalId(u32),
    }
}

impl LCoreId {
    pub const MAX: u32 = RTE_MAX_LCORE;

    pub fn iter() -> impl Iterator<Item = LCoreId> {
        LCoreIdIterator::new()
    }

    pub(crate) fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn current() -> LCoreId {
        LCoreId(unsafe { rte_lcore_id() })
    }

    pub fn main() -> LCoreId {
        LCoreId(unsafe { rte_get_main_lcore() })
    }
}

impl From<LCoreId> for LCoreIndex {
    fn from(value: LCoreId) -> Self {
        LCoreIndex(unsafe { rte_lcore_index(value.as_u32() as c_int) as u32 })
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
pub struct RteThreadId(pub(crate) rte_thread_t);

impl RteThreadId {
    pub fn current() -> RteThreadId {
        RteThreadId(unsafe { rte_thread_self() })
    }
}

impl PartialEq for RteThreadId {
    fn eq(&self, other: &Self) -> bool {
        unsafe { rte_thread_equal(self.0, other.0) != 0 }
    }
}

impl Eq for RteThreadId {}

impl LCoreIndex {
    /// Return an iterator which loops over all available [`LCoreIndex`] values.
    ///
    /// # Note
    ///
    /// This iterator deliberately skips the main LCore.
    pub fn list() -> impl Iterator<Item = LCoreIndex> {
        LCoreIndexIterator::new()
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
    pub fn new() -> Self {
        Self {
            inner: LCoreIdIterator::new(),
        }
    }
}

impl Iterator for LCoreIndexIterator {
    type Item = LCoreIndex;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(From::from)
    }
}
