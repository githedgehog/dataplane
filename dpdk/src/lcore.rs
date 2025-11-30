// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::eal::{Eal, EalErrno};
use core::ffi::{c_int, c_uint, c_void};
use core::fmt::Debug;
use errno::ErrorCode;
use tracing::{debug, info, warn};

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
        if unsafe { dpdk_sys::rte_get_main_lcore() } == next {
            return self.next();
        }
        if unsafe { dpdk_sys::rte_eal_lcore_role(next) } == dpdk_sys::rte_lcore_role_t::ROLE_NON_EAL
        {
            self.next()
        } else {
            Some(LCoreId(next))
        }
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
    priority: LCorePriority,
    handle: std::thread::ScopedJoinHandle<'scope, ()>,
}

// TODO: take stack size as an EAL argument instead of hard coding it
const STACK_SIZE: usize = 8 << 20;

impl ServiceThread<'_> {
    #[cold]
    #[allow(clippy::expect_used)]
    #[tracing::instrument(level = "debug", skip(run))]
    pub fn new<'scope>(
        scope: &'scope std::thread::Scope<'scope, '_>,
        name: impl AsRef<str> + Debug,
        run: impl FnOnce() + 'scope + Send,
    ) -> ServiceThread<'scope> {
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::Builder::new()
            .name(name.as_ref().to_string())
            .stack_size(STACK_SIZE)
            .spawn_scoped(scope, move || {
                Self::register_current_thread();
                let thread_id = unsafe { dpdk_sys::rte_thread_self() };
                send.send(thread_id).expect("could not send thread id");
                run();
                unsafe {
                    Self::unregister_current_thread();
                };
            })
            .expect("could not create EalThread");
        let thread_id = RteThreadId(recv.recv().expect("could not receive thread id"));
        ServiceThread {
            thread_id,
            priority: LCorePriority::RealTime,
            handle,
        }
    }

    #[tracing::instrument(level = "debug")]
    pub fn register_current_thread() {
        debug!("initializing RTE Lcore");
        let ret = unsafe { dpdk_sys::rte_thread_register() };
        if ret != 0 {
            let errno = unsafe { dpdk_sys::rte_errno_get() };
            let msg = format!("rte thread exited with code {ret}, errno: {errno}");
            Eal::fatal_error(msg)
        }
    }

    /// De-register / free the RTE lcore id / thread local slots
    ///
    /// # Safety
    ///
    /// * It only makes sense to call this function on a registered RTE lcore.
    /// * Don't unregister an lcore if it still needs DPDK functions.
    #[tracing::instrument(level = "debug")]
    pub unsafe fn unregister_current_thread() {
        debug!("tearing down RTE Lcore");
        unsafe { dpdk_sys::rte_thread_unregister() };
    }

    #[cold]
    pub fn register_thread_spawn_hook() {
        std::thread::add_spawn_hook(|t| {
            match t.name() {
                Some(name) => {
                    warn!(
                        "registering thread \"{name}\" (id {id:?}) with the DPDK EAL",
                        id = t.id()
                    );
                }
                None => {
                    warn!(
                        "registering nameless thread wit id {:?} with the DPDK EAL",
                        t.id()
                    );
                }
            }
            Self::register_current_thread
        })
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn join(self) -> std::thread::Result<()> {
        self.handle.join()
    }
}

#[derive(Debug)]
pub struct WorkerThread {
    lcore_id: LCoreId,
}

impl From<LCoreId> for WorkerThread {
    fn from(value: LCoreId) -> Self {
        Self { lcore_id: value }
    }
}

#[repr(i32)]
#[derive(Debug, thiserror::Error)]
pub enum WorkerThreadLaunchError {
    /// Worker thread is not in the waiting state
    #[error("attempt to launch function on worker thread which is not in the waiting state")]
    Busy = -errno::EBUSY,
    /// Unable to write to workerthread's pipe
    #[error(
        "unable to write to worker thread's pipe when attempting to launch function on that thread"
    )]
    Pipe = -errno::EPIPE,
    /// Unexpected errno when launching worker thread
    #[error("unexpected error when launching worker thread: {0}")]
    Unexpected(ErrorCode),
}

impl WorkerThread {
    /// This can only run on the main lcore
    #[allow(clippy::expect_used)] // this is only called at system launch where crash is still ok
    pub fn launch<T: Send + FnOnce()>(lcore: LCoreId, f: T) -> Result<LCoreId, WorkerThreadLaunchError> {
        unsafe extern "C" fn _launch<Task: Send + FnOnce()>(arg: *mut c_void) -> c_int {
            let task = unsafe {
                Box::from_raw(
                    arg.as_mut().expect("null argument in worker setup") as *mut _ as *mut Task,
                )
            };
            task();
            0
        }
        let task = Box::new(f);
        let res = unsafe {
            dpdk_sys::rte_eal_remote_launch(
                Some(_launch::<T>),
                Box::leak(task) as *mut _ as _,
                lcore.0 as c_uint,
            )
        };
        match res {
            0 => Ok(lcore),
            errno::NEG_EBUSY => Err(WorkerThreadLaunchError::Busy),
            errno::NEG_EPIPE => Err(WorkerThreadLaunchError::Pipe),
            other => Err(WorkerThreadLaunchError::Unexpected(ErrorCode::parse(other))),
        }
    }

    /// main lcore only.
    #[tracing::instrument(level = "info", skip(self))]
    pub fn join(&self) {
        info!(
            "joining WorkerThread with rte lcore id {thread_id:?}",
            thread_id = self.lcore_id
        );
        EalErrno::assert(unsafe { dpdk_sys::rte_eal_wait_lcore(self.lcore_id.0) });
        info!(
            "joined WorkerThread with rte lcore id {thread_id:?}",
            thread_id = self.lcore_id
        );
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
pub struct LCoreId(pub u32); // TODO: remove pub from inner value

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
