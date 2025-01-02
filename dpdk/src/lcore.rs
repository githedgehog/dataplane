use crate::eal::{Eal, EalErrno};
use crossbeam::channel::{RecvError, SendError};
use dpdk_sys::*;
use hashbrown::HashMap;
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::null_mut;
use tracing::{info, warn};

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

    //
    // pub fn launch_workers<T: Sync>(mut arg: &T) {
    //     warn!("Launching RTE Lcores");
    //     if unsafe {
    //         rte_eal_mp_remote_launch(
    //             Some(Self::spinup::<T>),
    //             arg as *const _ as *mut T as *mut _,
    //             rte_rmt_call_main_t::SKIP_MAIN,
    //         )
    //     } != 0
    //     {
    //         panic!("rte_eal_mp_remote_launch failed");
    //     }
    //     std::thread::sleep(std::time::Duration::from_secs(3));
    // }

    // todo: this should be private or `pub(crate)` after we supply a higher level API
    pub fn new_eal(run: extern "C" fn(*mut c_void) -> c_int, arg: *mut c_void, lcore: LCoreId) {
        warn!("launching on on LCoreId({0})", lcore.0);
        let ret = unsafe { rte_eal_remote_launch(Some(run), arg, lcore.0 as c_uint) };
        EalErrno::assert(ret);
    }

    #[allow(clippy::expect_used)]
    pub fn join(self) {
        self.handle.join().expect("failed to join LCore");
    }
}

pub struct MainThread {
    lcore_id: LCoreId,
}

impl MainThread {
    fn get() -> MainThread {
        MainThread {
            lcore_id: LCoreId::main(),
        }
    }

    pub fn launch<F: FnOnce() + Send + Sync>(f: F) {
        let main_lcore_id = LCoreId::main();
        WorkerThread::launch_on(main_lcore_id, f);
    }
}
pub struct WorkerThread {
    lcore_id: LCoreId,
    worker: ManagerInit,
}

struct WorkerInit {
    from_manager: crossbeam::channel::Receiver<WorkerMessage>,
    to_manager: crossbeam::channel::Sender<ManagerMessage>,
}

impl ManagerInit {
    fn send(&self, message: WorkerMessage) -> Result<(), SendError<WorkerMessage>> {
        self.to_worker.send(message)
    }

    fn recv(&self) -> Result<ManagerMessage, RecvError> {
        self.from_worker.recv()
    }
}

impl WorkerThread {
    pub fn send(&self, message: WorkerMessage) -> Result<(), SendError<WorkerMessage>> {
        self.worker.send(message)
    }

    pub fn recv(&self) -> Result<ManagerMessage, RecvError> {
        self.worker.recv()
    }
}

struct ManagerInit {
    from_worker: crossbeam::channel::Receiver<ManagerMessage>,
    to_worker: crossbeam::channel::Sender<WorkerMessage>,
}

pub enum WorkerMessage {
    Task(Box<dyn FnOnce() + Send>),
}
enum ManagerMessage {
    Register(LCoreId),
}

impl WorkerThread {
    pub fn launch_on<T: FnOnce() + Send>(lcore: LCoreId, f: T) {
        const CHANNEL_BOUND: usize = 1024;
        unsafe extern "C" fn _launch<Task: FnOnce() + Send>(arg: *mut c_void) -> c_int {
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
pub struct LCoreId(u32);

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

    #[derive(thiserror::Error, Debug)]
    pub enum LCoreIndexError {}
}

impl LCoreId {
    pub const MAX: u32 = RTE_MAX_LCORE;

    pub fn list() -> impl Iterator<Item = LCoreId> {
        LCoreIdIterator::new()
    }

    pub(crate) fn new(inner: u32) -> Result<LCoreId, err::LCoreIdError> {
        if inner >= Self::MAX {
            return Err(err::LCoreIdError::IllegalId(inner));
        }
        Ok(LCoreId(inner))
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
