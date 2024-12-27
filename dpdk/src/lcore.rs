use crate::eal::{Eal, EalErrno};
use dpdk_sys::{lcore_function_t, rte_eal_remote_launch, rte_get_next_lcore, rte_lcore_count, rte_lcore_id_w, rte_lcore_index, rte_thread_attr_init, rte_thread_attr_t, rte_thread_create, rte_thread_func, rte_thread_join, rte_thread_t, RTE_MAX_LCORE};
use std::ffi::{c_int, c_uint, c_void, CString};
use std::ptr::null_mut;
use tracing::{info, warn};

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
    /// This value is never supposed to be exposed to the user as u32::MAX is clearly
    /// an invalid [`LCoreId`].
    fn new() -> Self {
        Self {
            current: LCoreId(u32::MAX),
        }
    }
}

impl Iterator for LCoreIdIterator {
    type Item = LCoreId;

    fn next(&mut self) -> Option<Self::Item> {
        let next = unsafe { rte_get_next_lcore(self.current.0 as c_uint, 1, 0) };
        if next == RTE_MAX_LCORE {
            return None;
        }
        Some(LCoreId(next))
    }
}

/// An iterator over the available [`LCoreIndex`] values.
#[repr(transparent)]
struct LCoreIndexIterator {
    inner: LCoreIdIterator,
}

pub struct ServiceThread<'scope> {
    thread_id: rte_thread_t,
    priority: LCorePriority,
    handle: std::thread::ScopedJoinHandle<'scope, ()>,
}

// TODO: take stack size as an EAL argument instead of hard coding it
const STACK_SIZE: usize = 8 * 1024 * 1024;

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
                let ret = unsafe { dpdk_sys::rte_thread_register() };
                if ret != 0 {
                    let errno = unsafe { dpdk_sys::wrte_errno() };
                    let msg = format!("rte thread exited with code {ret}, errno: {errno}");
                    Eal::fatal_error(msg)
                }
                let thread_id = unsafe { dpdk_sys::rte_thread_self() };
                send.send(thread_id).expect("could not send thread id");
                run();
                unsafe { dpdk_sys::rte_thread_unregister() };
            })
            .expect("could not create EalThread");
        let thread_id = recv.recv().expect("could not receive thread id");
        ServiceThread {
            thread_id,
            priority: LCorePriority::RealTime,
            handle,
        }
    }

    pub fn new_eal(run: extern "C" fn(*mut c_void) -> c_int, arg: *mut c_void) {
        let mut thread_id = rte_thread_t::default();
        let mut attr = rte_thread_attr_t {
            priority: LCorePriority::RealTime as u32,
        };
        let mut val: u32 = 0;
        let mut list = LCoreId::list();
        list.next();
        list.next();
        list.next();
        list.next();
        #[allow(clippy::panic)]
        let Some(lcore) = list.next() else {
            panic!("no LCores available");
        };
        warn!("lanuching on on LCoreId({0})", lcore.0);
        let ret = unsafe {
            rte_eal_remote_launch(Some(run), arg, lcore.0 as c_uint)
        };
        EalErrno::check(ret);
        // unsafe {
        //     EalErrno::check(rte_thread_attr_init(&mut attr));
        //     EalErrno::check(rte_thread_create(&mut thread_id, &attr, Some(run), arg));
        //     rte_thread_join(thread_id, &mut val);
        // }
    }

    #[allow(clippy::expect_used)]
    fn join(self) {
        self.handle.join().expect("failed to join LCore");
    }
}

struct LCoreParams {
    priority: LCorePriority,
    name: String,
    thunk: rte_thread_func,
    thunk2: lcore_function_t,
}

trait LCoreParameters {
    fn priority(&self) -> &LCorePriority;
    fn name(&self) -> &String;
}

struct LCore {
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

#[repr(transparent)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct LCoreIndex(u32);

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
        LCoreId(unsafe { rte_lcore_id_w() })
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

impl PartialEq for RteThreadId {
    fn eq(&self, other: &Self) -> bool {
        unsafe { dpdk_sys::rte_thread_equal(self.0, other.0) != 0 }
    }
}

impl Eq for RteThreadId {}

impl LCore {
    fn allocate(params: LCoreParams) -> LCore {
        let mut thread = rte_thread_t::default();
        let mut attr = rte_thread_attr_t {
            priority: LCorePriority::RealTime as u32,
        };
        EalErrno::check(unsafe { rte_thread_attr_init(&mut attr) });
        EalErrno::check(unsafe { rte_thread_create(&mut thread, &attr, params.thunk, null_mut()) });

        #[allow(clippy::panic)]
        if !params.name.is_ascii() {
            panic!("invalid thread name: not ascii");
        }
        #[allow(clippy::expect_used)]
        unsafe {
            dpdk_sys::rte_thread_set_name(
                thread,
                CString::new(params.name.as_bytes().to_vec())
                    .expect("could not allocate thread name")
                    .as_ptr(),
            )
        };
        EalErrno::check(unsafe {
            dpdk_sys::rte_thread_set_priority(thread, LCorePriority::RealTime as c_uint)
        });
        LCore {
            params,
            id: RteThreadId(thread),
        }
    }
}

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
        self.inner
            .next()
            .map(|id| unsafe { LCoreIndex(rte_lcore_index(id.0 as c_int) as u32) })
    }
}
