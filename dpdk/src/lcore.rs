// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::eal::{Eal, EalErrno};
use core::ffi::{c_int, c_uint, c_void};
use core::fmt::Debug;
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
struct LCoreIdIterator {
    current: LCoreId,
    /// Whether to omit the main lcore.
    ///
    /// Previously hard-coded to "yes" while this type's constructor documentation said it looped
    /// over *all* lcores. The two disagreed and the behaviour won: under a configuration whose
    /// only lcore is the main one -- which the unit-test EAL is, since `--lcores 0@(0,1,...)`
    /// maps a single lcore across every CPU -- the iterator yielded nothing at all.
    skip_main: bool,
}

impl LCoreIdIterator {
    /// Iterate every enabled [`LCoreId`], main included.
    ///
    /// This is internal and should not be directly exposed to the end user of this crate.
    ///
    /// # Note
    ///
    /// We start the [`LCoreId`] in an invalid condition as a signal to DPDK to
    /// return the first actual [`LCoreId`] on the first call to `.next()`.
    /// This value is never supposed to be exposed to the user as `u32::MAX` is
    /// an invalid [`LCoreId`].  It works because `rte_get_next_lcore` increments before testing
    /// and unsigned overflow takes `u32::MAX` to zero.
    #[tracing::instrument(level = "trace")]
    fn all() -> Self {
        Self {
            current: LCoreId::INVALID,
            skip_main: false,
        }
    }

    /// Iterate every enabled [`LCoreId`] except the main one.
    #[tracing::instrument(level = "trace")]
    fn workers() -> Self {
        Self {
            current: LCoreId::INVALID,
            skip_main: true,
        }
    }
}

impl Iterator for LCoreIdIterator {
    type Item = LCoreId;

    #[tracing::instrument(level = "trace")]
    fn next(&mut self) -> Option<Self::Item> {
        let next = unsafe {
            dpdk_sys::rte_get_next_lcore(self.current.0 as c_uint, c_int::from(self.skip_main), 0)
        };
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
    priority: LCorePriority,
    handle: std::thread::ScopedJoinHandle<'scope, ()>,
}

// TODO: take stack size as an EAL argument instead of hard coding it
const STACK_SIZE: usize = 8 << 20;

/// Releases this thread's EAL lcore registration when it goes out of scope, including on unwind.
///
/// Constructed only after a successful [`rte_thread_register`](dpdk_sys::rte_thread_register), and
/// never moved off the thread that registered -- `rte_thread_unregister` releases the *calling*
/// thread's id, so running it anywhere else would strand this one and corrupt another.
#[allow(missing_debug_implementations)]
struct LcoreRegistration;

impl Drop for LcoreRegistration {
    fn drop(&mut self) {
        // SAFETY: paired with the `rte_thread_register` that preceded this guard's construction,
        // on the same thread, and runs exactly once because the guard is never cloned or moved.
        unsafe { dpdk_sys::rte_thread_unregister() };
    }
}

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
                info!("Initializing RTE Lcore");
                let ret = unsafe { dpdk_sys::rte_thread_register() };
                if ret != 0 {
                    let errno = unsafe { dpdk_sys::rte_errno_get() };
                    let msg = format!("rte thread exited with code {ret}, errno: {errno}");
                    Eal::fatal_error(msg)
                }
                // Unregister on the way out however this thread ends.  A bare call after `run()`
                // is skipped when `run()` unwinds, and every skipped unregister strands an lcore
                // id for the life of the process -- `RTE_MAX_LCORE` of them and no further thread
                // can register at all.  A panicking service thread is exactly the situation where
                // that matters, since it is also the one most likely to be retried.
                let _registration = LcoreRegistration;
                let thread_id = unsafe { dpdk_sys::rte_thread_self() };
                send.send(thread_id).expect("could not send thread id");
                run();
            })
            .expect("could not create EalThread");
        let thread_id = RteThreadId(recv.recv().expect("could not receive thread id"));
        ServiceThread {
            thread_id,
            priority: LCorePriority::RealTime,
            handle,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn join(self) -> std::thread::Result<()> {
        self.handle.join()
    }
}

#[allow(unused)]
pub struct WorkerThread {
    lcore_id: LCoreId,
}

impl WorkerThread {
    #[allow(clippy::expect_used)] // this is only called at system launch where crash is still ok
    pub fn launch<T: Send + FnOnce()>(lcore: LCoreId, f: T) {
        #[inline]
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

    /// Every lcore the EAL enabled, including the main one.
    ///
    /// This replaces a former `iter()` whose name and documentation promised all lcores while it
    /// actually skipped the main one -- so it returned an empty iterator under any configuration
    /// whose only lcore is main. Use [`workers`](Self::workers) when the main lcore should be
    /// excluded, and say which you mean.
    #[tracing::instrument(level = "trace")]
    pub fn all() -> impl Iterator<Item = LCoreId> {
        LCoreIdIterator::all()
    }

    /// Every lcore the EAL enabled except the main one.
    ///
    /// The set to dispatch work across: the main lcore runs the control plane, and DPDK's own
    /// dispatch helpers (`rte_eal_remote_launch`, `RTE_LCORE_FOREACH_WORKER`) exclude it for the
    /// same reason. Empty when the EAL was given only one lcore.
    #[tracing::instrument(level = "trace")]
    pub fn workers() -> impl Iterator<Item = LCoreId> {
        LCoreIdIterator::workers()
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
            // Workers only, which this constructor's documentation has always stated.
            inner: LCoreIdIterator::workers(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::with_eal;

    /// `all()` includes the main lcore and `workers()` does not.
    ///
    /// This is the test the former `iter()` needed and did not have. Under the unit-test EAL the
    /// only enabled lcore *is* the main one, so `workers()` is legitimately empty while `all()`
    /// must not be -- which is exactly the case where a single iterator claiming to cover "all"
    /// lcores while skipping main returns nothing and looks like a broken EAL.
    #[test]
    #[with_eal]
    fn all_includes_the_main_lcore_and_workers_excludes_it() {
        let main = LCoreId::main();
        let all: Vec<_> = LCoreId::all().collect();
        let workers: Vec<_> = LCoreId::workers().collect();

        assert!(
            all.contains(&main),
            "all() must include the main lcore {main:?}, got {all:?}"
        );
        assert!(
            !workers.contains(&main),
            "workers() must exclude the main lcore {main:?}, got {workers:?}"
        );
        assert_eq!(
            all.len(),
            workers.len() + 1,
            "the two sets should differ by exactly the main lcore"
        );
    }

    /// Everything `all()` yields is an lcore DPDK considers enabled, and in range.
    #[test]
    #[with_eal]
    fn all_yields_only_valid_enabled_lcores() {
        let all: Vec<_> = LCoreId::all().collect();
        assert!(!all.is_empty(), "a running EAL has at least one lcore");
        for lcore in all {
            assert!(lcore.as_u32() < LCoreId::MAX, "{lcore:?} out of range");
            assert_ne!(
                unsafe { dpdk_sys::rte_lcore_is_enabled(lcore.as_u32()) },
                0,
                "{lcore:?} was yielded but DPDK does not consider it enabled"
            );
        }
    }

    /// The fact that motivated dropping `LCoreId` from `concurrency::local::Local` in favour of a
    /// `ThreadId`: DPDK reports `LCORE_ID_ANY` (`u32::MAX`) for a thread that is neither an EAL
    /// thread nor registered, so an lcore id is simply unavailable on an ordinary thread.
    ///
    /// Kept as a regression test because the choice is easy to second-guess later.
    #[test]
    #[with_eal]
    fn an_unregistered_thread_has_no_lcore_identity() {
        let id = std::thread::spawn(|| LCoreId::current().as_u32())
            .join()
            .expect("thread panicked");
        assert_eq!(
            id,
            u32::MAX,
            "expected LCORE_ID_ANY on an unregistered thread"
        );
    }

    /// ...whereas a registered thread does get one, and it is not the main lcore.
    #[test]
    #[with_eal]
    fn a_registered_thread_gets_a_non_main_lcore() {
        // SAFETY: registers the calling thread with the EAL; paired with `rte_thread_unregister`
        // below.  Per-thread state, so it does not disturb other tests.
        let ret = unsafe { dpdk_sys::rte_thread_register() };
        assert_eq!(ret, 0, "could not register the test thread with the EAL");

        let here = LCoreId::current();
        assert_ne!(
            here.as_u32(),
            u32::MAX,
            "a registered thread should have an lcore"
        );
        assert_ne!(
            here,
            LCoreId::main(),
            "a registered non-EAL thread is not the main lcore"
        );

        // SAFETY: pairs with the `rte_thread_register` above.
        unsafe { dpdk_sys::rte_thread_unregister() };
    }
}
