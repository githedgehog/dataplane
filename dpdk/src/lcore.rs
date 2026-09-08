// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::eal::{Eal, EalErrno};
use core::ffi::{c_int, c_uint, c_void};
use core::fmt::Debug;
use errno::ErrorCode;
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

/// A thread spawned and registered with the EAL for its lifetime.
///
/// # This is not a DPDK "service core"
///
/// It was called `ServiceThread`, which invited exactly the wrong reading. DPDK has a distinct and
/// unrelated concept: a **service core** is an lcore with `ROLE_SERVICE` that runs registered
/// service *functions* (`rte_service_component_register`) on a scheduler DPDK owns. This type is
/// nothing of the kind -- it is an ordinary Rust thread that happens to hold an
/// [`LCore`], and it is `ROLE_NON_EAL`. `rte_service_lcore_add` would refuse it.
///
/// The two are not interchangeable and the names should not be either.
///
/// # What it is for
///
/// It spawns a thread, registers it, and **lends the resulting [`LCore`] token to the body**. That
/// is the whole job: the body cannot run without a registration, cannot outlive it, and cannot move
/// it elsewhere, so every API gated on `&LCore` is reachable inside and nowhere outside.
#[allow(unused)]
pub struct RegisteredThread<'scope> {
    thread_id: RteThreadId,
    priority: LCorePriority,
    handle: std::thread::ScopedJoinHandle<'scope, ()>,
}

// TODO: take stack size as an EAL argument instead of hard coding it
const STACK_SIZE: usize = 8 << 20;

/// Proof, held by value, that **this** thread is registered with the EAL.
///
/// This is a capability token, not merely a guard. Some DPDK calls are only meaningful -- or only
/// safe -- on a thread the EAL knows about, and those take an `&LCore` so that the requirement is
/// discharged at the type level instead of being a comment nobody reads. Registration is released
/// when the token drops.
///
/// # Why a thread wants to be registered
///
/// A thread the EAL does not know about reports `LCORE_ID_ANY` (`u32::MAX`) from `rte_lcore_id()`,
/// and DPDK reads that in more places than is obvious:
///
/// - **Mempool caches.** `rte_mempool_default_cache` returns `NULL` for `LCORE_ID_ANY`, so an
///   unregistered thread has no per-core object cache and every `alloc_bulk` and every mbuf free
///   goes to the shared ring under atomics -- on every burst, in both directions. This one is a
///   silent performance cliff rather than an error, which is why it is not gated on the token.
/// - **Per-lcore variables.** `RTE_LCORE_VAR` indexes `handle + lcore_id * RTE_MAX_LCORE_VAR`. At
///   `LCORE_ID_ANY` that is a wild pointer, which is why DPDK documents the accessor as usable only
///   by EAL threads and registered non-EAL threads. Anything this crate builds on lcore variables
///   **must** take an `&LCore`.
/// - **The power-monitor family** ([`crate::power`]) rejects an unregistered caller with `-EINVAL`.
/// - `socket::Preference::CurrentThread` answers `SOCKET_ID_ANY` rather than a real NUMA node.
///
/// # Why `&LCore` is sound proof about the *current* thread
///
/// [`LCore`] is `!Send` **and** `!Sync`. `!Send` keeps the token itself on the registering thread;
/// `!Sync` is what makes `&LCore` also `!Send`, so a *reference* cannot be handed to another thread
/// either. Both are needed: with only `!Send`, a `&LCore` could be shared with an unregistered
/// thread and would then prove nothing about it.
///
/// # Why it releases on drop
///
/// `rte_thread_unregister` releases the *calling* thread's id, so it must run on the thread that
/// registered and it must run however that thread ends. A bare call after the work is skipped when
/// the work unwinds, and **every skipped unregister strands an lcore id for the life of the
/// process** -- there are `RTE_MAX_LCORE` of them, after which nothing can register at all. A
/// panicking worker is exactly the case where that matters, being also the one most likely to be
/// restarted.
///
/// Note the token deliberately carries no `'eal` brand. The invariant that a registration must not
/// outlive the EAL is real -- `rte_eal_cleanup` detaches DPDK memory and frees per-lcore storage --
/// but it is already enforced where it arises: workers live in a `thread::scope` that cannot return
/// until they are joined, and the ports they borrow *are* `'eal`-branded. `Eal::drop` also counts
/// any stragglers and complains. Branding this token too would prove the same property a second
/// time at the cost of threading an `EalShared` into every registration site.
#[allow(missing_debug_implementations)]
pub struct LCore {
    id: LCoreId,
    /// Pins the token to the registering thread, and `&LCore` with it. See the type docs.
    _not_send: core::marker::PhantomData<*const ()>,
}

/// The token cannot be sent to another thread, so it cannot release someone else's id.
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::lcore::LCore;
/// fn assert_send<T: Send>(_: T) {}
/// fn not_send(lcore: LCore) {
///     assert_send(lcore);
/// }
/// ```
///
/// Nor can a *reference* to it, which is what makes `&LCore` proof about the calling thread rather
/// than about some other thread that once registered. This is the property `!Sync` buys, and it is
/// the one that would be easy to lose by deriving something careless.
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::lcore::LCore;
/// fn assert_send<T: Send>(_: T) {}
/// fn ref_not_send(lcore: &LCore) {
///     assert_send(lcore);
/// }
/// ```
///
/// And a gated API cannot be reached without one.
///
/// ```compile_fail,E0061
/// # use dataplane_dpdk::power;
/// # fn call(cond: &power::MonitorCond<'_>) {
/// power::monitor(cond, 0).unwrap();
/// # }
/// ```
impl LCore {
    /// Register the calling thread with the EAL.
    ///
    /// Prefer [`LCore::with`], which cannot leave the registration held past the work it was for.
    ///
    /// # Errors
    ///
    /// Returns `EEXIST` if this thread already has an lcore id, and the EAL's `rte_errno`
    /// (typically `ENOMEM`) if no id was available -- see
    /// `dpdk/examples/lcore_capacity_probe.rs` for what the capacity actually is.
    pub fn register() -> Result<LCore, ErrorCode> {
        // `rte_thread_register` does **not** check whether the calling thread already has an lcore
        // id -- it allocates a fresh non-EAL one and `__rte_thread_init` overwrites the thread's
        // id with it. Doing that on an EAL lcore (the main one, say) silently costs that thread its
        // real identity, and the matching unregister then leaves it as `LCORE_ID_ANY` rather than
        // restoring what it was. Nothing downstream would report an error; the thread would simply
        // stop being the main lcore. Refuse instead.
        if LCoreId::current().as_u32() != u32::MAX {
            warn!("this thread is already an lcore; refusing to register it a second time");
            return Err(ErrorCode::parse_i32(-errno::EEXIST));
        }
        // SAFETY: no preconditions; the EAL is initialised by construction, since nothing can hold
        // an `Eal` handle to reach this otherwise.
        let ret = unsafe { dpdk_sys::rte_thread_register() };
        if ret != 0 {
            let errno = unsafe { dpdk_sys::rte_errno_get() };
            warn!("could not register this thread with the EAL: ret {ret}, errno {errno}");
            return Err(ErrorCode::parse_i32(errno));
        }
        Ok(LCore {
            id: LCoreId::current(),
            _not_send: core::marker::PhantomData,
        })
    }

    /// Register this thread, run `f` with the token, and release the registration.
    ///
    /// # Errors
    ///
    /// Returns whatever [`LCore::register`] would.
    pub fn with<R>(f: impl FnOnce(&LCore) -> R) -> Result<R, ErrorCode> {
        let lcore = LCore::register()?;
        Ok(f(&lcore))
    }

    /// The lcore id the EAL assigned to this thread.
    ///
    /// Never `LCORE_ID_ANY`: the token only exists after a successful registration, and cannot
    /// outlive it or leave this thread.
    #[must_use]
    pub fn id(&self) -> LCoreId {
        self.id
    }
}

impl Drop for LCore {
    fn drop(&mut self) {
        // SAFETY: paired with the `rte_thread_register` in `register`, on the same thread (the
        // token is `!Send`), and runs exactly once because it is neither `Clone` nor `Copy`.
        unsafe { dpdk_sys::rte_thread_unregister() };
    }
}

impl RegisteredThread<'_> {
    #[cold]
    #[allow(clippy::expect_used)]
    #[tracing::instrument(level = "debug", skip(run))]
    pub fn new<'scope>(
        scope: &'scope std::thread::Scope<'scope, '_>,
        name: impl AsRef<str> + Debug,
        run: impl FnOnce(&LCore) + 'scope + Send,
    ) -> RegisteredThread<'scope> {
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::Builder::new()
            .name(name.as_ref().to_string())
            .stack_size(STACK_SIZE)
            .spawn_scoped(scope, move || {
                info!("Initializing RTE Lcore");
                // The registration is created here and lent to `run`, which is the point of this
                // type: the body cannot run without one, cannot keep it afterwards, and cannot send
                // it anywhere. Everything gated on `&LCore` is reachable inside `run` and nowhere
                // else.
                let lcore = LCore::register().unwrap_or_else(|e| {
                    Eal::fatal_error(format!("could not register an EAL thread: {e:?}"))
                });
                let thread_id = unsafe { dpdk_sys::rte_thread_self() };
                send.send(thread_id).expect("could not send thread id");
                run(&lcore);
            })
            .expect("could not create EalThread");
        let thread_id = RteThreadId(recv.recv().expect("could not receive thread id"));
        RegisteredThread {
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

    /// The guard registers, so a thread holding one has a real lcore id.
    ///
    /// That id is the whole point: `rte_mempool_default_cache` returns NULL for `LCORE_ID_ANY`, so
    /// without it a thread allocates and frees mbufs straight out of the shared ring.
    #[test]
    #[with_eal]
    fn the_guard_registers_the_calling_thread() {
        // Spawned deliberately. Whether the *harness's* thread is registered is not a property of
        // this code: under `cargo test` a test body runs on a spawned thread and is unregistered,
        // while under `nextest` (one process per test) it runs on the thread that initialised the
        // EAL and so *is* the main lcore. A freshly spawned thread is unregistered under both, and
        // is what the real callers are.
        std::thread::spawn(|| {
            assert_eq!(
                LCoreId::current().as_u32(),
                u32::MAX,
                "a freshly spawned thread should start unregistered"
            );

            let registration = LCore::register().expect("could not register");
            let here = LCoreId::current();
            assert_ne!(here.as_u32(), u32::MAX, "the guard did not register");
            assert_ne!(
                here,
                LCoreId::main(),
                "a registered thread is not the main lcore"
            );

            drop(registration);
            assert_eq!(
                LCoreId::current().as_u32(),
                u32::MAX,
                "the guard did not release the id when dropped"
            );
        })
        .join()
        .expect("the test thread panicked");
    }

    /// Registering a thread that already has an lcore id is refused.
    ///
    /// `rte_thread_register` itself does not check: it allocates a fresh non-EAL id and overwrites
    /// the thread's with it, so calling it on the main lcore silently costs that thread its
    /// identity, and the matching unregister then leaves it `LCORE_ID_ANY` rather than restoring
    /// lcore 0. Nothing downstream reports an error, which is what makes it worth refusing here.
    #[test]
    #[with_eal]
    fn a_thread_that_is_already_an_lcore_is_refused() {
        std::thread::spawn(|| {
            let first = LCore::register().expect("first registration");
            let id = LCoreId::current();

            assert!(
                LCore::register().is_err(),
                "registering twice on one thread was allowed; the second would have overwritten \
                 the first's lcore id"
            );
            assert_eq!(
                LCoreId::current(),
                id,
                "the refused registration changed this thread's lcore id anyway"
            );
            drop(first);
        })
        .join()
        .expect("the test thread panicked");
    }

    /// Dropping the guard returns the id to the pool, so registrations can be made indefinitely.
    ///
    /// This is the property the guard exists for. A leaked registration strands an id for the life
    /// of the process, and there are only `RTE_MAX_LCORE` of them -- so a worker that is restarted
    /// enough times without releasing would eventually be unable to register at all. Iterating
    /// well past any plausible `RTE_MAX_LCORE` is what makes a leak show up as a failure here
    /// rather than as an exhaustion months later.
    #[test]
    #[with_eal]
    fn registrations_are_released_and_can_be_reused() {
        // Spawned, for the same reason as `the_guard_registers_the_calling_thread`.
        std::thread::spawn(|| {
            for round in 0..1024 {
                let registration = LCore::register()
                    .unwrap_or_else(|e| panic!("registration {round} failed: {e:?} -- ids leaked"));
                assert_ne!(LCoreId::current().as_u32(), u32::MAX);
                drop(registration);
            }
        })
        .join()
        .expect("the test thread panicked");
    }

    /// `LCore::with` registers for the duration of the closure and releases after it.
    #[test]
    #[with_eal]
    fn with_scopes_the_registration_to_the_closure() {
        std::thread::spawn(|| {
            let seen = LCore::with(|lcore| {
                assert_ne!(lcore.id().as_u32(), u32::MAX, "the token has no lcore id");
                assert_eq!(
                    lcore.id(),
                    LCoreId::current(),
                    "the token disagrees with the thread it was made on"
                );
                lcore.id()
            })
            .expect("could not register");
            assert_ne!(seen.as_u32(), u32::MAX);
            assert_eq!(
                LCoreId::current().as_u32(),
                u32::MAX,
                "the registration outlived the closure"
            );
        })
        .join()
        .expect("the test thread panicked");
    }

    /// The id a token reports stays put for its whole life.
    ///
    /// It is cached at construction rather than read on each call, so this is the test that says
    /// the cache cannot go stale -- which it could if a token were ever reachable from a thread
    /// other than the one that made it.
    #[test]
    #[with_eal]
    fn a_token_reports_a_stable_id() {
        std::thread::spawn(|| {
            let lcore = LCore::register().expect("could not register");
            let first = lcore.id();
            for _ in 0..100 {
                assert_eq!(lcore.id(), first);
                assert_eq!(lcore.id(), LCoreId::current());
            }
        })
        .join()
        .expect("the test thread panicked");
    }

    /// Concurrent registrations get distinct lcore ids.
    ///
    /// The allocator hands out the first `ROLE_OFF` slot under a write lock; if that were racy two
    /// threads could share an id, and an lcore id is the index into per-lcore state -- most
    /// visibly a mempool's `local_cache`, where two threads sharing a cache would corrupt it.
    ///
    /// Deliberately a small number rather than a saturating one. Capacity is process-global, and
    /// under `cargo test` (which shares one process across tests, unlike nextest) a test that
    /// consumed every id would starve whatever ran beside it. Exhaustion behaviour is covered by
    /// `examples/lcore_capacity_probe.rs` instead, where the process is the probe's own.
    #[test]
    #[with_eal]
    fn concurrent_registrations_get_distinct_ids() {
        const THREADS: usize = 16;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
        let ids: Vec<u32> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        let _registration = LCore::register().expect("could not register");
                        let id = LCoreId::current().as_u32();
                        // Hold every registration at once; ids are only distinct if they overlap.
                        barrier.wait();
                        id
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("a registering thread panicked"))
                .collect()
        });

        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            THREADS,
            "concurrent registrations shared an lcore id: {ids:?}"
        );
        assert!(
            ids.iter().all(|id| *id != u32::MAX),
            "a registration reported no lcore id: {ids:?}"
        );
    }

    /// An unwinding thread still releases its id.
    ///
    /// The guard is a `Drop` impl precisely so that a panicking worker -- the case most likely to
    /// be retried, and so the one where exhaustion would compound -- does not strand its id.
    #[test]
    #[with_eal]
    fn a_panicking_thread_releases_its_registration() {
        let before = std::thread::spawn(|| {
            let _registration = LCore::register().expect("register");
            LCoreId::current().as_u32()
        })
        .join()
        .expect("thread should not have panicked");
        assert_ne!(before, u32::MAX);

        // Panic while holding a guard, many times over. If unwinding skipped the release, this
        // would strand an id per iteration and the assertion below would eventually fail.
        for _ in 0..512 {
            let panicked = std::thread::spawn(|| {
                let _registration = LCore::register().expect("register");
                panic!("deliberate");
            })
            .join();
            assert!(panicked.is_err(), "the thread was supposed to panic");
        }

        let after = std::thread::spawn(|| {
            let _registration = LCore::register().expect(
                "could not register after panicking threads ran -- unwinding leaked lcore ids",
            );
            LCoreId::current().as_u32()
        })
        .join()
        .expect("thread should not have panicked");
        assert_ne!(after, u32::MAX);
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
