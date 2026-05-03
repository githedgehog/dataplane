// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reconciler-shaped management of the ACL pipeline.
//!
//! This module hosts the control-plane / data-plane bridge:
//!
//! - [`Backend`] is the per-backend hook that knows how to materialize
//!   a [`PipelineIR`] into a runtime-side value (e.g. a DPDK
//!   `AclContext`, or an `enum`'d `Empty | Built` for non-allocating
//!   sentinel use).
//! - [`AclManager`] is the rekon-facing object; it implements
//!   [`rekon::Observe`] and [`rekon::Reconcile`].
//! - [`spawn_manager`] wires everything up: constructs an empty
//!   materialization, builds a [`pipeline`] writer/factory pair, and
//!   spins up an EAL-registered [`ServiceThread`] that owns the
//!   writer and runs the build loop.
//!
//! # Threading
//!
//! The reconciler ([`AclManager`]) runs on the mgmt thread (typically
//! a `current_thread` tokio runtime).  The build worker runs on a
//! [`ServiceThread`] which is EAL-registered for backends that need
//! it.  Communication is via two private primitives in this module:
//!
//! - [`GreedyMailbox`] for desired-IR submission (single-slot,
//!   latest-wins; older un-taken submissions are silently coalesced
//!   into the newest).
//! - [`OutcomeBoard`] for build results (latest-wins; reconciler
//!   awaits "world is at or past gen N").
//!
//! # Reclamation
//!
//! Materialized values published via [`pipeline::PipelineWriter`] are
//! reclaimed by the writer thread per the QSBR scheme in
//! [`pipeline`](crate::pipeline).  This module piggy-backs on that
//! contract; no additional reclamation logic lives here.
//!
//! [`ServiceThread`]: dpdk::lcore::ServiceThread
//! [`pipeline`]: crate::pipeline

#![allow(missing_docs)] // shape settling; doc once stable

use crate::ir::PipelineIR;
use crate::pipeline::{Lookup, PipelineWriter, ReaderFactory, pipeline};
use arc_swap::ArcSwap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

// =====================================================================
// Backend -- per-backend materialization hook
// =====================================================================

/// Backend-specific materialization of a [`PipelineIR`].
///
/// Each backend (DPDK ACL, tc-flower, rte_flow, hardware) implements
/// this once.  [`Materialized`](Self::Materialized) is whatever the
/// data path needs to do lookups (e.g. `enum DpdkPipeline { Empty,
/// Built { ... } }`); the manager owns one current and one or more
/// retired generations of it via the [`pipeline`] machinery.
///
/// # Threading
///
/// [`empty`](Self::empty) is called on the calling thread of
/// [`spawn_manager`] (typically the mgmt thread, which is NOT
/// EAL-registered).  Backends with FFI allocator requirements MUST
/// make `empty` allocate nothing from the FFI side.  For DPDK ACL,
/// that means a sentinel variant that returns `None` on every lookup
/// rather than an `rte_acl` context with zero rules.
///
/// [`build`](Self::build) is called on the EAL-registered build
/// worker thread; FFI allocations are valid there.
///
/// [`pipeline`]: crate::pipeline
pub trait Backend: Send + 'static {
    type Materialized: Lookup + Send + Sync + Unpin + 'static;
    type Error: Send + Sync + 'static + std::error::Error;

    /// Allocator-free "no rules installed yet" sentinel.  Constructed
    /// before the first build completes.
    fn empty() -> Self::Materialized;

    /// Build a [`Materialized`](Self::Materialized) from `ir`.  Runs
    /// on the build worker thread.
    fn build(&self, ir: &PipelineIR) -> Result<Self::Materialized, Self::Error>;
}

// =====================================================================
// Submission + Payload -- internal channel types
// =====================================================================

/// A single mailbox payload from the manager to the build worker.
///
/// Carries the generation tag for outcome-board correlation, plus
/// either a desired IR to build OR a shutdown signal.
struct Submission {
    generation: u64,
    payload: Payload,
}

enum Payload {
    Build(Arc<PipelineIR>),
    Shutdown,
}

// =====================================================================
// GreedyMailbox -- single-slot coalescing channel
// =====================================================================

/// Single-slot coalescing channel.  `submit` always overwrites;
/// `take_blocking` waits until something is in the slot and returns
/// the latest value (silently dropping any intermediate writes that
/// were coalesced into the new latest).
///
/// Asymmetric: `submit` is callable from any thread (sync); the
/// consumer (`take_blocking`) is the build worker (sync).  The mgmt
/// runtime calling `submit` from an `async fn` is fine -- the lock
/// is held only briefly and never across an `.await`.
pub(crate) struct GreedyMailbox<T> {
    slot: Mutex<Option<T>>,
    cv: Condvar,
}

impl<T> GreedyMailbox<T> {
    pub(crate) fn new() -> Self {
        Self {
            slot: Mutex::new(None),
            cv: Condvar::new(),
        }
    }

    pub(crate) fn submit(&self, value: T) {
        let mut slot = self.slot.lock().expect("greedy mailbox poisoned");
        *slot = Some(value);
        self.cv.notify_all();
    }

    pub(crate) fn take_blocking(&self) -> T {
        let mut slot = self.slot.lock().expect("greedy mailbox poisoned");
        loop {
            if let Some(v) = slot.take() {
                return v;
            }
            slot = self
                .cv
                .wait(slot)
                .expect("greedy mailbox condvar wait failed");
        }
    }
}

// =====================================================================
// OutcomeBoard -- latest-wins async-friendly result publication
// =====================================================================

/// Build outcomes, latest-wins.  "World is at or past gen N"
/// semantics: a reconciler that submitted gen 3 is satisfied if the
/// world ever reaches gen 3 *or any later gen* -- which is what
/// makes greedy coalescing on the mailbox safe.
pub(crate) struct OutcomeBoard<E> {
    state: Mutex<OutcomeState<E>>,
    notify: tokio::sync::Notify,
}

#[derive(Debug)]
struct OutcomeState<E> {
    completed_generation: u64,
    last_error: Option<Arc<E>>,
}

impl<E> OutcomeBoard<E> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(OutcomeState {
                completed_generation: 0,
                last_error: None,
            }),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Called by the build worker after each completed (or failed)
    /// build attempt.  Updates the latest reported state and wakes
    /// any async waiters.
    pub(crate) fn publish(&self, generation: u64, result: Result<(), E>) {
        {
            let mut state = self.state.lock().expect("outcome mutex poisoned");
            state.completed_generation = state.completed_generation.max(generation);
            match result {
                Ok(()) => state.last_error = None,
                Err(e) => state.last_error = Some(Arc::new(e)),
            }
        }
        self.notify.notify_waiters();
    }

    /// Wait until the world is at or past `generation`.  Returns the
    /// (current, possibly-later) generation on success, or the
    /// `Arc<E>` error of whichever attempt last failed at or above
    /// `generation`.
    pub(crate) async fn wait_for_gen(&self, generation: u64) -> Result<u64, Arc<E>> {
        loop {
            let snapshot = {
                let state = self.state.lock().expect("outcome mutex poisoned");
                if state.completed_generation >= generation {
                    Some((state.completed_generation, state.last_error.clone()))
                } else {
                    None
                }
            };
            match snapshot {
                Some((completed, None)) => return Ok(completed),
                Some((_, Some(err))) => return Err(err),
                None => self.notify.notified().await,
            }
        }
    }
}

// =====================================================================
// AclManager -- the rekon-facing object
// =====================================================================

/// Owns the channel handles to the build worker plus a snapshot of
/// the IR-of-installed.  Implements [`rekon::Observe`] and
/// [`rekon::Reconcile`].
///
/// `Send + Sync`: rekon's [`reconcile`](rekon::Reconcile::reconcile)
/// returns `impl Future + Send`, and the body holds `&self` across an
/// `.await`, so `Self: Sync` is required.  Internal state is all
/// `Arc`s wrapping atomics + mutexes; no thread-affine state lives
/// in the manager itself.
pub struct AclManager<E: Send + Sync + 'static> {
    submission: Arc<GreedyMailbox<Submission>>,
    outcomes: Arc<OutcomeBoard<E>>,
    /// IR-of-installed.  Updated pessimistically by the worker after
    /// a successful build.  Source of truth for `Observe`.
    installed_ir: Arc<ArcSwap<PipelineIR>>,
    next_generation: AtomicU64,
}

impl<E: Send + Sync + 'static> AclManager<E> {
    /// Snapshot the IR-of-installed.  Equivalent to
    /// [`rekon::Observe::observe`]; exposed directly for callers that
    /// don't want to plumb through rekon.
    #[must_use]
    pub fn installed(&self) -> Arc<PipelineIR> {
        self.installed_ir.load_full()
    }

    /// Latest generation number the mgmt side has submitted.  Returns
    /// 0 before any successful submission.
    #[must_use]
    pub fn current_submission_generation(&self) -> u64 {
        self.next_generation
            .load(Ordering::Relaxed)
            .saturating_sub(1)
    }
}

impl<E: Send + Sync + 'static> Drop for AclManager<E> {
    fn drop(&mut self) {
        // Signal the build worker to exit its loop.  The mailbox slot
        // is greedy: if there's a pending Build submission, it gets
        // coalesced with this Shutdown, which is exactly what we
        // want -- in-flight build requests stop mattering once we're
        // shutting down anyway.
        self.submission.submit(Submission {
            generation: u64::MAX,
            payload: Payload::Shutdown,
        });
    }
}

impl<E: Send + Sync + 'static> rekon::Observe for AclManager<E> {
    type Observation<'a>
        = Arc<PipelineIR>
    where
        Self: 'a;

    async fn observe<'a>(&self) -> Self::Observation<'a>
    where
        Self: 'a,
    {
        self.installed_ir.load_full()
    }
}

impl<E: Send + Sync + 'static> rekon::Reconcile for AclManager<E> {
    type Requirement<'a>
        = Arc<PipelineIR>
    where
        Self: 'a;
    type Observation<'a>
        = Arc<PipelineIR>
    where
        Self: 'a;
    type Outcome<'a>
        = Result<u64, Arc<E>>
    where
        Self: 'a;

    async fn reconcile<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        if *requirement == *observation {
            return Ok(self.outcomes_completed_generation());
        }
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        self.submission.submit(Submission {
            generation,
            payload: Payload::Build(requirement),
        });
        self.outcomes.wait_for_gen(generation).await
    }
}

impl<E: Send + Sync + 'static> AclManager<E> {
    /// Snapshot of the latest-completed generation reported by the
    /// build worker.
    fn outcomes_completed_generation(&self) -> u64 {
        let state = self.outcomes.state.lock().expect("outcome mutex poisoned");
        state.completed_generation
    }
}

// =====================================================================
// spawn_manager + worker loop
// =====================================================================

/// Bring up an [`AclManager`] and its build worker.
///
/// Constructs an empty materialization, wires the publish/observe
/// machinery, and spawns a [`dpdk::lcore::ServiceThread`] inside
/// `scope` to run the build loop on an EAL-registered thread.
/// Returns the manager (for the mgmt-side reconciler) and a
/// [`ReaderFactory`] (for handing to lcore lookup threads).
///
/// The build worker exits its loop when [`AclManager`] drops
/// (`Drop` sends a `Shutdown` payload via the mailbox), so the
/// scope's auto-join after the calling block ends is deterministic;
/// no explicit join needed.
///
/// # EAL prerequisite
///
/// The DPDK EAL must be initialised before this is called.  This is
/// not enforced statically; calling it without EAL will panic on the
/// first `rte_thread_register` attempted by `ServiceThread::new`.
/// During this phase we assume EAL is always available; a later
/// refactor can add a non-EAL spawn variant for testing
/// non-DPDK-bound backends in isolation.
pub fn spawn_manager<'scope, B: Backend>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    backend: B,
) -> (AclManager<B::Error>, ReaderFactory<B::Materialized>) {
    let initial = B::empty();
    let (writer, factory) = pipeline(initial);

    let submission = Arc::new(GreedyMailbox::<Submission>::new());
    let outcomes = Arc::new(OutcomeBoard::<B::Error>::new());
    let installed_ir = Arc::new(ArcSwap::from_pointee(PipelineIR::default()));

    {
        let submission = Arc::clone(&submission);
        let outcomes = Arc::clone(&outcomes);
        let installed_ir = Arc::clone(&installed_ir);
        // AssertUnwindSafe: pipeline machinery is mutex-and-arc only;
        // an inner panic doesn't violate logical invariants this
        // closure cares about.
        //
        // ServiceThread<'scope> handle is dropped here; the spawned
        // thread keeps running until AclManager::drop sends Shutdown
        // and the worker_loop exits voluntarily.  std::thread::scope's
        // auto-join collects the thread on its way out.
        let _ = dpdk::lcore::ServiceThread::new(
            scope,
            "acl-build",
            AssertUnwindSafe(move || {
                worker_loop(backend, submission, outcomes, writer, installed_ir);
            }),
        );
    }

    let manager = AclManager {
        submission,
        outcomes,
        installed_ir,
        next_generation: AtomicU64::new(1),
    };

    (manager, factory)
}

fn worker_loop<B: Backend>(
    backend: B,
    submission: Arc<GreedyMailbox<Submission>>,
    outcomes: Arc<OutcomeBoard<B::Error>>,
    mut writer: PipelineWriter<B::Materialized>,
    installed_ir: Arc<ArcSwap<PipelineIR>>,
) {
    loop {
        let submission = submission.take_blocking();
        match submission.payload {
            Payload::Shutdown => break,
            Payload::Build(ir) => match backend.build(&ir) {
                Ok(materialized) => {
                    let _published = writer.publish(materialized);
                    installed_ir.store(ir);
                    outcomes.publish(submission.generation, Ok(()));
                }
                Err(err) => {
                    // installed_ir unchanged on failure -- the next
                    // reconcile re-diffs against the still-prior
                    // installed and either re-submits (if desired
                    // remains different) or short-circuits (if the
                    // operator reverted the desired state).
                    outcomes.publish(submission.generation, Err(err));
                }
            },
        }
    }
}

// =====================================================================
// Tests (no DPDK; uses a fake Backend)
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{AclAction, AclRule, PortRange, Proto, RuleId};
    use std::num::NonZero;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    // -- Toy backend -------------------------------------------------------

    /// Minimal Backend impl that just clones the IR's rules into a
    /// linear vector.  No FFI, no DPDK; lookup is an O(N) scan.
    /// Counts builds so tests can assert greedy coalescing.
    struct ToyBackend {
        build_count: Arc<AtomicUsize>,
        build_delay: Duration,
        fail_on: Option<u64>, // build the Nth gen returns Err
    }

    #[derive(Debug)]
    enum ToyPipeline {
        Empty,
        Built(Vec<AclRule>),
    }

    impl Lookup for ToyPipeline {
        type Key = u64; // RuleId-as-u64 for the toy
        type Rule = AclRule;
        fn lookup(&self, key: &u64) -> Option<&AclRule> {
            match self {
                ToyPipeline::Empty => None,
                ToyPipeline::Built(rs) => rs.iter().find(|r| r.id.get().get() == *key),
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    enum ToyError {
        #[error("induced failure for testing")]
        Induced,
    }

    impl Backend for ToyBackend {
        type Materialized = ToyPipeline;
        type Error = ToyError;

        fn empty() -> ToyPipeline {
            ToyPipeline::Empty
        }

        fn build(&self, ir: &PipelineIR) -> Result<ToyPipeline, ToyError> {
            let n = self.build_count.fetch_add(1, Ordering::Relaxed) as u64;
            if Some(n) == self.fail_on {
                return Err(ToyError::Induced);
            }
            std::thread::sleep(self.build_delay);
            Ok(ToyPipeline::Built(ir.acl.iter().cloned().collect()))
        }
    }

    fn rid(n: u64) -> RuleId {
        RuleId::new(NonZero::new(n).unwrap())
    }

    fn rule(n: u64, action: AclAction) -> AclRule {
        AclRule {
            id: rid(n),
            priority: 100,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: Some(PortRange { lo: 80, hi: 80 }),
            proto: Some(Proto::Tcp),
            action,
        }
    }

    fn run<F: std::future::Future<Output = T>, T>(f: F) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt")
            .block_on(f)
    }

    use crate::test_support::EAL;

    // -- Basic flow --------------------------------------------------------

    #[test]
    fn applying_the_initial_empty_ir_is_a_noop() {
        let _eal = &*EAL;
        let count = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let backend = ToyBackend {
                build_count: Arc::clone(&count),
                build_delay: Duration::ZERO,
                fail_on: None,
            };
            let (manager, _factory) = spawn_manager(scope, backend);

            run(async {
                use rekon::{Observe, Reconcile};
                let observation = manager.observe().await;
                let requirement = Arc::new(PipelineIR::default());
                let outcome = manager.reconcile(requirement, observation).await;
                assert!(outcome.is_ok(), "noop reconcile should succeed");
            });

            // No build happened: manager observed empty == requirement empty.
            assert_eq!(count.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn first_real_reconcile_triggers_a_build_and_updates_installed() {
        let _eal = &*EAL;
        let count = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let backend = ToyBackend {
                build_count: Arc::clone(&count),
                build_delay: Duration::ZERO,
                fail_on: None,
            };
            let (manager, _factory) = spawn_manager(scope, backend);

            let mut ir = PipelineIR::new();
            ir.acl.insert(rule(1, AclAction::Accept));
            let req = Arc::new(ir);

            run(async {
                use rekon::{Observe, Reconcile};
                let obs = manager.observe().await;
                let outcome = manager
                    .reconcile(Arc::clone(&req), obs)
                    .await
                    .expect("reconcile");
                assert!(outcome >= 1, "outcome should report a generation >= 1");
            });

            assert_eq!(count.load(Ordering::Relaxed), 1);
            assert_eq!(*manager.installed(), *req);
        });
    }

    #[test]
    fn build_failure_propagates_and_does_not_advance_installed() {
        let _eal = &*EAL;
        let count = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let backend = ToyBackend {
                build_count: Arc::clone(&count),
                build_delay: Duration::ZERO,
                fail_on: Some(0), // first build fails
            };
            let (manager, _factory) = spawn_manager(scope, backend);

            let mut ir = PipelineIR::new();
            ir.acl.insert(rule(1, AclAction::Accept));

            run(async {
                use rekon::{Observe, Reconcile};
                let obs = manager.observe().await;
                let outcome = manager.reconcile(Arc::new(ir), obs).await;
                assert!(outcome.is_err(), "induced failure should propagate");
            });

            // Installed IR is still empty.
            assert_eq!(*manager.installed(), PipelineIR::default());
        });
    }

    #[test]
    fn greedy_coalescing_drops_intermediate_submissions() {
        let _eal = &*EAL;
        let count = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let backend = ToyBackend {
                build_count: Arc::clone(&count),
                build_delay: Duration::from_millis(50),
                fail_on: None,
            };
            let (manager, _factory) = spawn_manager(scope, backend);

            let mut ir1 = PipelineIR::new();
            ir1.acl.insert(rule(1, AclAction::Accept));
            let mut ir2 = PipelineIR::new();
            ir2.acl.insert(rule(2, AclAction::Accept));
            let mut ir3 = PipelineIR::new();
            ir3.acl.insert(rule(3, AclAction::Accept));

            run(async {
                use rekon::{Observe, Reconcile};
                let obs = manager.observe().await;
                let h1 = manager.reconcile(Arc::new(ir1.clone()), Arc::clone(&obs));
                let h2 = manager.reconcile(Arc::new(ir2.clone()), Arc::clone(&obs));
                let h3 = manager.reconcile(Arc::new(ir3.clone()), Arc::clone(&obs));
                let _ = tokio::join!(h1, h2, h3);
            });

            // First build runs immediately; intermediates coalesce; the
            // last surviving submission also builds.  Expect <= 2 builds.
            let n = count.load(Ordering::Relaxed);
            assert!(n <= 2, "expected <= 2 builds (greedy coalescing), got {n}",);
            // Final installed should match ir3 (or whichever survived
            // coalescing -- but the LATEST submission always wins).
            assert_eq!(*manager.installed(), ir3);
        });
    }

    #[test]
    fn manager_drop_signals_worker_to_exit() {
        // If Drop didn't signal Shutdown, the std::thread::scope at
        // the end of this test would block forever (the worker would
        // sit in take_blocking).  This test passes by completing.
        let _eal = &*EAL;
        let count = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let backend = ToyBackend {
                build_count: Arc::clone(&count),
                build_delay: Duration::ZERO,
                fail_on: None,
            };
            let (manager, _factory) = spawn_manager(scope, backend);
            // Drop manager immediately; scope joins worker on its way out.
            drop(manager);
        });
    }

    #[test]
    fn snapshot_through_reader_reflects_published_pipeline() {
        let _eal = &*EAL;
        let count = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let backend = ToyBackend {
                build_count: Arc::clone(&count),
                build_delay: Duration::ZERO,
                fail_on: None,
            };
            let (manager, factory) = spawn_manager(scope, backend);
            let mut reader = factory.reader();

            // Pre-publish: snapshot lookup misses (Empty sentinel).
            assert!(reader.snapshot().lookup(&1).is_none());

            let mut ir = PipelineIR::new();
            ir.acl.insert(rule(1, AclAction::Accept));

            run(async {
                use rekon::{Observe, Reconcile};
                let obs = manager.observe().await;
                manager.reconcile(Arc::new(ir), obs).await.expect("ok");
            });

            // Post-publish: snapshot lookup hits.
            let snap = reader.snapshot();
            let hit = snap.lookup(&1).expect("rule should be installed");
            assert_eq!(hit.action, AclAction::Accept);
        });
    }
}
