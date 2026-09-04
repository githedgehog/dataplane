// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Model-checked coverage for `concurrency::reclaim`.
//!
//! The wall-clock parts of the protocol (`drain_until`) are excluded on purpose: they poll
//! `Instant::now()`, which no model checker models, and a spin-until-deadline loop has no
//! meaningful interleaving semantics under loom. What *is* checked here is the part that carries
//! the guarantee -- that a retired resource is never released while a worker could still be using
//! it, under every interleaving of retire/reclaim against a worker's safe points.
//!
//! ## What does *not* belong here
//!
//! Only genuinely concurrent properties. The shuttle portfolio includes the PCT scheduler, which
//! panics with "test closure did not exercise any concurrency" on a single-threaded body -- so a
//! sequential property added here fails the shuttle matrix rather than passing it trivially.
//! Sequential coverage (release happens exactly once, retirement with no attendants releases at
//! once) lives in `reclaim_protocol.rs` instead. `arc_weak.rs` opts out of shuttle at file level
//! for the same reason.
//!
//! ## Sizing
//!
//! Loom explores every legal interleaving inside each invocation, so these bodies are kept to one
//! worker and one resource. See the sizing note in `quiescent_model.rs`: two threads with one
//! operation each is about the right shape, and more explodes.

// `#[concurrency::test]` expands to `::concurrency::stress(...)`; cargo rejects a self-dep, so
// alias the crate by hand.
extern crate dataplane_concurrency as concurrency;

use concurrency::reclaim::Reclaimer;
use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use concurrency::thread;

/// Counts its own release.
struct Marker(Arc<AtomicUsize>);

impl Drop for Marker {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// A resource retired while a worker is attending is never released before that worker passes a
/// safe point -- under every interleaving of the worker's snapshot against the owner's
/// retire/reclaim.
#[concurrency::test]
fn a_retired_resource_is_never_released_under_a_live_attendant() {
    let drops = Arc::new(AtomicUsize::new(0));
    let reclaimer: Reclaimer<Arc<Marker>> = Reclaimer::new();
    reclaimer.register(Arc::new(Marker(Arc::clone(&drops))));

    let attendants = reclaimer.attendants();
    thread::scope(|scope| {
        scope.spawn(move || {
            let mut attendant = attendants.attend();
            attendant.at_safe_point();
        });

        // The worker may or may not have attended yet, and may or may not have snapshotted. In
        // every case, releasing the resource requires it to have passed a safe point *after* the
        // retirement, which this reclaim cannot know has happened.
        reclaimer.retire_unless(|_| false);
        reclaimer.reclaim();
    });

    // Once the worker is gone its attendant is gone, so this reclaim is unconstrained.
    reclaimer.reclaim();
    assert_eq!(
        drops.load(Ordering::Relaxed),
        1,
        "released exactly once, after the worker was no longer able to reach it"
    );
}
