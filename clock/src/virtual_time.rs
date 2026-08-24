// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Driving the clock from a test.
//!
//! Compiled only under the `virtual` feature, which every crate that reads the clock turns on
//! through a dev-dependency, so this module exists in test builds and nowhere else.
//!
//! # There is exactly one clock
//!
//! tokio's pausable clock is **per runtime**, and reading it goes through the *calling thread's*
//! runtime context. Two consequences, both measured rather than assumed:
//!
//! * Two paused runtimes are two timelines. Advance one by ten minutes and the other is ten
//!   minutes behind, forever.
//! * A thread with no runtime context falls back to the wall clock **silently**. After an hour's
//!   advance, an entered thread and an unentered one disagree by an hour, and the unentered one is
//!   the one that looks normal.
//!
//! So the design is not "keep several clocks in step" -- that cannot be done, because
//! [`tokio::time::advance`] must run inside the runtime whose clock it moves, and N advances are
//! never simultaneous, so a broadcast *creates* the backwards read it is meant to prevent. The
//! design is that there is one [`Paused`] at a time, [`Paused::new`] refuses a second, and every
//! thread that reads a clock is inside it.
//!
//! # The guard
//!
//! "Every thread is inside it" is an invariant, so it is checked rather than documented, the same
//! way `.semgrep/rules/no-std-time-direct.yaml` checks that nobody reads `std`'s clock directly.
//! While a [`Paused`] is alive, [`crate::now`] panics on a thread with no runtime context instead
//! of quietly answering from the wrong timeline.
//!
//! The check is armed by a live [`Paused`] and disarmed when it drops, rather than latched for the
//! life of the process. That matters: tokio's own `DID_PAUSE_CLOCK` latches forever, and a latched
//! check would panic on every innocent reader in any test binary that shares a process -- which
//! `cargo test` and edition-2024's merged doctests both do.
//!
//! # Which threads the check applies to
//!
//! Only the ones actually in the test's world, which is a *tree*: the thread holding the [`Paused`],
//! and every thread spawned from it, transitively. `std::thread::add_spawn_hook` is what makes that
//! knowable -- it runs a closure on the parent at spawn time and another on the child before its
//! body, so both the runtime context and the "in a driven-clock world" flag are inherited rather
//! than reconstructed.
//!
//! That inheritance is the design, not an optimisation. A process-wide check is unsound under any
//! runner that shares a process: it refused unrelated tests for something they did not do, and
//! failed the whole packet-processor suite ten times out of ten because one property paused while
//! another built a fabric on its main thread. Scoped to the tree, an unrelated test is simply not in
//! it -- measured, a thread spawned from outside inherits nothing.
//!
//! The hook also *enters* the runtime on the child, so a worker that would have forgotten to is
//! simply correct instead. What is left for the panic to catch is the case inheritance cannot
//! reach: a thread created outside `std::thread` -- by DPDK's EAL, or any C library calling
//! `pthread_create` -- which is exactly where a silent wall-clock reading would be least expected.
//!
//! Without `has_spawn_hook` (a build with no `RUSTC_BOOTSTRAP`, which the dev shell and the nix
//! build both set) nothing is inherited, so only the thread holding the `Paused` is checked. Weaker,
//! never wrong.
//!
//! # Wall-clock mode
//!
//! Built with `--cfg wall_clock`, everything here still compiles and [`advance`] really sleeps.
//! A property written against this module is therefore the test under both clocks: virtual, where
//! an hour costs nothing, and wall, where the same property is what would catch the virtual clock
//! lying. Only durations of a second or two are practical in wall mode, so it is opt-in per run.

use crate::Duration;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

/// How many [`Paused`] sections are alive. Zero almost always.
///
/// A count rather than a flag, because independent tests running in one process legitimately hold
/// one each -- see [`Paused`] on why a second is not refused.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// Yields after an advance, so that timers which are now due actually run.
///
/// [`tokio::time::advance`] makes the new time *visible*; it does not poll the tasks waiting on it.
/// A property that looked immediately afterwards would see state that is past its deadline and has
/// not yet been told so. Four is empirical -- one is not enough for a timer that reschedules -- and
/// costs nothing when there is nothing to run.
const YIELDS: usize = 4;

thread_local! {
    /// Whether this thread is inside a [`Paused`]'s world.
    ///
    /// Set on the thread that builds one, and inherited by every thread it spawns. A read on a
    /// thread where this is false is nobody's business but that thread's.
    static IN_WORLD: Cell<bool> = const { Cell::new(false) };
}

/// Whether [`crate::now`] should refuse a read with no runtime context.
///
/// Both halves matter. The global says a clock is being driven *somewhere*, so the common case --
/// no clock driven at all -- costs one atomic load and never touches the thread-local. The
/// thread-local says this thread is part of it, which is what keeps an unrelated test out.
#[cfg(not(wall_clock))]
#[inline]
#[must_use]
pub(crate) fn armed() -> bool {
    LIVE.load(Ordering::Acquire) != 0 && IN_WORLD.with(Cell::get)
}

thread_local! {
    /// Whether this thread has already registered the spawn hook.
    ///
    /// Per thread, not per process, because that is how `add_spawn_hook` works: `SPAWN_HOOKS` is a
    /// thread-local list which children inherit, and "adding a hook has no effect on already running
    /// threads". A `Once` looked right and was not -- the first test to build a `Paused` consumed
    /// it, and every later test's threads then inherited nothing. That failed as a spawned thread
    /// reading the wall clock while the thread that spawned it was an hour ahead.
    ///
    /// Hooks can be added but never removed, so this also stops a thread that builds several
    /// `Paused`s from stacking one hook per clock.
    #[cfg(all(has_spawn_hook, not(wall_clock)))]
    static HOOKED: Cell<bool> = const { Cell::new(false) };
}

/// Make every thread spawned from here on inherit this thread's clock.
///
/// That the hook list is itself thread-local is what scopes this: only threads descending from one
/// that drives a clock carry it, so an unrelated test in the same process is untouched without
/// anything having to know about it.
#[cfg(all(has_spawn_hook, not(wall_clock)))]
fn inherit_across_spawns() {
    if !HOOKED.replace(true) {
        std::thread::add_spawn_hook(|_parent| {
            // On the parent, at spawn time.
            let handle = tokio::runtime::Handle::try_current().ok();
            let in_world = IN_WORLD.with(Cell::get);
            move || {
                // On the child, before its body.
                IN_WORLD.with(|flag| flag.set(in_world));
                if let Some(handle) = handle {
                    // Both deliberate. `EnterGuard` restores the previous context when it drops and
                    // the context should last the thread rather than this closure, so it is
                    // forgotten; and the guard borrows the handle, so the handle is leaked to give
                    // it somewhere to borrow from.
                    //
                    // One `Handle` -- an `Arc` clone -- per spawned thread, which is small beside
                    // the thread. Caching one for the process was tried and is wrong: each `Paused`
                    // builds its own runtime, so a cached handle sends every later test's threads to
                    // the *first* test's clock. That failed as a spawned thread reading 3599.99s
                    // away from the one that advanced it.
                    std::mem::forget(Box::leak(Box::new(handle)).enter());
                }
            }
        });
    }
}

/// Without the hook nothing is inherited, so only the thread holding the [`Paused`] is checked.
#[cfg(not(all(has_spawn_hook, not(wall_clock))))]
fn inherit_across_spawns() {}

/// Refuse a clock read that would come from the wrong timeline.
///
/// Out of line and cold because the arming check is on every clock read in a test build, and this
/// arm never returns.
///
/// Reaching this means a thread is in a driven-clock world and cannot see the clock -- which, with
/// inheritance in place, means it was not created by `std::thread`. There is no runner to blame and
/// nothing to soften: the read would answer from a different timeline.
#[cfg(not(wall_clock))]
#[cold]
#[inline(never)]
pub(crate) fn refuse() -> ! {
    panic!(
        "clock::now() on a thread with no tokio runtime while the virtual clock is paused.\n\
         \n\
         This read would have answered from the wall clock, which is a different timeline from the \
         paused one -- they disagree by however far the test has advanced -- so comparing it \
         against a deadline taken on the other side is silently wrong, in either direction.\n\
         \n\
         A thread spawned with `std::thread` inherits its parent's clock automatically, so reaching \
         this means this one did not come from there -- DPDK's EAL, or a C library calling \
         `pthread_create`. Enter `clock::virtual_time::Paused::handle()` on the thread itself; a \
         guard held by whoever created it does nothing, because tokio's context is thread-local."
    );
}

/// A runtime whose clock a test drives.
///
/// Holding this is what makes the clock controllable, and dropping it gives the process back its
/// ordinary clock. Every thread that reads a clock while it is alive must be inside it -- see the
/// module documentation for why that is checked rather than trusted.
///
/// The runtime is current-thread, which is not a preference: `Builder::get_cfg` sets
/// `enable_pause_time` false for the multi-threaded flavour, so tokio refuses to pause one at all.
///
/// # One per *property*, not one per process
///
/// A second `Paused` is not refused, and an earlier draft of this type refused it. That was the
/// wrong granularity. Two clocks are only harmful when state crosses between them, and independent
/// tests in one process share no state -- ten expiry properties running in parallel under `cargo
/// test` each want their own, and refusing that broke a whole crate's suite while catching nothing.
///
/// What must not happen is one *property* building two, so that its own threads read different
/// timelines. That is a claim about a single test, which a process-wide count cannot express;
/// [`Paused::handle`] is the instrument -- thread the handle through, rather than starting another.
#[derive(Debug)]
pub struct Paused {
    runtime: tokio::runtime::Runtime,
}

impl Paused {
    /// Build it, and arm the check.
    ///
    /// # Panics
    ///
    /// If a current-thread runtime with timers cannot be built, which does not happen in practice.
    #[must_use]
    pub fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            // Under `wall_clock` the runtime is ordinary: `advance` sleeps, `now` reads the real
            // clock, and there is nothing to be inside of.
            .start_paused(!cfg!(wall_clock))
            .build()
            .unwrap_or_else(|e| panic!("a current-thread runtime with timers does not build: {e}"));

        // After the build, so a runtime that failed to build cannot leave the check armed.
        if !cfg!(wall_clock) {
            inherit_across_spawns();
            IN_WORLD.with(|flag| flag.set(true));
            LIVE.fetch_add(1, Ordering::AcqRel);
        }

        Self { runtime }
    }

    /// Run a future on it.
    ///
    /// `block_on` rather than `Handle::enter` for the driving thread: [`advance`] is async, and the
    /// timer tasks the code under test spawns have to be *driven* before they can observe a new
    /// time. Entering alone gives a context but nothing to poll them.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    /// A handle for the threads that are not driving.
    ///
    /// Enter it **on the thread that will read the clock**. tokio's context is thread-local, so a
    /// guard the spawning thread holds does nothing for the spawned one, and a worker that skips
    /// this trips the panic in [`crate::now`] rather than reading the wrong timeline.
    #[must_use]
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }
}

impl Default for Paused {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Paused {
    fn drop(&mut self) {
        if !cfg!(wall_clock) {
            IN_WORLD.with(|flag| flag.set(false));
            LIVE.fetch_sub(1, Ordering::Release);
        }
    }
}

/// Move the clock forward, and let every timer that is now due run.
///
/// Under the virtual clock this costs nothing and can be an hour. Under `--cfg wall_clock` it is a
/// real sleep of the same length, which is what makes a property written against it a test of the
/// virtual clock itself rather than only of the code beneath it.
///
/// Call it from the thread driving [`Paused::block_on`], not from a worker: it is async, and it is
/// only meaningful when the workers are quiesced. A clock that moves while a packet is halfway
/// through the pipeline is measuring the scheduler, not the code.
///
/// # Panics
///
/// If called outside the paused runtime, which tokio reports as "time cannot be frozen from outside
/// the Tokio runtime".
pub async fn advance(by: Duration) {
    #[cfg(not(wall_clock))]
    {
        tokio::time::advance(by).await;
        for _ in 0..YIELDS {
            tokio::task::yield_now().await;
        }
    }
    #[cfg(wall_clock)]
    {
        let _ = YIELDS;
        tokio::time::sleep(by).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{Paused, advance};
    use crate::serially;
    use crate::{Duration, now};
    use std::thread;

    /// How far these tests move the clock.
    ///
    /// An hour under the virtual clock, where it costs nothing and is safely past anything in the
    /// workspace. Under `--cfg wall_clock` the same call is a real sleep, so it drops to something a
    /// test run can afford -- what wall mode checks is that the mechanism waits *at all*, not that it
    /// can wait an hour.
    ///
    /// Every test that drives the clock wants this pair rather than a literal. A literal hour is
    /// correct under one clock and a hung test suite under the other.
    const LONG: Duration = if cfg!(wall_clock) {
        Duration::from_millis(50)
    } else {
        Duration::from_hours(1)
    };

    /// A deadline the [`LONG`] advance is certain to pass.
    const NEARLY_LONG: Duration = if cfg!(wall_clock) {
        Duration::from_millis(20)
    } else {
        Duration::from_mins(2)
    };

    /// An hour costs nothing, and the clock reports it.
    #[test]
    fn the_clock_moves_when_a_test_says_so() {
        let _serial = serially();
        let clock = Paused::new();
        clock.block_on(async {
            let before = now();
            advance(LONG).await;
            assert!(
                now().duration_since(before) >= LONG,
                "the clock was advanced by {LONG:?} and did not follow"
            );
        });
    }

    /// A timer waiting on the clock actually fires, rather than only the reads moving.
    ///
    /// This is the asymmetry the crate exists to fix, stated as a test: deadlines and waits have to
    /// be on the same clock or a paused test buys exactly one time step.
    #[test]
    fn a_timer_fires_when_the_clock_passes_it() {
        let _serial = serially();
        let clock = Paused::new();
        clock.block_on(async {
            let deadline = now() + NEARLY_LONG;
            let waiting = tokio::spawn(async move {
                while now() < deadline {
                    tokio::task::yield_now().await;
                }
            });
            advance(LONG).await;
            waiting.await.expect("the waiter panicked");
        });
    }

    /// Two clocks would be two timelines, so the second is refused where it is asked for.
    /// A thread spawned inside the world reads the driven clock, with nobody telling it to.
    ///
    /// No `handle.enter()` anywhere: the spawn hook carried the context across. This is what makes
    /// the forgetful worker unrepresentable rather than merely detected -- there is nothing left to
    /// forget.
    #[test]
    #[cfg(all(has_spawn_hook, not(wall_clock)))]
    fn a_spawned_thread_inherits_the_clock_without_being_told() {
        let _serial = serially();
        let clock = Paused::new();
        let (driver, worker) = clock.block_on(async {
            advance(LONG).await;
            // Spawned from inside `block_on`, so the parent has a runtime context to pass on.
            let worker = thread::spawn(now)
                .join()
                .expect("an inherited read was refused");
            (now(), worker)
        });
        assert_eq!(
            driver,
            worker,
            "a spawned thread read {:?} away from the thread that advanced the clock",
            driver.saturating_duration_since(worker)
        );
    }

    /// A thread in the world with no clock to read is refused, not answered wrongly.
    ///
    /// Reached on the thread holding the `Paused` itself, outside its `block_on`: it is in the world
    /// -- it built the thing -- and has no runtime context, so it cannot see the clock it is driving.
    /// A reading taken there and compared against a deadline taken inside would be off by however
    /// far the test had advanced, which is the whole failure. It is also the shape of the case
    /// inheritance cannot reach: a thread created outside `std::thread`, by DPDK's EAL or a C
    /// library.
    ///
    /// Not gated on `has_spawn_hook`, deliberately -- this is the half of the check that survives a
    /// build with no inheritance, and it should be seen to.
    #[test]
    #[cfg(not(wall_clock))]
    fn a_thread_in_the_world_with_no_clock_is_refused() {
        let _serial = serially();
        let clock = Paused::new();
        clock.block_on(async { advance(LONG).await });

        let refused = std::panic::catch_unwind(now);
        let panic = refused.expect_err("a read from the wrong timeline was allowed");
        // The refusal is a literal, so it arrives as `&'static str` rather than `String`.
        let message = panic
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("");
        assert!(
            message.contains("no tokio runtime"),
            "the refusal did not explain itself: {message}"
        );
    }

    /// A thread that is not in the tree is left entirely alone.
    ///
    /// The property the process-wide check could not have: this thread never built a `Paused`, so a
    /// clock being driven on another thread is none of its business. Without this, an unrelated test
    /// sharing the process is refused for something it did not do -- which failed the whole
    /// packet-processor suite ten times out of ten.
    #[test]
    #[cfg(not(wall_clock))]
    fn a_thread_outside_the_tree_is_left_alone() {
        let _serial = serially();
        let (started, wait_for_start) = std::sync::mpsc::channel();
        let (finish, wait_to_finish) = std::sync::mpsc::channel();

        // The world lives on its own thread, so this one is never in it.
        let driving = thread::spawn(move || {
            let clock = Paused::new();
            clock.block_on(async { advance(LONG).await });
            started.send(()).expect("the test is waiting");
            // Hold the clock paused across the outsider's read, which is the whole question.
            wait_to_finish.recv().expect("the test releases this");
        });
        wait_for_start.recv().expect("the driver starts");

        let outsider = thread::spawn(now).join();
        finish.send(()).expect("the driver is waiting");
        driving.join().expect("the driver panicked");
        outsider.expect("a thread outside the world was refused a clock read");
    }

    /// A worker that did enter reads the same clock as the thread that drove it.
    #[test]
    fn a_thread_that_entered_reads_the_same_clock() {
        let _serial = serially();
        let clock = Paused::new();
        let driver = clock.block_on(async {
            advance(LONG).await;
            now()
        });

        let handle = clock.handle();
        let worker = thread::spawn(move || {
            let _guard = handle.enter();
            now()
        })
        .join()
        .expect("an entered read was refused");

        assert!(
            worker >= driver,
            "an entered worker read {:?} behind the thread that advanced the clock",
            driver.saturating_duration_since(worker)
        );
    }

    /// Dropping the clock gives the process back its ordinary one.
    ///
    /// The check has to be scoped rather than latched: tokio's own `DID_PAUSE_CLOCK` latches for the
    /// life of the process, and a latched check would panic on every innocent reader in any binary
    /// that shares a process -- which `cargo test` and merged doctests both do.
    #[test]
    fn dropping_the_clock_disarms_the_check() {
        let _serial = serially();
        {
            let clock = Paused::new();
            clock.block_on(async { advance(LONG).await });
        }
        thread::spawn(now)
            .join()
            .expect("an ordinary read was refused after the clock was dropped");
    }
}
