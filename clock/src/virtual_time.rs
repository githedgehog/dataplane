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
//! One residual false positive is accepted: under plain `cargo test`, an unrelated test running in
//! parallel *in the same process* can read the clock while this one holds it paused. `cargo
//! nextest` -- what CI, `just miri` and the development guide all use -- gives each test its own
//! process and has no such window. The panic message says so.
//!
//! # Wall-clock mode
//!
//! Built with `--cfg wall_clock`, everything here still compiles and [`advance`] really sleeps.
//! A property written against this module is therefore the test under both clocks: virtual, where
//! an hour costs nothing, and wall, where the same property is what would catch the virtual clock
//! lying. Only durations of a second or two are practical in wall mode, so it is opt-in per run.

use crate::Duration;
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

/// Whether [`crate::now`] should refuse a read with no runtime context.
#[cfg(not(wall_clock))]
#[inline]
#[must_use]
pub(crate) fn armed() -> bool {
    LIVE.load(Ordering::Acquire) != 0
}

/// Refuse a clock read that would come from the wrong timeline.
///
/// Out of line and cold because the arming check is on every clock read in a test build, and this
/// arm never returns.
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
         Two things cause it:\n\
         \n\
         * A thread this test spawned never entered the runtime. Hand it \
         `clock::virtual_time::Paused::handle()` and enter that, on the spawned thread rather than \
         on the spawning one -- tokio's context is thread-local, so a guard held by the parent does \
         nothing for the child.\n\
         \n\
         * Or another test in this process holds the clock paused and this thread has nothing to do \
         with it. `cargo nextest` gives each test its own process and cannot hit this; plain `cargo \
         test` shares one, so run it under nextest or with `--test-threads=1`."
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
    /// A worker that never entered the runtime is refused rather than answered wrongly.
    ///
    /// The measured alternative is an hour of silent disagreement: an unentered thread falls back
    /// to the wall clock, which looks entirely normal and is a different timeline.
    /// Wall mode reads the real clock from every thread, entered or not, so there is no wrong timeline
    /// to be answered from and nothing to refuse.
    #[cfg(not(wall_clock))]
    #[test]
    fn a_thread_that_did_not_enter_is_refused() {
        let _serial = serially();
        let clock = Paused::new();
        clock.block_on(async { advance(LONG).await });

        let forgetful = thread::spawn(now).join();
        let panic =
            forgetful.expect_err("an unentered read was allowed while the clock was paused");
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
