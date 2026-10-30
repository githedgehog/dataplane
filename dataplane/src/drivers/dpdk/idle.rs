// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Idle behavior shared by data and control workers.
//!
//! [`IdleMode::Poll`] spins and periodically yields. [`IdleMode::Monitor`] begins low-power waits
//! after [`IdleConfig::polls`] consecutive empty polls. Each wait ends on a watched queue write
//! or after [`IdleConfig::sleep_us`] microseconds; traffic resets the empty-poll streak.
//! Workers without receive queues use timed kernel sleeps, independent of CPU wait support.

use std::time::{Duration, Instant};

use args::{IdleConfig, IdleMode};
use dpdk::lcore::LCore;
use dpdk::power::{Sleeper, Slept};
use dpdk::queue::rx::RxQueue;
use tracing::{info, warn};

use crate::drivers::status::WorkerId;

/// Yield after this many consecutive polls without traffic, while spinning.
const POLLS_BEFORE_YIELD: u32 = 128;

/// Elapsed-time threshold for shutdown checks, watchdog updates, and counter reporting.
/// Poll-count thresholds alone delay this work while the worker sleeps.
const CHECK_WHILE_ASLEEP: Duration = Duration::from_millis(10);

/// What to do after a poll that found nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    /// Poll again at once.
    Spin,
    /// Give the CPU to anything else that wants it, then poll again.
    Yield,
    /// Sleep until a packet or the deadline, then poll again.
    Sleep,
}

/// The count of empty polls, and what it calls for.
#[derive(Debug, Clone, Copy)]
struct Streak {
    /// Consecutive empty polls. Wrap instead of saturating to preserve periodic yields.
    empty: u32,
    sleep_after: Option<u32>,
    /// Whether `sleep_after` has been reached. Separate from the count to preserve sleep on wrap.
    asleep: bool,
}

impl Streak {
    fn new(sleep_after: Option<u32>) -> Self {
        Self {
            empty: 0,
            sleep_after,
            asleep: false,
        }
    }

    fn busy(&mut self) {
        self.empty = 0;
        self.asleep = false;
    }

    fn empty(&mut self) -> Next {
        self.empty = self.empty.wrapping_add(1);
        if !self.asleep {
            self.asleep = self.sleep_after.is_some_and(|after| self.empty >= after);
        }
        if self.asleep {
            Next::Sleep
        } else if self.empty.is_multiple_of(POLLS_BEFORE_YIELD) {
            Next::Yield
        } else {
            Next::Spin
        }
    }

    /// Permanently disable monitor sleeps while preserving the empty-poll count.
    fn stop_sleeping(&mut self) {
        self.sleep_after = None;
        self.asleep = false;
    }

    /// Empty polls in a row so far, wrapping.
    fn count(&self) -> u32 {
        self.empty
    }
}

/// A worker's idling, across all of its receive queues.
pub(crate) struct Idle {
    worker: WorkerId,
    streak: Streak,
    sleeper: Option<Sleeper>,
    longest: Duration,
    /// The queue that last had traffic: the one to watch if only one can be.
    last_busy: usize,
    sleeps: u64,
    /// When the worker last did its periodic checks.
    checked: Instant,
    /// Whether elapsed time requires periodic checks before the next poll-count threshold.
    due: bool,
}

impl Idle {
    /// Configure idle behavior using the available CPU capabilities.
    /// `lcore` is required for power-optimized waits, but not for timed kernel sleeps.
    pub(crate) fn new(worker: WorkerId, config: IdleConfig, lcore: Option<&LCore>) -> Self {
        let sleeper = match (config.mode, lcore) {
            (IdleMode::Poll, _) => None,
            (IdleMode::Monitor, None) => {
                warn!(
                    worker,
                    "idle mode is {}, but this worker is not an lcore, so it has no \
                     power-optimized wait",
                    config.mode
                );
                None
            }
            (IdleMode::Monitor, Some(lcore)) => {
                let sleeper = Sleeper::new(lcore);
                if let Some(sleeper) = &sleeper {
                    info!(
                        worker,
                        "idle mode is {}: sleeping after {} empty polls, for at most {} us, \
                         with {:?}",
                        config.mode,
                        config.polls,
                        config.sleep_us,
                        sleeper.intrinsics()
                    );
                } else {
                    warn!(
                        worker,
                        "idle mode is {}, but this CPU has no power-optimized wait; it will poll",
                        config.mode
                    );
                }
                sleeper
            }
        };
        Self {
            worker,
            // Even without a power-optimized wait: a worker with no queues sleeps all the same.
            streak: Streak::new((config.mode != IdleMode::Poll).then_some(config.polls)),
            sleeper,
            longest: Duration::from_micros(u64::from(config.sleep_us)),
            last_busy: 0,
            sleeps: 0,
            checked: clock::now(),
            due: false,
        }
    }

    /// Whether elapsed time makes periodic checks due before the next poll-count threshold.
    pub(crate) fn checks_due(&self) -> bool {
        self.due
    }

    /// The worker did its periodic checks.
    pub(crate) fn checked(&mut self) {
        self.checked = clock::now();
        self.due = false;
    }

    /// A poll found traffic on queue `slot`.
    pub(crate) fn busy(&mut self, slot: usize) {
        self.last_busy = slot;
        self.working();
    }

    /// Reset idling for non-packet work, such as an expiry backlog.
    pub(crate) fn working(&mut self) {
        self.streak.busy();
    }

    /// A poll found nothing on any of `queues`, the worker's receive queues in slot order.
    pub(crate) fn empty<'q, 'd: 'q>(
        &mut self,
        lcore: Option<&LCore>,
        queues: impl Iterator<Item = &'q RxQueue<'d>> + Clone,
    ) {
        match self.streak.empty() {
            Next::Spin => {}
            Next::Yield => std::thread::yield_now(),
            Next::Sleep => self.sleep(lcore, queues),
        }
    }

    /// Empty polls in a row so far, wrapping; zero after a busy one.
    pub(crate) fn empty_polls(&self) -> u32 {
        self.streak.count()
    }

    /// How many times this worker has slept in a low-power state.
    pub(crate) fn sleeps(&self) -> u64 {
        self.sleeps
    }

    fn sleep<'q, 'd: 'q>(
        &mut self,
        lcore: Option<&LCore>,
        queues: impl Iterator<Item = &'q RxQueue<'d>> + Clone,
    ) {
        // With no receive queues, a timed kernel sleep needs no CPU monitor instruction.
        if queues.clone().next().is_none() {
            std::thread::sleep(self.longest);
            self.slept();
            return;
        }
        let (Some(sleeper), Some(lcore)) = (&self.sleeper, lcore) else {
            // No power-optimized wait: spin and yield.
            self.streak.stop_sleeping();
            return;
        };
        // The queue that last had traffic first: it is the one watched if only one can be.
        let first = self.last_busy;
        let ordered = queues.clone().skip(first).chain(queues.take(first));
        match sleeper.sleep(lcore, ordered, self.longest) {
            Ok(Slept::Watched(_) | Slept::Paused) => self.slept(),
            // No usable monitor condition or pause instruction; disable further monitor attempts.
            Ok(Slept::Not) => {
                info!(
                    worker = self.worker,
                    "this worker's queues offer nothing to watch and the CPU no pause; it will poll"
                );
                self.sleeper = None;
                self.streak.stop_sleeping();
            }
            Err(e) => {
                warn!(
                    worker = self.worker,
                    "an idle sleep failed ({e}); this worker will poll from now on"
                );
                self.sleeper = None;
                self.streak.stop_sleeping();
            }
        }
    }

    /// Count a sleep, and note whether it ran long enough for the periodic checks to come due.
    fn slept(&mut self) {
        self.sleeps += 1;
        self.due = clock::elapsed(self.checked) >= CHECK_WHILE_ASLEEP;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use args::{IdleConfig, IdleMode};
    use dpdk::queue::rx::RxQueue;

    use super::{Idle, Next, POLLS_BEFORE_YIELD, Streak};

    #[derive(Clone, Copy, Debug, bolero::TypeGenerator)]
    enum Operation {
        Empty,
        Busy,
        DisableSleep,
    }

    /// Compare arbitrary poll/reset/disable sequences with an unbounded count of empty polls.
    /// Seed reachable states near wrapping as well as startup; reaching wrap by iteration would
    /// require billions of steps and leave that invariant effectively untested.
    #[test]
    fn streak_matches_empty_poll_history() {
        bolero::check!()
            .with_type::<(Option<u32>, u32, Vec<Operation>)>()
            .for_each(|(threshold, prefix, operations)| {
                for threshold in [None, Some(0), Some(1), Some(u32::MAX), *threshold] {
                    for prefix in [0, u32::MAX - 1, *prefix] {
                        let mut elapsed = u64::from(prefix);
                        let mut enabled = threshold.is_some();
                        let after = u64::from(threshold.unwrap_or(0).max(1));
                        let mut streak = Streak {
                            empty: prefix,
                            sleep_after: threshold,
                            asleep: enabled && elapsed >= after,
                        };
                        for operation in operations.iter().take(128) {
                            match operation {
                                Operation::Empty => {
                                    elapsed += 1;
                                    let count = u32::try_from(elapsed % (1_u64 << 32)).unwrap();
                                    let expected = if enabled && elapsed >= after {
                                        Next::Sleep
                                    } else if count.is_multiple_of(POLLS_BEFORE_YIELD) {
                                        Next::Yield
                                    } else {
                                        Next::Spin
                                    };
                                    assert_eq!(streak.empty(), expected);
                                }
                                Operation::Busy => {
                                    elapsed = 0;
                                    streak.busy();
                                }
                                Operation::DisableSleep => {
                                    enabled = false;
                                    streak.stop_sleeping();
                                }
                            }
                            assert_eq!(u64::from(streak.count()), elapsed % (1_u64 << 32));
                            assert_eq!(streak.asleep, enabled && elapsed >= after);
                        }
                    }
                }
            });
    }

    /// `polls` empty polls by a worker with no queues; how many it slept, and for how long.
    fn idle_without_queues(mode: IdleMode, polls: u32) -> (u64, Duration) {
        let config = IdleConfig {
            mode,
            polls: 4,
            sleep_us: 1000,
        };
        // No lcore, so no power-optimized wait either.
        let mut idle = Idle::new(0, config, None);
        let start = clock::now();
        for _ in 0..polls {
            idle.empty(None, std::iter::empty::<&RxQueue<'_>>());
        }
        (idle.sleeps(), clock::elapsed(start))
    }

    /// A control worker without receive queues can sleep without CPU monitor support.
    #[test]
    fn a_worker_without_queues_sleeps_with_no_help_from_the_cpu() {
        let (sleeps, took) = idle_without_queues(IdleMode::Monitor, 8);
        assert_eq!(
            sleeps, 5,
            "the 4th empty poll and every one after it sleeps"
        );
        assert!(took >= Duration::from_millis(5), "slept {took:?} in all");
    }

    #[test]
    fn a_polling_worker_without_queues_does_not_sleep() {
        assert_eq!(idle_without_queues(IdleMode::Poll, 8).0, 0);
    }

    #[test]
    fn polling_yields_now_and_then_and_never_sleeps() {
        let mut streak = Streak::new(None);
        let nexts: Vec<Next> = (0..POLLS_BEFORE_YIELD * 3)
            .map(|_| streak.empty())
            .collect();
        assert!(!nexts.contains(&Next::Sleep));
        let yields = nexts.iter().filter(|&&n| n == Next::Yield).count();
        assert_eq!(yields, 3);
    }

    #[test]
    fn monitoring_sleeps_on_every_empty_poll_from_the_threshold_until_traffic() {
        let mut streak = Streak::new(Some(4));
        let nexts: Vec<Next> = (0..6).map(|_| streak.empty()).collect();
        assert_eq!(
            nexts,
            [
                Next::Spin,
                Next::Spin,
                Next::Spin,
                Next::Sleep,
                Next::Sleep,
                Next::Sleep
            ]
        );
        streak.busy();
        assert_eq!(streak.empty(), Next::Spin);
    }

    #[test]
    fn a_long_idle_spell_neither_overflows_nor_wakes_up() {
        let mut streak = Streak::new(Some(4));
        for _ in 0..4 {
            streak.empty();
        }
        streak.empty = u32::MAX - 1;
        let nexts: Vec<Next> = (0..8).map(|_| streak.empty()).collect();
        assert!(nexts.iter().all(|&n| n == Next::Sleep), "{nexts:?}");
    }

    /// A worker that finds it cannot sleep after all goes back to spinning and yielding, without
    /// starting its count again.
    #[test]
    fn giving_up_on_sleep_keeps_the_count_and_yields_again() {
        let mut streak = Streak::new(Some(4));
        for _ in 0..4 {
            streak.empty();
        }
        streak.stop_sleeping();
        assert_eq!(streak.count(), 4);
        let nexts: Vec<Next> = (0..POLLS_BEFORE_YIELD).map(|_| streak.empty()).collect();
        assert!(!nexts.contains(&Next::Sleep));
        assert_eq!(nexts.iter().filter(|&&n| n == Next::Yield).count(), 1);
    }

    /// A count stuck at `u32::MAX` would never again be a multiple of the yield interval.
    #[test]
    fn a_long_spell_of_polling_keeps_yielding() {
        let mut streak = Streak::new(None);
        streak.empty = u32::MAX - POLLS_BEFORE_YIELD;
        let yields = (0..POLLS_BEFORE_YIELD * 4)
            .map(|_| streak.empty())
            .filter(|&n| n == Next::Yield)
            .count();
        assert_eq!(yields, 4);
    }
}
