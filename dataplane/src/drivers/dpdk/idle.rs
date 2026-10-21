// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a worker does between polls that found nothing.
//!
//! In [`IdleMode::Poll`] it spins, yielding the CPU now and then. In [`IdleMode::Monitor`], once
//! [`IdleConfig::polls`] polls in a row have found nothing, it sleeps before every poll in a
//! low-power state, until a NIC writes to one of its receive queues or [`IdleConfig::sleep_us`]
//! passes, and goes back to spinning the moment a poll finds something.

use std::time::{Duration, Instant};

use args::{IdleConfig, IdleMode};
use dpdk::lcore::LCore;
use dpdk::power::{Sleeper, Slept};
use dpdk::queue::rx::RxQueue;
use tracing::{info, warn};

use crate::drivers::status::WorkerId;

/// Yield after this many consecutive polls without traffic, while spinning.
const POLLS_BEFORE_YIELD: u32 = 128;

/// While asleep, how often to do what a worker otherwise does every few thousand polls: check for
/// shutdown, pat its watchdog and report its counts. A thousand sleeps can take a second.
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
    empty: u32,
    sleep_after: Option<u32>,
}

impl Streak {
    fn new(sleep_after: Option<u32>) -> Self {
        Self {
            empty: 0,
            sleep_after,
        }
    }

    fn busy(&mut self) {
        self.empty = 0;
    }

    fn empty(&mut self) -> Next {
        self.empty = self.empty.saturating_add(1);
        match self.sleep_after {
            Some(after) if self.empty >= after => Next::Sleep,
            _ if self.empty.is_multiple_of(POLLS_BEFORE_YIELD) => Next::Yield,
            _ => Next::Spin,
        }
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
    /// Whether it has slept for long enough since that they are due.
    due: bool,
}

impl Idle {
    /// Idling as `config` asks, as far as this CPU allows.
    ///
    /// `lcore` is the worker's registration with the EAL; without one there is no sleeping.
    pub(crate) fn new(worker: WorkerId, config: IdleConfig, lcore: Option<&LCore>) -> Self {
        let sleeper = match (config.mode, lcore) {
            (IdleMode::Poll, _) => None,
            (IdleMode::Monitor, None) => {
                warn!(
                    worker,
                    "idle mode is monitor, but this worker is not an lcore; it will poll"
                );
                None
            }
            (IdleMode::Monitor, Some(lcore)) => {
                let sleeper = Sleeper::new(lcore);
                if let Some(sleeper) = &sleeper {
                    info!(
                        worker,
                        "idle mode is monitor: sleeping after {} empty polls, for at most {} us, \
                         with {:?}",
                        config.polls,
                        config.sleep_us,
                        sleeper.intrinsics()
                    );
                } else {
                    warn!(
                        worker,
                        "idle mode is monitor, but this CPU has no power-optimized wait; it will \
                         poll"
                    );
                }
                sleeper
            }
        };
        Self {
            worker,
            streak: Streak::new(sleeper.map(|_| config.polls)),
            sleeper,
            longest: Duration::from_micros(u64::from(config.sleep_us)),
            last_busy: 0,
            sleeps: 0,
            checked: clock::now(),
            due: false,
        }
    }

    /// Whether the worker has slept long enough since its periodic checks that it should do them
    /// now rather than wait for its poll count.
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
        self.streak.busy();
        self.last_busy = slot;
    }

    /// A poll found nothing on any of `queues`, the worker's receive queues in slot order.
    pub(crate) fn empty<'q, 'dev: 'q>(
        &mut self,
        lcore: Option<&LCore>,
        queues: impl Iterator<Item = &'q RxQueue<'dev>> + Clone,
    ) {
        match self.streak.empty() {
            Next::Spin => {}
            Next::Yield => std::thread::yield_now(),
            Next::Sleep => self.sleep(lcore, queues),
        }
    }

    /// How many times this worker has slept.
    pub(crate) fn sleeps(&self) -> u64 {
        self.sleeps
    }

    fn sleep<'q, 'dev: 'q>(
        &mut self,
        lcore: Option<&LCore>,
        queues: impl Iterator<Item = &'q RxQueue<'dev>> + Clone,
    ) {
        let (Some(sleeper), Some(lcore)) = (&self.sleeper, lcore) else {
            return;
        };
        // The queue that last had traffic first: it is the one watched if only one can be.
        let first = self.last_busy;
        let ordered = queues.clone().skip(first).chain(queues.take(first));
        match sleeper.sleep(lcore, ordered, self.longest) {
            Ok(Slept::Watched(_) | Slept::Paused) => {
                self.sleeps += 1;
                self.due = clock::elapsed(self.checked) >= CHECK_WHILE_ASLEEP;
            }
            Ok(Slept::Not) => {}
            Err(e) => {
                warn!(
                    worker = self.worker,
                    "an idle sleep failed ({e}); this worker will poll from now on"
                );
                self.sleeper = None;
                self.streak = Streak::new(None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Next, POLLS_BEFORE_YIELD, Streak};

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
        let mut streak = Streak::new(Some(1));
        streak.empty = u32::MAX - 1;
        assert_eq!(streak.empty(), Next::Sleep);
        assert_eq!(streak.empty(), Next::Sleep);
    }
}
