// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Idle behavior shared by data and control workers.
//!
//! [`IdleMode::Poll`] spins and periodically yields. [`IdleMode::Monitor`] begins low-power waits
//! after [`IdleConfig::polls`] consecutive empty polls. Each wait ends on a watched queue write
//! or after [`IdleConfig::sleep_us`] microseconds; traffic resets the empty-poll streak.
//! Workers without receive queues use timed kernel sleeps, independent of CPU wait support.
//!
//! [`IdleMode::Interrupt`] uses monitor waits where supported, then blocks in epoll after
//! [`IdleConfig::interrupt_after_us`] microseconds without work:
//!
//! 1. Arm every receive queue and injection doorbell, then poll again to catch pre-arm arrivals.
//! 2. If still idle, wait for an interrupt, a doorbell, or the periodic checks to come due.
//! 3. Disarm on wake and resume polling.
//!
//! Interrupt sleep requires support on every receive queue owned by the worker.
//! If any queue lacks it, the worker uses monitor waits or polling to avoid delaying that queue.

use std::time::{Duration, Instant};

use args::{IdleConfig, IdleMode};
use dpdk::interrupt::RxWaiter;
use dpdk::lcore::LCore;
use dpdk::power::{Sleeper, Slept};
use dpdk::queue::rx::RxQueue;
use tracing::{info, warn};

use crate::drivers::cpbridge::Doorbell;
use crate::drivers::load::Spent;
use crate::drivers::status::WorkerId;

/// Yield after this many consecutive polls without traffic, while spinning.
const POLLS_BEFORE_YIELD: u32 = 128;

/// Elapsed-time threshold for shutdown checks, watchdog updates, and counter reporting.
/// Poll-count thresholds alone delay this work while the worker sleeps.
///
/// Interrupt timeouts use the remaining interval so repeated waits do not reset the deadline.
const CHECK_WHILE_ASLEEP: Duration = Duration::from_millis(10);

/// The shortest interrupt wait: [`RxWaiter::wait`] counts whole milliseconds, at least one.
const SHORTEST_INTERRUPT_WAIT: Duration = Duration::from_millis(1);

/// Sample the idle duration every this many empty polls to limit clock-read overhead.
const POLLS_PER_CLOCK_READ: u32 = 64;

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

/// Interrupt registrations and idle-duration tracking for one worker.
struct Interrupts<'dev> {
    waiter: RxWaiter<'dev>,
    /// Declared after the waiter so its registered descriptors remain open until it is dropped.
    bells: Vec<Doorbell>,
    /// How long the worker finds nothing before it sleeps on interrupts.
    after: Duration,
    /// First clock sample in the current idle period.
    quiet_since: Option<Instant>,
    sleeps: u64,
}

/// A worker's idling, across all of its receive queues.
pub(crate) struct Idle<'dev> {
    worker: WorkerId,
    config: IdleConfig,
    streak: Streak,
    sleeper: Option<Sleeper>,
    interrupts: Option<Interrupts<'dev>>,
    longest: Duration,
    /// The queue that last had traffic: the one to watch if only one can be.
    last_busy: usize,
    sleeps: u64,
    /// When the worker last did its periodic checks.
    checked: Instant,
    /// Whether elapsed time requires periodic checks before the next poll-count threshold.
    due: bool,
}

impl Interrupts<'_> {
    /// Disarm queue interrupts and doorbell notifications before resuming polling.
    ///
    /// Leave doorbells unread here; `wait_for_interrupt` drains them only after a descriptor wake.
    /// A pending edge may end the next wait early. Because eventfd writes produce new edges,
    /// leaving a bell readable does not prevent later writes from waking the worker.
    fn disarm(&mut self) {
        self.waiter.disarm();
        self.bells.iter().for_each(Doorbell::disarm);
    }
}

impl Drop for Interrupts<'_> {
    /// A worker that stops, or gives up on interrupts, while armed must not leave its doorbells
    /// armed: its senders would write to an eventfd that nobody reads, once per frame.
    fn drop(&mut self) {
        self.disarm();
    }
}

impl<'dev> Idle<'dev> {
    /// Configure idle behavior using the available CPU capabilities.
    /// `lcore` is required for power-optimized waits, but not for timed kernel sleeps.
    pub(crate) fn new(worker: WorkerId, config: IdleConfig, lcore: Option<&LCore>) -> Self {
        let sleeper = match (config.mode, lcore) {
            (IdleMode::Poll, _) => None,
            (IdleMode::Monitor | IdleMode::Interrupt, None) => {
                warn!(
                    worker,
                    "idle mode is {}, but this worker is not an lcore, so it has no \
                     power-optimized wait",
                    config.mode
                );
                None
            }
            (IdleMode::Monitor | IdleMode::Interrupt, Some(lcore)) => {
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
                        "idle mode is {}, but this CPU has no power-optimized wait; it will poll{}",
                        config.mode,
                        if config.mode == IdleMode::Interrupt {
                            " until it sleeps on interrupts, if it can"
                        } else {
                            ""
                        }
                    );
                }
                sleeper
            }
        };
        Self {
            worker,
            config,
            // Even without a power-optimized wait: a worker with no queues sleeps all the same.
            streak: Streak::new((config.mode != IdleMode::Poll).then_some(config.polls)),
            sleeper,
            interrupts: None,
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

    /// Register queue interrupts and injection doorbells for [`IdleMode::Interrupt`].
    /// Each queue is paired with its port's interrupt-support flag.
    /// If any queue lacks support or registration fails, warn and retain monitor or poll mode.
    pub(crate) fn sleep_on_interrupts<'q>(
        &mut self,
        queues: impl Iterator<Item = (&'q RxQueue<'dev>, bool)>,
        bells: impl Iterator<Item = Doorbell>,
    ) where
        'dev: 'q,
    {
        let config = self.config;
        if config.mode != IdleMode::Interrupt {
            return;
        }
        let mut waiter = match RxWaiter::new() {
            Ok(waiter) => waiter,
            Err(e) => {
                warn!(worker = self.worker, "will not sleep on interrupts: {e}");
                return;
            }
        };
        for (queue, has_interrupts) in queues {
            if !has_interrupts {
                warn!(
                    worker = self.worker,
                    "will not sleep on interrupts: one of its ports has none, and its packets \
                     would wait for the next wake-up"
                );
                return;
            }
            if let Err(e) = waiter.watch(queue) {
                warn!(worker = self.worker, "will not sleep on interrupts: {e}");
                return;
            }
        }
        let bells: Vec<Doorbell> = bells.collect();
        for bell in &bells {
            // SAFETY: the bell stays open in `Interrupts::bells`, which outlives the waiter.
            if let Err(e) = unsafe { waiter.watch_fd(bell.fd()) } {
                warn!(worker = self.worker, "will not sleep on interrupts: {e}");
                return;
            }
        }
        info!(
            worker = self.worker,
            "sleeping on the interrupts of {} queue(s) and {} doorbell(s) after {} us without a \
             packet",
            waiter.queues(),
            bells.len(),
            config.interrupt_after_us
        );
        self.interrupts = Some(Interrupts {
            waiter,
            bells,
            after: Duration::from_micros(u64::from(config.interrupt_after_us)),
            quiet_since: None,
            sleeps: 0,
        });
    }

    /// A poll found traffic on queue `slot`.
    pub(crate) fn busy(&mut self, slot: usize) {
        self.last_busy = slot;
        self.working();
    }

    /// Reset idling for non-packet work, such as an expiry backlog, and disarm pending waits.
    pub(crate) fn working(&mut self) {
        self.streak.busy();
        if let Some(interrupts) = &mut self.interrupts {
            interrupts.quiet_since = None;
            if interrupts.waiter.armed() {
                // Found by the poll after arming: no need to sleep after all.
                interrupts.disarm();
            }
        }
    }

    /// A poll found nothing on any of `queues`, the worker's receive queues in slot order.
    /// Returns what the worker did about it: polled on, or slept, and how.
    pub(crate) fn empty<'q, 'd: 'q>(
        &mut self,
        lcore: Option<&LCore>,
        queues: impl Iterator<Item = &'q RxQueue<'d>> + Clone,
    ) -> Spent {
        // Armed, and the poll after arming found nothing: sleep until something happens.
        if self
            .interrupts
            .as_ref()
            .is_some_and(|interrupts| interrupts.waiter.armed())
        {
            self.streak.empty();
            return if self.wait_for_interrupt() {
                Spent::Interrupt
            } else {
                Spent::Polling
            };
        }
        let (tried, slept) = match self.streak.empty() {
            Next::Spin => (false, false),
            Next::Yield => {
                std::thread::yield_now();
                (false, false)
            }
            Next::Sleep => (true, self.sleep(lcore, queues)),
        };
        self.maybe_arm(tried);
        if slept {
            Spent::Monitor
        } else {
            Spent::Polling
        }
    }

    /// The mode the worker idles in now: the configured one, or a weaker one if it lacks what that
    /// needs or a sleep failed.
    pub(crate) fn mode(&self) -> IdleMode {
        if self.interrupts.is_some() {
            IdleMode::Interrupt
        } else if self.streak.sleep_after.is_some() {
            IdleMode::Monitor
        } else {
            IdleMode::Poll
        }
    }

    /// Empty polls in a row so far, wrapping; zero after a busy one.
    pub(crate) fn empty_polls(&self) -> u32 {
        self.streak.count()
    }

    /// How many times this worker has slept in a low-power state, and on interrupts.
    pub(crate) fn sleeps(&self) -> (u64, u64) {
        (
            self.sleeps,
            self.interrupts.as_ref().map_or(0, |i| i.sleeps),
        )
    }

    /// Arm the interrupts if the worker has found nothing for long enough. The worker polls once
    /// more before it sleeps on them.
    fn maybe_arm(&mut self, slept: bool) {
        let Some(interrupts) = &mut self.interrupts else {
            return;
        };
        // Sample time periodically while polling and after each sleep.
        // This can start the idle period up to POLLS_PER_CLOCK_READ polls late.
        if !slept && !self.streak.count().is_multiple_of(POLLS_PER_CLOCK_READ) {
            return;
        }
        let now = clock::now();
        let since = *interrupts.quiet_since.get_or_insert(now);
        if now.saturating_duration_since(since) < interrupts.after {
            return;
        }
        match interrupts.waiter.arm() {
            // The next poll checks the injection queues too, for frames queued before arming.
            Ok(()) => interrupts.bells.iter().for_each(Doorbell::arm),
            Err(e) => {
                warn!(
                    worker = self.worker,
                    "could not arm receive interrupts ({e}); this worker will no longer sleep on \
                     them"
                );
                self.interrupts = None;
            }
        }
    }

    /// Wait on armed interrupts and doorbells with a timeout bounded by the next periodic check.
    /// Disarm after waiting, or run checks first if less than 1 ms remains.
    /// Returns whether the worker slept.
    fn wait_for_interrupt(&mut self) -> bool {
        let Some(interrupts) = &mut self.interrupts else {
            return false;
        };
        let Some(longest) = interrupt_wait(clock::elapsed(self.checked)) else {
            // Too close to the checks to wait at all: do them, then arm again.
            interrupts.disarm();
            self.due = true;
            return false;
        };
        let woke = interrupts.waiter.wait(longest);
        interrupts.disarm();
        match woke {
            Ok(woke) => {
                if woke.other > 0 {
                    interrupts.bells.iter().for_each(Doorbell::clear);
                }
                interrupts.sleeps += 1;
                self.due = interrupt_wait(clock::elapsed(self.checked)).is_none();
                true
            }
            Err(e) => {
                warn!(
                    worker = self.worker,
                    "a sleep on interrupts failed ({e}); this worker will no longer sleep on them"
                );
                self.interrupts = None;
                false
            }
        }
    }

    fn sleep<'q, 'd: 'q>(
        &mut self,
        lcore: Option<&LCore>,
        queues: impl Iterator<Item = &'q RxQueue<'d>> + Clone,
    ) -> bool {
        // With no receive queues, a timed kernel sleep needs no CPU monitor instruction.
        if queues.clone().next().is_none() {
            std::thread::sleep(self.longest);
            self.slept();
            return true;
        }
        let (Some(sleeper), Some(lcore)) = (&self.sleeper, lcore) else {
            // No power-optimized wait: spin and yield.
            self.streak.stop_sleeping();
            return false;
        };
        // The queue that last had traffic first: it is the one watched if only one can be.
        let first = self.last_busy;
        let ordered = queues.clone().skip(first).chain(queues.take(first));
        match sleeper.sleep(lcore, ordered, self.longest) {
            Ok(Slept::Watched(_) | Slept::Paused) => {
                self.slept();
                true
            }
            // No usable monitor condition or pause instruction; disable further monitor attempts.
            Ok(Slept::Not) => {
                info!(
                    worker = self.worker,
                    "this worker's queues offer nothing to watch and the CPU no pause; it will poll"
                );
                self.sleeper = None;
                self.streak.stop_sleeping();
                false
            }
            Err(e) => {
                warn!(
                    worker = self.worker,
                    "an idle sleep failed ({e}); this worker will poll from now on"
                );
                self.sleeper = None;
                self.streak.stop_sleeping();
                false
            }
        }
    }

    /// Count a sleep, and note whether it ran long enough for the periodic checks to come due.
    fn slept(&mut self) {
        self.sleeps += 1;
        self.due = clock::elapsed(self.checked) >= CHECK_WHILE_ASLEEP;
    }
}

/// Remaining timeout budget, given `since` elapsed since the last periodic checks.
/// Reusing a full interval after each wake could postpone checks by almost
/// another [`CHECK_WHILE_ASLEEP`].
///
/// `None` if less than [`SHORTEST_INTERRUPT_WAIT`] is left, so the checks should run first.
fn interrupt_wait(since: Duration) -> Option<Duration> {
    Some(CHECK_WHILE_ASLEEP.saturating_sub(since)).filter(|left| *left >= SHORTEST_INTERRUPT_WAIT)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use args::{IdleConfig, IdleMode};
    use dpdk::queue::rx::RxQueue;

    use super::{
        CHECK_WHILE_ASLEEP, Idle, Next, POLLS_BEFORE_YIELD, SHORTEST_INTERRUPT_WAIT, Spent, Streak,
        interrupt_wait,
    };
    use crate::drivers::cpbridge::{Doorbell, inject_channel};

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
            ..IdleConfig::default()
        };
        // No lcore, so no power-optimized wait either.
        let mut idle = Idle::new(0, config, None);
        let start = clock::now();
        for _ in 0..polls {
            idle.empty(None, std::iter::empty::<&RxQueue<'_>>());
        }
        (idle.sleeps().0, clock::elapsed(start))
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

    /// Each empty poll says what it became, which is what the worker's load is made of: polls until
    /// the streak calls for sleep, then sleeps.
    #[test]
    fn an_empty_poll_says_whether_it_slept() {
        let config = IdleConfig {
            mode: IdleMode::Monitor,
            polls: 3,
            sleep_us: 100,
            ..IdleConfig::default()
        };
        let mut idle = Idle::new(0, config, None);
        let spent: Vec<Spent> = (0..4)
            .map(|_| idle.empty(None, std::iter::empty::<&RxQueue<'_>>()))
            .collect();
        assert_eq!(
            spent,
            [
                Spent::Polling,
                Spent::Polling,
                Spent::Monitor,
                Spent::Monitor
            ]
        );
    }

    /// A worker reports the mode it idles in, not the one it was asked for: interrupts need queues
    /// to sleep on, and one that was never given them idles in monitor mode instead.
    #[test]
    fn the_mode_is_the_one_the_worker_can_idle_in() {
        let idle = |mode| {
            Idle::new(
                0,
                IdleConfig {
                    mode,
                    ..IdleConfig::default()
                },
                None,
            )
            .mode()
        };
        assert_eq!(idle(IdleMode::Poll), IdleMode::Poll);
        assert_eq!(idle(IdleMode::Monitor), IdleMode::Monitor);
        assert_eq!(idle(IdleMode::Interrupt), IdleMode::Monitor);
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

    /// An interrupt wait ends by the time the periodic checks come due, and is never shorter than
    /// the waiter can sleep.
    #[test]
    fn an_interrupt_wait_ends_when_the_checks_come_due() {
        bolero::check!().with_type::<u64>().for_each(|&nanos| {
            for since in [
                Duration::from_nanos(nanos),
                Duration::from_nanos(nanos % 12_000_000),
                CHECK_WHILE_ASLEEP.saturating_sub(SHORTEST_INTERRUPT_WAIT),
            ] {
                let left = CHECK_WHILE_ASLEEP.saturating_sub(since);
                match interrupt_wait(since) {
                    Some(wait) => {
                        assert!(wait >= SHORTEST_INTERRUPT_WAIT, "{since:?}: {wait:?}");
                        assert_eq!(wait, left, "since {since:?}");
                    }
                    None => assert!(left < SHORTEST_INTERRUPT_WAIT, "since {since:?}"),
                }
            }
        });
    }

    /// A worker with no receive queues, sleeping on `bell` alone, armed and about to wait.
    fn armed_on(bell: Doorbell) -> Idle<'static> {
        let config = IdleConfig {
            mode: IdleMode::Interrupt,
            polls: 1,
            sleep_us: 1,
            interrupt_after_us: 0,
        };
        let mut idle = Idle::new(0, config, None);
        idle.sleep_on_interrupts(std::iter::empty(), std::iter::once(bell));
        // The first empty poll sleeps briefly and, idle long enough already, arms.
        idle.empty(None, std::iter::empty::<&RxQueue<'_>>());
        assert!(
            idle.interrupts
                .as_ref()
                .is_some_and(|interrupts| interrupts.waiter.armed())
        );
        idle
    }

    /// Just before the periodic checks, the worker does them rather than wait first.
    #[test]
    fn a_worker_about_to_check_does_not_wait_on_interrupts() {
        let (_sender, receiver) = inject_channel(1).unwrap();
        let mut idle = armed_on(receiver.doorbell());
        idle.checked = clock::now()
            .checked_sub(CHECK_WHILE_ASLEEP.saturating_sub(SHORTEST_INTERRUPT_WAIT / 2))
            .unwrap();
        idle.empty(None, std::iter::empty::<&RxQueue<'_>>());
        assert!(idle.checks_due());
        assert_eq!(idle.sleeps().1, 0, "waited on interrupts");
        assert!(idle.interrupts.as_ref().is_some_and(|i| !i.waiter.armed()));
    }

    /// A wait that starts late in the check interval ends when the checks come due.
    #[test]
    fn an_interrupt_wait_does_not_postpone_the_checks() {
        let left = CHECK_WHILE_ASLEEP / 2;
        let since = CHECK_WHILE_ASLEEP.saturating_sub(left);
        // A fresh wait would take all of CHECK_WHILE_ASLEEP, every time. A shortened one takes that
        // long only if the runner stalls it, and a stall before it can leave the worker too close to
        // the checks to wait at all. Both are luck, so try a few times; the bug never passes.
        let mut tries = Vec::new();
        for _ in 0..5 {
            let (_sender, receiver) = inject_channel(1).unwrap();
            let mut idle = armed_on(receiver.doorbell());
            let start = clock::now();
            idle.checked = start.checked_sub(since).unwrap();
            idle.empty(None, std::iter::empty::<&RxQueue<'_>>());
            let took = clock::elapsed(start);
            assert!(idle.checks_due());
            let waits = idle.sleeps().1;
            if waits == 1 && took < CHECK_WHILE_ASLEEP {
                return;
            }
            tries.push((waits, took));
        }
        unreachable!("with {left:?} left before the checks, (waits, took) were {tries:?}");
    }

    /// Whether `bell` rang since it was last read, clearing it.
    fn rang(bell: &Doorbell) -> bool {
        nix::unistd::read(bell.fd(), &mut [0; 8]).is_ok()
    }

    /// Frames sent after a worker stops while armed ring no doorbell.
    #[test]
    fn a_worker_stopped_while_armed_leaves_its_doorbells_quiet() {
        let (sender, receiver) = inject_channel(4).unwrap();
        let bell = receiver.doorbell();
        let idle = armed_on(receiver.doorbell());
        sender.try_send(vec![0; 64]).unwrap();
        assert!(rang(&bell), "an armed worker's doorbell did not ring");
        drop(idle);
        sender.try_send(vec![0; 64]).unwrap();
        assert!(!rang(&bell), "a stopped worker's doorbell rang");
    }

    /// A ring ends the wait, and the bell is cleared after it.
    #[test]
    fn a_doorbell_wakes_the_worker_and_is_cleared() {
        let (sender, receiver) = inject_channel(4).unwrap();
        let bell = receiver.doorbell();
        let mut idle = armed_on(receiver.doorbell());
        // Rung while armed, before the wait: edge-triggered, so the wait still sees it.
        sender.try_send(vec![0; 64]).unwrap();
        // A full check interval ahead, so a slow start (under emulation, say) does not make the
        // worker do its checks instead of waiting.
        idle.checked();
        idle.empty(None, std::iter::empty::<&RxQueue<'_>>());
        assert_eq!(idle.sleeps().1, 1);
        // A wait that timed out instead would not have cleared it.
        assert!(!rang(&bell), "the bell was left readable");
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
