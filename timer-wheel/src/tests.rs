// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::*;
use std::time::Duration;

const TICK: Duration = Duration::from_millis(10);

// Single-threaded tests; the facade's locks only work inside a model checker under loom/shuttle.
#[cfg(not(any(feature = "loom", feature = "shuttle")))]
mod single_threaded {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    /// A payload whose deadline the test can move, and which remembers the handle it was bound to.
    #[derive(Debug, Clone)]
    struct Probe {
        key: u32,
        deadline: Rc<Cell<Instant>>,
        bound: Rc<Cell<Option<TimerId>>>,
    }

    impl Probe {
        fn new(key: u32, deadline: Instant) -> Self {
            Self {
                key,
                deadline: Rc::new(Cell::new(deadline)),
                bound: Rc::new(Cell::new(None)),
            }
        }
    }

    impl Timer for Probe {
        fn deadline(&self) -> Instant {
            self.deadline.get()
        }

        fn bind(&self, timer: TimerRef) {
            assert!(self.bound.get().is_none(), "bound twice");
            self.bound.set(Some(timer.id()));
        }
    }

    fn wheel(slots: u32, start: Instant) -> Wheel<Probe> {
        Wheel::new(WheelConfig::new(TICK, slots).unwrap(), start)
    }

    fn keys(out: &[Fired<Probe>]) -> (Vec<u32>, Vec<u32>) {
        let mut due = Vec::new();
        let mut cancelled = Vec::new();
        for fired in out {
            match fired {
                Fired::Due(p) => due.push(p.key),
                Fired::Cancelled(p) => cancelled.push(p.key),
            }
        }
        due.sort_unstable();
        cancelled.sort_unstable();
        (due, cancelled)
    }

    #[test]
    fn a_timer_fires_after_its_deadline_and_within_a_tick() {
        let start = clock::now();
        let mut w = wheel(64, start);
        w.insert(Probe::new(1, start + Duration::from_millis(25)))
            .unwrap();
        let mut out = Vec::new();
        w.sweep(start + Duration::from_millis(24), usize::MAX, &mut out);
        assert!(out.is_empty());
        // Seen 1 ms early, the timer moved to the next tick: it is due by 25 + 10 ms.
        w.sweep(start + Duration::from_millis(35), usize::MAX, &mut out);
        assert_eq!(keys(&out).0, [1]);
        assert!(w.is_empty());
    }

    #[test]
    fn a_refreshed_deadline_moves_the_timer_instead_of_firing_it() {
        let start = clock::now();
        let mut w = wheel(64, start);
        let probe = Probe::new(1, start + Duration::from_millis(20));
        w.insert(probe.clone()).unwrap();
        probe.deadline.set(start + Duration::from_millis(200));
        let mut out = Vec::new();
        let sweep = w.sweep(start + Duration::from_millis(100), usize::MAX, &mut out);
        assert!(out.is_empty());
        assert_eq!(sweep.moved, 1);
        w.sweep(start + Duration::from_millis(200), usize::MAX, &mut out);
        assert_eq!(keys(&out).0, [1]);
    }

    #[test]
    fn a_deadline_beyond_the_span_waits_for_its_revolution() {
        let start = clock::now();
        // 8 slots of 10 ms: an 80 ms span.
        let mut w = wheel(8, start);
        w.insert(Probe::new(1, start + Duration::from_millis(1000)))
            .unwrap();
        let mut out = Vec::new();
        let mut t = start;
        while t < start + Duration::from_millis(990) {
            t += TICK;
            w.sweep(t, usize::MAX, &mut out);
            assert!(out.is_empty(), "fired early at {:?}", t - start);
        }
        w.sweep(start + Duration::from_millis(1000), usize::MAX, &mut out);
        assert_eq!(keys(&out).0, [1]);
    }

    #[test]
    fn cancelling_from_a_ref_hands_the_payload_back_once() {
        let start = clock::now();
        let mut w = wheel(64, start);
        let probe = Probe::new(7, start + Duration::from_secs(60));
        let id = w.insert(probe.clone()).unwrap();
        assert_eq!(probe.bound.get(), Some(id));
        let timer = TimerRef::new(Arc::clone(&w.cancels), id);
        timer.cancel();
        timer.cancel();
        let mut out = Vec::new();
        w.sweep(start, usize::MAX, &mut out);
        assert_eq!(keys(&out), (vec![], vec![7]));
        assert!(w.is_empty());
        // The slot is reused; the stale ref must not cancel its new tenant.
        let other = w
            .insert(Probe::new(8, start + Duration::from_secs(60)))
            .unwrap();
        assert_eq!(other.slot, id.slot);
        timer.cancel();
        out.clear();
        w.sweep(start, usize::MAX, &mut out);
        assert!(out.is_empty());
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn a_sweep_does_no_more_than_its_budget_and_the_rest_carries_over() {
        let start = clock::now();
        let mut w = wheel(64, start);
        for key in 0..100 {
            w.insert(Probe::new(key, start + TICK)).unwrap();
        }
        let mut out = Vec::new();
        let mut calls = 0;
        loop {
            let before = out.len();
            let sweep = w.sweep(start + TICK, 16, &mut out);
            assert!(out.len() - before <= 16);
            calls += 1;
            if !sweep.behind {
                break;
            }
        }
        assert_eq!(keys(&out).0, (0..100).collect::<Vec<_>>());
        assert_eq!(calls, 100usize.div_ceil(16));
    }

    #[test]
    fn remote_timers_are_adopted_and_bound_on_the_next_sweep() {
        let start = clock::now();
        let mut w = wheel(64, start);
        let remote = w.remote();
        let probe = Probe::new(3, start + TICK);
        remote.schedule(probe.clone());
        assert!(w.is_empty());
        assert!(probe.bound.get().is_none());
        let mut out = Vec::new();
        let sweep = w.sweep(start, usize::MAX, &mut out);
        assert_eq!(sweep.adopted, 1);
        assert!(probe.bound.get().is_some());
        w.sweep(start + TICK, usize::MAX, &mut out);
        assert_eq!(keys(&out).0, [3]);
    }

    #[test]
    fn an_idle_wheel_catches_up_without_walking_every_bucket() {
        let start = clock::now();
        let mut w = wheel(64, start);
        let mut out = Vec::new();
        w.sweep(start + Duration::from_secs(3600), 1, &mut out);
        w.insert(Probe::new(1, start + Duration::from_secs(3600) + TICK))
            .unwrap();
        let sweep = w.sweep(
            start + Duration::from_secs(3600) + TICK,
            usize::MAX,
            &mut out,
        );
        assert_eq!(keys(&out).0, [1]);
        assert!(!sweep.behind);
    }

    #[test]
    fn configs_outside_the_supported_shape_are_refused() {
        assert_eq!(
            WheelConfig::new(Duration::ZERO, 8),
            Err(ConfigError::TickTooShort(Duration::ZERO))
        );
        assert_eq!(WheelConfig::new(TICK, 1), Err(ConfigError::TooFewSlots(1)));
        assert_eq!(
            WheelConfig::new(TICK, WheelConfig::MAX_SLOTS + 1),
            Err(ConfigError::TooManySlots(WheelConfig::MAX_SLOTS + 1))
        );
        assert!(WheelConfig::new(TICK, 2).is_ok());
    }

    /// One step of the model test.
    #[derive(Debug, Clone, bolero::TypeGenerator)]
    enum Op {
        /// A timer `after` ms (0..=2047) from now.
        Insert { after: u16 },
        /// Move timer `which` (index into the live set) `by` ms later.
        Refresh { which: u16, by: u16 },
        /// Cancel timer `which` through the owner.
        Cancel { which: u16 },
        /// Cancel timer `which` through its ref, as another thread would.
        CancelRef { which: u16 },
        /// Let `ms` (0..=255) pass.
        Advance { ms: u8 },
        /// Sweep with `budget` (1..=64).
        Sweep { budget: u8 },
    }

    struct Model {
        probe: Probe,
        deadline: Instant,
        cancel_queued: bool,
    }

    /// Against a plain map of deadlines: a timer never fires early, never fires after being cancelled,
    /// fires within a tick of its deadline once the wheel has caught up, and the wheel holds exactly
    /// the timers the model holds.
    #[test]
    fn the_wheel_agrees_with_a_map_of_deadlines() {
        bolero::check!()
            .with_type::<(bool, Vec<Op>)>()
            .for_each(|(small, ops)| {
                let start = clock::now();
                // A small wheel exercises wrap-around; a large one, long spans.
                let slots = if *small { 4 } else { 256 };
                let mut w = wheel(slots, start);
                let mut now = start;
                let mut live: BTreeMap<u32, Model> = BTreeMap::new();
                let mut next_key = 0u32;
                let mut out = Vec::new();
                let pick = |live: &BTreeMap<u32, Model>, which: u16| {
                    (!live.is_empty())
                        .then(|| *live.keys().nth(usize::from(which) % live.len()).unwrap())
                };
                for op in ops {
                    match *op {
                        Op::Insert { after } => {
                            let deadline = now + Duration::from_millis(u64::from(after % 2048));
                            let probe = Probe::new(next_key, deadline);
                            w.insert(probe.clone()).unwrap();
                            live.insert(
                                next_key,
                                Model {
                                    probe,
                                    deadline,
                                    cancel_queued: false,
                                },
                            );
                            next_key += 1;
                        }
                        Op::Refresh { which, by } => {
                            if let Some(key) = pick(&live, which) {
                                let m = live.get_mut(&key).unwrap();
                                m.deadline += Duration::from_millis(u64::from(by % 2048));
                                m.probe.deadline.set(m.deadline);
                            }
                        }
                        Op::Cancel { which } => {
                            if let Some(key) = pick(&live, which) {
                                let id = live[&key].probe.bound.get().unwrap();
                                let payload = w.cancel(id).expect("a live timer cancels");
                                assert_eq!(payload.key, key);
                                live.remove(&key);
                            }
                        }
                        Op::CancelRef { which } => {
                            if let Some(key) = pick(&live, which) {
                                let m = live.get_mut(&key).unwrap();
                                TimerRef::new(Arc::clone(&w.cancels), m.probe.bound.get().unwrap())
                                    .cancel();
                                m.cancel_queued = true;
                            }
                        }
                        Op::Advance { ms } => now += Duration::from_millis(u64::from(ms)),
                        Op::Sweep { budget } => {
                            let budget = usize::from(budget % 64) + 1;
                            let sweep = w.sweep(now, budget, &mut out);
                            for fired in out.drain(..) {
                                match fired {
                                    Fired::Due(p) => {
                                        let m = live.remove(&p.key).expect("only live timers fire");
                                        // A cancel still queued behind the budget may lose the
                                        // race with expiry; either outcome is fine.
                                        assert!(m.deadline <= now, "fired early");
                                    }
                                    Fired::Cancelled(p) => {
                                        let m =
                                            live.remove(&p.key).expect("only live timers cancel");
                                        assert!(m.cancel_queued, "cancelled without being asked");
                                    }
                                }
                            }
                            if !sweep.behind {
                                // Caught up: nothing queued for cancel is left, and nothing more than a
                                // tick overdue is still waiting.
                                for (key, m) in &live {
                                    assert!(!m.cancel_queued, "cancel of {key} not applied");
                                    assert!(
                                        m.deadline + TICK > now,
                                        "timer {key} overdue by {:?}",
                                        now - m.deadline
                                    );
                                }
                            }
                        }
                    }
                    assert_eq!(w.len(), live.len());
                }
            });
    }
}

/// A timer cancelled from another thread while its owner sweeps comes back exactly once, and it
/// comes back as cancelled unless it was already due.
#[concurrency::test]
fn a_cross_thread_cancel_is_applied_exactly_once() {
    use concurrency::sync::mpsc;
    use concurrency::thread;

    // No Debug: loom's channel ends do not implement it.
    struct Sendable {
        deadline: Instant,
        bound: mpsc::Sender<TimerRef>,
    }
    impl Timer for Sendable {
        fn deadline(&self) -> Instant {
            self.deadline
        }
        fn bind(&self, timer: TimerRef) {
            self.bound.send(timer).unwrap();
        }
    }

    let start = clock::now();
    let mut w: Wheel<Sendable> = Wheel::new(WheelConfig::new(TICK, 8).unwrap(), start);
    let (tx, rx) = mpsc::channel();
    let inserted = w.insert(Sendable {
        deadline: start + TICK,
        bound: tx,
    });
    assert!(inserted.is_ok(), "the wheel has room");
    let timer = rx.recv().unwrap();
    let canceller = thread::spawn(move || timer.cancel());
    let mut out = Vec::new();
    w.sweep(start + TICK, 1, &mut out);
    canceller.join().unwrap();
    w.sweep(start + TICK, usize::MAX, &mut out);
    assert_eq!(out.len(), 1);
    assert!(w.is_empty());
}
