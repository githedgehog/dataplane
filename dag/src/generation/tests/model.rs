// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The publication protocol with real threads: a publisher and two workers.
//!
//! Under the `shuttle` feature the threads, atomics and locks are shuttle's, and every generated
//! [`Plan`] is explored under the standard portfolio (random and PCT schedules) by
//! [`concurrency::stress`]. Without it, each plan runs once on OS threads, which is what Miri and
//! the thread sanitizer see.
//!
//! The workers do what the load test's do, at a size a model checker can explore: they stamp the
//! packets that arrive from the selector (or leave them unstamped), queue them FIFO, and poll
//! bursts that they run through the toy graph, then settle, or idle on an empty poll. A worker
//! either reads the live generations before it polls (as a poll loop that reads its tables first
//! does) or after; the first is the order in which the flip's gate on observation matters.
//!
//! Checked, on every schedule:
//! - I1 for every packet, and no stale packet: queues are FIFO, so the acknowledgement rule must
//!   never let a generation retire while a worker still holds its packets;
//! - I3 where it is decided: when a worker stamps a packet, it has observed the generation the
//!   stamp names;
//! - a flip only once every worker has observed the newest generation, a retire only once every
//!   worker has acknowledged it;
//! - the publisher is never held up for good (the workers keep polling once their script ends);
//! - every snapshot is released exactly once, on the publisher's thread.

use super::*;
use bolero::TypeGenerator;
use concurrency::sync::atomic::AtomicBool;

/// Generations a run publishes after the first, at most.
const MAX_BEGINS: u8 = 2;
/// Scripted steps per worker, at most. The rest of a long plan is ignored.
const MAX_STEPS: usize = 6;

/// One scripted step of a worker.
#[derive(Clone, Copy, Debug, TypeGenerator)]
enum Step {
    /// `count % 3` packets arrive: stamped from the selector, now, or unstamped.
    Arrive { count: u8, unstamped: bool },
    /// Poll up to `max % 3 + 1` packets, and run them.
    Poll { max: u8 },
}

/// What one worker does before it only polls.
#[derive(Clone, Debug, TypeGenerator)]
struct Worker {
    /// Read the live generations before polling the queue, rather than after.
    live_first: bool,
    steps: Vec<Step>,
}

/// One run: how many generations the publisher cycles through, and the two workers' scripts.
#[derive(Clone, Debug, TypeGenerator)]
struct Plan {
    begins: u8,
    workers: [Worker; 2],
}

/// The generation a stamp names. Runs are short enough that the stamp's low bits are all of it.
fn generation_of(stamp: Stamp) -> u64 {
    (1..=u64::from(MAX_BEGINS) + 1)
        .find(|&g| {
            let bank = if g % 2 == 1 { Bank::A } else { Bank::B };
            Stamp::new(bank, g) == stamp
        })
        .unwrap_or_else(|| unreachable!("a stamp of a generation this run never published"))
}

/// A packet arriving now, at the worker that owns `reader`: the selector stamps it, unless
/// `unstamped`.
fn arrive(reader: &Reader<'_, Tag>, selector: &Selector, unstamped: bool) -> Packet<TestBuffer> {
    if unstamped {
        return packet(None);
    }
    let stamp = selector.stamp();
    let generation = generation_of(stamp);
    let observed = reader.progress.observed.load(Ordering::Acquire);
    assert!(
        observed >= generation,
        "I3: stamped with generation {generation}, but the worker has only observed {observed}"
    );
    packet(Some(stamp))
}

/// Poll up to `max` packets and run them; on an empty poll, idle.
fn poll(
    reader: &mut Reader<'_, Tag>,
    queue: &mut VecDeque<Packet<TestBuffer>>,
    max: usize,
    live_first: bool,
) {
    let take = |queue: &mut VecDeque<_>| -> Vec<_> {
        let n = max.min(queue.len());
        queue.drain(..n).collect()
    };
    let (live, mut burst) = if live_first {
        let live = reader.live();
        (live, take(queue))
    } else {
        let burst = take(queue);
        (reader.live(), burst)
    };
    if burst.is_empty() {
        reader.idle();
        return;
    }
    let seen = run_checked(&mut burst, live.tables());
    assert_eq!(seen.stale, 0, "a FIFO worker saw a stale packet");
    reader.settle(seen);
}

/// A worker: its script, then polls until the publisher is done and its queue is empty.
fn work(mut reader: Reader<'_, Tag>, selector: &Selector, plan: &Worker, done: &AtomicBool) {
    let mut queue = VecDeque::new();
    for step in plan.steps.iter().take(MAX_STEPS) {
        match *step {
            Step::Arrive { count, unstamped } => {
                for _ in 0..count % 3 {
                    queue.push_back(arrive(&reader, selector, unstamped));
                }
            }
            Step::Poll { max } => poll(
                &mut reader,
                &mut queue,
                usize::from(max % 3) + 1,
                plan.live_first,
            ),
        }
    }
    while !(done.load(Ordering::Acquire) && queue.is_empty()) {
        poll(&mut reader, &mut queue, MAX_BURST, plan.live_first);
        thread::yield_now();
    }
}

/// Sets its flag when dropped: the workers stop however the publisher ends.
struct Done<'a>(&'a AtomicBool);

impl Drop for Done<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Take a publisher step, retrying while it waits for the workers, and only for that.
fn retry(step: impl Fn() -> Result<(), Wait>, waiting: Wait) {
    loop {
        match step() {
            Ok(()) => return,
            Err(wait) => {
                assert_eq!(wait, waiting);
                thread::yield_now();
            }
        }
    }
}

/// Run `plan`: the publisher on this thread, the workers on two others.
fn run_plan(plan: &Plan) {
    let log = drops();
    let begins = u64::from(plan.begins % MAX_BEGINS) + 1;
    let publisher = thread::current().id();
    {
        let generations = Generations::new(Tag::new(1, &log));
        let done = AtomicBool::new(false);
        let readers = [generations.reader(), generations.reader()];
        thread::scope(|s| {
            for (reader, worker) in readers.into_iter().zip(&plan.workers) {
                let selector = generations.selector();
                let done = &done;
                s.spawn(move || work(reader, &selector, worker, done));
            }
            let _done = Done(&done);
            for n in 2..=begins + 1 {
                assert_eq!(generations.begin(Tag::new(n, &log)), Ok(n));
                retry(|| generations.flip(), Wait::NotObserved);
                assert!(
                    generations.all(|p| p.observed.load(Ordering::Acquire) >= n),
                    "flipped to {n} before every worker observed it"
                );
                retry(|| generations.retire(), Wait::NotAcknowledged);
                assert!(
                    generations.all(|p| p.acknowledged.load(Ordering::Acquire) >= n),
                    "retired {} before every worker acknowledged {n}",
                    n - 1
                );
            }
        });
    }
    let log = log.lock();
    assert_eq!(
        log.len(),
        usize::try_from(begins + 1).unwrap(),
        "every snapshot is released, once"
    );
    assert!(
        log.iter().all(|&t| t == publisher),
        "a snapshot was released on a worker"
    );
}

/// A plan that straddles every flip on both workers: packets arrive and are polled one at a time
/// throughout, one worker reading before it polls and the other after. An unstamped packet sits
/// ahead of stamped ones, so a burst of it alone must not acknowledge.
fn straddling() -> Plan {
    let arrive = |count, unstamped| Step::Arrive { count, unstamped };
    let one = Step::Poll { max: 0 };
    let worker = |live_first| Worker {
        live_first,
        steps: vec![
            arrive(2, false),
            one,
            arrive(1, true),
            arrive(2, false),
            one,
            one,
        ],
    };
    Plan {
        begins: MAX_BEGINS - 1,
        workers: [worker(true), worker(false)],
    }
}

/// Runs of `concurrency::stress` on the fixed plan: each is a fresh portfolio of random and PCT
/// schedules under shuttle, and one run on OS threads otherwise.
#[cfg(feature = "shuttle")]
const RUNS: usize = 32;
#[cfg(not(feature = "shuttle"))]
const RUNS: usize = 8;

#[concurrency::model_test]
#[cfg_attr(
    any(feature = "loom", feature = "shuttle_dfs"),
    ignore = "the publisher and the workers spin-wait on each other, and loom and shuttle's DFS schedule unfairly: a spin never ends"
)]
fn a_straddling_plan_holds_on_every_schedule() {
    for _ in 0..RUNS {
        concurrency::stress(|| run_plan(&straddling()));
    }
}

#[concurrency::model_test]
#[cfg_attr(
    any(feature = "loom", feature = "shuttle_dfs"),
    ignore = "the publisher and the workers spin-wait on each other, and loom and shuttle's DFS schedule unfairly: a spin never ends"
)]
fn generated_plans_hold_on_every_schedule() {
    bolero::check!()
        .with_type::<Plan>()
        .cloned()
        .for_each(|plan| concurrency::stress(move || run_plan(&plan)));
}
