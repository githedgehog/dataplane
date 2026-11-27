// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generations: each packet runs under one generation (I1), and the publication protocol.
//!
//! The nodes here are toys whose tables are a generation number: each records, per packet, the
//! generation it ran it under. The real NFs' differential against the legacy stages is in
//! `dataplane`'s `fuzz.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::MAX_BURST;
use crate::burst::{Emit, Keep, scope_with};
use crate::meta::Opaque;
use crate::presence::Presence;
use net::buffer::TestBuffer;
use net::packet::test_utils::build_test_ipv4_packet;
use net::packet::{Packet, PacketMeta};
use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::thread::ThreadId;
use std::time::{Duration, Instant};

/// A generation's tables: its number. Dropping one records the thread it was dropped on.
#[derive(Debug)]
struct Tag {
    generation: u64,
    drops: Arc<Mutex<Vec<ThreadId>>>,
}

impl Tag {
    fn new(generation: u64, drops: &Arc<Mutex<Vec<ThreadId>>>) -> Tag {
        Tag {
            generation,
            drops: Arc::clone(drops),
        }
    }
}

impl Drop for Tag {
    fn drop(&mut self) {
        self.drops.lock().push(std::thread::current().id());
    }
}

/// Per packet of a burst: the generations the nodes ran it under, in order.
type Record = Vec<Vec<u64>>;

/// A node: records the generation for each packet, and drops those whose index is a multiple of
/// `drop_every`, if any.
fn node<'b, S: State>(
    burst: &mut Burst<'b, TestBuffer>,
    sel: Sel<'b, S>,
    tag: &Tag,
    record: &mut Record,
    drop_every: Option<usize>,
) -> (Sel<'b, S>, Drops<'b>) {
    let mut kept = Emit::<S, Keep>::new();
    let mut drops = Drops::none();
    for i in sel {
        record[i.index()].push(tag.generation);
        if drop_every.is_some_and(|n| i.index() % n == 0) {
            burst.drop(&mut drops, i, DoneReason::Filtered);
        } else {
            kept.push(i);
        }
    }
    (kept.finish(), drops)
}

/// What a burst came to.
struct Ran {
    record: Record,
    admitted: u64,
    dropped: u64,
    seen: Seen,
}

/// The toy graph: resolve, a node, a node that drops, a hosted legacy join point (a no-op), and a
/// last node. Shaped like admission: nodes reading tables split per generation, and rejoin where
/// a legacy stage must see the whole burst.
fn run(packets: &mut Vec<Packet<TestBuffer>>, tables: Tables<'_, Tag>) -> Ran {
    let mut record: Record = vec![Vec::new(); packets.len()];
    let (admitted, dropped, seen) = scope_with(packets, tables, |mut burst, all, tables| {
        let tables = *tables;
        let all: Sel<'_, Opaque> = burst.scan(all);
        let (live, stale, seen) = burst.resolve(all, tables);
        let (a, d1) = burst.per_generation(
            live,
            tables,
            |t| t,
            |b, s, t| node(b, s, t, &mut record, None),
        );
        let (b, d2) = burst.per_generation(
            a,
            tables,
            |t| t,
            |b, s, t| node(b, s, t, &mut record, Some(7)),
        );
        let (joined, d3) = burst.legacy(b, Presence::EMPTY, |_| {});
        let (c, d4) = burst.per_generation(
            joined,
            tables,
            |t| t,
            |b, s, t| node(b, s, t, &mut record, None),
        );
        let dropped = stale.join(d1).join(d2).join(d3).join(d4);
        (c.bits(), dropped.bits(), seen)
    });
    Ran {
        record,
        admitted,
        dropped,
        seen,
    }
}

/// The generation each packet must run under, from its stamp and the burst's tables; `None` if
/// stale.
fn expected(packet: &Packet<TestBuffer>, tables: Tables<'_, Tag>) -> Option<u64> {
    match packet.meta().stamp {
        None => Some(tables.newest().generation()),
        Some(stamp) if tables.newest().stamp() == stamp => Some(tables.newest().generation()),
        Some(stamp) => tables
            .previous()
            .filter(|p| p.stamp() == stamp)
            .map(Snapshot::generation),
    }
}

/// Run a burst and check I1 for every packet: every node that saw it ran it under the generation
/// its stamp names (the newest if unstamped), stale packets were dropped and seen by no node, and
/// the outcomes partition the burst.
fn run_checked(packets: &mut Vec<Packet<TestBuffer>>, tables: Tables<'_, Tag>) -> Seen {
    let want: Vec<Option<u64>> = packets.iter().map(|p| expected(p, tables)).collect();
    let ran = run(packets, tables);
    let all = if packets.len() == MAX_BURST {
        u64::MAX
    } else {
        (1 << packets.len()) - 1
    };
    assert!(crate::partitions(all, &[ran.admitted, ran.dropped]));
    for (index, (packet, want)) in packets.iter().zip(&want).enumerate() {
        let seen = &ran.record[index];
        match want {
            None => {
                assert!(seen.is_empty(), "packet {index}: stale, but a node ran it");
                assert_eq!(packet.get_done(), Some(DoneReason::StaleGeneration));
            }
            Some(generation) => {
                // Dropped at the second node (every 7th), or through all three.
                let nodes = if index % 7 == 0 { 2 } else { 3 };
                assert_eq!(seen.len(), nodes, "packet {index}: nodes {seen:?}");
                assert!(
                    seen.iter().all(|g| g == generation),
                    "packet {index}: stamped for {generation}, ran under {seen:?}"
                );
            }
        }
    }
    ran.seen
}

fn packet(stamp: Option<Stamp>) -> Packet<TestBuffer> {
    let mut packet = build_test_ipv4_packet(64).unwrap();
    packet.meta_mut().stamp = stamp;
    packet
}

fn drops() -> Arc<Mutex<Vec<ThreadId>>> {
    Arc::new(Mutex::new(Vec::new()))
}

// ---- The protocol, step by step (single thread) ----

#[test]
fn a_flip_waits_for_every_worker_to_observe() {
    let log = drops();
    let generations = Generations::new(Tag::new(1, &log));
    let mut reader = generations.reader();
    assert_eq!(generations.begin(Tag::new(2, &log)), Ok(2));
    assert_eq!(generations.flip(), Err(Wait::NotObserved));
    let _ = reader.live();
    assert_eq!(generations.flip(), Ok(()));
    assert_eq!(generations.flip(), Err(Wait::NothingPending));
}

#[test]
fn a_retire_waits_for_the_flip_and_every_acknowledgement() {
    let log = drops();
    let generations = Generations::new(Tag::new(1, &log));
    let mut reader = generations.reader();
    assert_eq!(generations.retire(), Err(Wait::NothingPending));
    generations.begin(Tag::new(2, &log)).unwrap();
    let _ = reader.live();
    assert_eq!(generations.retire(), Err(Wait::NotFlipped));
    // Not flipped yet: nothing is acknowledged.
    reader.idle();
    generations.flip().unwrap();
    assert_eq!(generations.retire(), Err(Wait::NotAcknowledged));
    // A burst still holding packets stamped with the previous generation: not yet.
    let _ = reader.live();
    reader.settle(Seen {
        previous: 1,
        newest: 3,
        stale: 0,
    });
    assert_eq!(generations.retire(), Err(Wait::NotAcknowledged));
    // Only unstamped packets: older stamped ones may be queued behind them.
    let _ = reader.live();
    reader.settle(Seen::default());
    assert_eq!(generations.retire(), Err(Wait::NotAcknowledged));
    // A burst stamped with the newest generation, and nothing older.
    let _ = reader.live();
    reader.settle(Seen {
        previous: 0,
        newest: 4,
        stale: 0,
    });
    assert_eq!(generations.retire(), Ok(()));
    assert!(!generations.draining());
}

#[test]
fn at_most_two_generations_are_live() {
    let log = drops();
    let generations = Generations::new(Tag::new(1, &log));
    generations.begin(Tag::new(2, &log)).unwrap();
    assert_eq!(generations.begin(Tag::new(3, &log)), Err(Wait::TwoLive));
}

#[test]
fn an_idle_worker_does_not_hold_up_updates() {
    let log = drops();
    let generations = Generations::new(Tag::new(1, &log));
    let mut idle = generations.reader();
    for n in 2..10 {
        generations.begin(Tag::new(n, &log)).unwrap();
        // Empty polls.
        let _ = idle.live();
        idle.idle();
        generations.flip().unwrap();
        let _ = idle.live();
        idle.idle();
        generations.retire().unwrap();
    }
}

#[test]
fn a_gone_worker_does_not_hold_up_updates() {
    let log = drops();
    let generations = Generations::new(Tag::new(1, &log));
    let reader = generations.reader();
    generations.begin(Tag::new(2, &log)).unwrap();
    drop(reader);
    generations.flip().unwrap();
    generations.retire().unwrap();
}

#[test]
fn a_new_worker_observes_what_is_already_published() {
    let log = drops();
    let generations = Generations::new(Tag::new(1, &log));
    generations.begin(Tag::new(2, &log)).unwrap();
    let _late = generations.reader();
    assert_eq!(generations.flip(), Ok(()));
}

// ---- Packets ----

#[test]
fn a_burst_straddling_a_flip_runs_each_packet_under_its_own_generation() {
    let log = drops();
    let generations = Generations::new(Tag::new(1, &log));
    let mut reader = generations.reader();
    let old = generations.selector().stamp();
    generations.begin(Tag::new(2, &log)).unwrap();
    let _ = reader.live();
    generations.flip().unwrap();
    let new = generations.selector().stamp();
    assert_ne!(old, new);
    // Old, then new, with unstamped packets mixed in, and two stragglers near the flip.
    let stamps = [
        Some(old),
        Some(old),
        None,
        Some(old),
        Some(new),
        Some(old),
        Some(new),
        None,
        Some(new),
        Some(new),
    ];
    let mut packets: Vec<_> = stamps.iter().map(|s| packet(*s)).collect();
    let live = reader.live();
    let seen = run_checked(&mut packets, live.tables());
    assert_eq!(
        seen,
        Seen {
            previous: 4,
            newest: 4,
            stale: 0
        }
    );
}

#[test]
fn a_straggler_after_its_generation_retires_is_stale() {
    let log = drops();
    let generations = Generations::new(Tag::new(1, &log));
    let mut reader = generations.reader();
    let first = generations.selector().stamp();
    for n in 2..=3 {
        generations.begin(Tag::new(n, &log)).unwrap();
        let _ = reader.live();
        generations.flip().unwrap();
        let _ = reader.live();
        reader.idle();
        generations.retire().unwrap();
    }
    // Generation 3 is back in generation 1's bank: only the low bits tell them apart.
    assert_eq!(generations.selector().stamp().bank(), first.bank());
    let mut packets = vec![packet(Some(first)), packet(None), packet(Some(first))];
    let live = reader.live();
    let seen = run_checked(&mut packets, live.tables());
    assert_eq!(seen.stale, 2);
}

#[test]
fn snapshots_are_released_on_the_publisher_thread() {
    let log = drops();
    let publisher = std::thread::current().id();
    {
        let generations = Generations::new(Tag::new(1, &log));
        let reader = generations.reader();
        std::thread::scope(|s| {
            let worker = s.spawn(move || {
                let mut reader = reader;
                for _ in 0..1000 {
                    let _ = reader.live();
                    reader.idle();
                }
            });
            let mut n = 2;
            while !worker.is_finished() {
                if generations.begin(Tag::new(n, &log)).is_ok() {
                    n += 1;
                }
                let _ = generations.flip();
                let _ = generations.retire();
            }
        });
    }
    let log = log.lock();
    assert!(log.len() > 1, "no generation was ever released");
    assert!(
        log.iter().all(|&t| t == publisher),
        "a snapshot dropped on a worker"
    );
}

// ---- Under load ----

/// A small deterministic generator, so that a failing run replays.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % bound
    }
}

/// Sets its flag when dropped: stops workers however the publisher's loop ends.
struct Stop<'a>(&'a AtomicBool);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Workers stamp packets as hardware would (the selector at arrival; some unstamped), queue them
/// as an RX ring does, and run them through the toy graph in bursts of random size, while the
/// publisher cycles through generations as fast as the workers let it. Every packet is checked
/// for I1. Queues are FIFO, so no packet may be stale: the acknowledgement rule must never let a
/// generation retire while a worker still holds its packets.
#[test]
fn generations_cycle_under_load_and_every_packet_runs_under_one() {
    const WORKERS: u64 = 3;
    const GENERATIONS: u64 = 300;
    const RING: usize = 256;
    let deadline = Instant::now() + Duration::from_secs(60);
    let log = drops();
    let generations = Generations::new(Tag::new(1, &log));
    let stop = AtomicBool::new(false);
    let straddled = AtomicU64::new(0);
    let checked = AtomicU64::new(0);
    let readers: Vec<_> = (0..=WORKERS).map(|_| generations.reader()).collect();
    std::thread::scope(|s| {
        let mut readers = readers.into_iter();
        // An idle worker: empty polls only.
        let idle = readers.next().unwrap();
        let stop_ref = &stop;
        s.spawn(move || {
            let mut reader = idle;
            while !stop_ref.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = reader.live();
                reader.idle();
                std::thread::yield_now();
            }
        });
        for (w, reader) in readers.enumerate() {
            let selector = generations.selector();
            let (stop, straddled, checked) = (&stop, &straddled, &checked);
            s.spawn(move || {
                let mut reader = reader;
                let mut rng = Lcg(w as u64 + 1);
                let mut queue: VecDeque<Packet<TestBuffer>> = VecDeque::new();
                let mut spare: Vec<Packet<TestBuffer>> = Vec::new();
                loop {
                    let stopping = stop.load(std::sync::atomic::Ordering::Relaxed);
                    if stopping && queue.is_empty() {
                        break;
                    }
                    if !stopping {
                        // Arrivals: a ring of RING descriptors; the NIC drops what does not fit.
                        for _ in 0..rng.next(32).min((RING - queue.len()) as u64) {
                            let stamp = (rng.next(10) != 0).then(|| selector.stamp());
                            let mut p = spare.pop().unwrap_or_else(|| packet(None));
                            *p.meta_mut() = PacketMeta::default();
                            p.meta_mut().stamp = stamp;
                            queue.push_back(p);
                        }
                    }
                    let take = usize::try_from(rng.next(32) + 1).unwrap().min(queue.len());
                    let mut burst: Vec<_> = queue.drain(..take).collect();
                    let live = reader.live();
                    if burst.is_empty() {
                        reader.idle();
                        continue;
                    }
                    let seen = run_checked(&mut burst, live.tables());
                    assert_eq!(seen.stale, 0, "a FIFO worker saw a stale packet");
                    if seen.previous > 0 && seen.newest > 0 {
                        straddled.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    checked.fetch_add(burst.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    reader.settle(seen);
                    spare.extend(burst);
                }
            });
        }
        // The publisher. Stops the workers however it ends, so a failure here fails the test
        // instead of hanging it.
        let _stop = Stop(&stop);
        for n in 2..=GENERATIONS {
            assert_eq!(generations.begin(Tag::new(n, &log)), Ok(n));
            while generations.flip() == Err(Wait::NotObserved) {
                assert!(Instant::now() < deadline, "a flip never happened");
                std::thread::yield_now();
            }
            while generations.retire() == Err(Wait::NotAcknowledged) {
                assert!(Instant::now() < deadline, "a retire never happened");
                std::thread::yield_now();
            }
        }
    });
    let (straddled, checked) = (
        straddled.load(std::sync::atomic::Ordering::Relaxed),
        checked.load(std::sync::atomic::Ordering::Relaxed),
    );
    eprintln!("checked {checked} packets; {straddled} bursts straddled a flip");
    assert!(straddled > 0, "no burst ever straddled a flip");
    assert_eq!(generations.newest(), GENERATIONS);
    let publisher = std::thread::current().id();
    assert!(log.lock().iter().all(|&t| t == publisher));
}
