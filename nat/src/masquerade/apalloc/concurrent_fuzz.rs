// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Concurrent property tests for masquerade allocator replacement.
//!
//! Bolero generates ranges and per-thread operations; `concurrency::stress` explores each fixed
//! scenario. Packet threads allocate from the published generation while a writer re-reserves
//! surviving tuples in a replacement and publishes it.
//!
//! The suite checks that live and carried tuples remain unique and that contention never produces
//! [`AllocatorError::InternalIssue`]. Some scenarios retain every allocation for an exact
//! uniqueness oracle; others exercise release paths.
//!
//! Loom is excluded because its `Weak` shim keeps liveness entries alive. The suite uses
//! `model_test` because it invokes `stress` inside Bolero's outer loop.

#![cfg(test)]
#![cfg(not(feature = "loom"))]

use super::AllocatedPort;
use super::alloc::PoolSet;
use super::region::AddrInterval;
use super::setup::{PoolSpec, pool_sets_for_specs};
use crate::masquerade::allocation::AllocatorError;
use crate::port::NatPort;
use concurrency::slot::SlotOption;
use concurrency::sync::{Arc, Mutex};
use concurrency::thread;
// `spawn_scoped` is inherent on std's `Builder`, but supplied by `BuilderExt` under shuttle
#[cfg_attr(not(feature = "shuttle"), allow(unused_imports))]
use concurrency::thread::BuilderExt;
use net::ip::NextHeader;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::time::Duration;

// 10.1.0.0, over a window narrow enough that generated ranges overlap most of the time and the
// pools stay cheap to build once per published generation.
const BASE: u128 = 0x0A01_0000;
const WINDOW: u128 = 8;
const MAX_EXPOSES: u8 = 3;
const MAX_RANGE_LEN: u8 = 4;

// Op streams are kept short: the backend explores interleavings of a fixed shape, so length costs
// schedule space without buying coverage.
const MAX_PACKET_OPS: usize = 6;
const MAX_CONFIG_OPS: usize = 3;
const PACKET_WORKERS: usize = 2;

const IDLE_TIMEOUT: Duration = Duration::from_mins(2);

/// What a packet thread does. Allocating and freeing model flows starting and ending; reserving
/// models a flow being carried over, and is the op that races reservation against allocation on
/// pools that are already published and in use.
#[derive(Clone, Copy, Debug, bolero::TypeGenerator)]
enum PacketOp {
    Allocate,
    FreeOldest,
    ReserveExisting,
}

/// What the config thread does. Production has a single writer, so only this thread republishes.
#[derive(Clone, Copy, Debug, bolero::TypeGenerator)]
enum ConfigOp {
    Republish,
    Idle,
}

/// One generated shape: the public ranges each expose claims, and an op stream per thread.
#[derive(Clone, Debug)]
struct Scenario {
    ranges: Vec<Vec<(u8, u8)>>,
    packet_ops: [Vec<PacketOp>; PACKET_WORKERS],
    config_ops: Vec<ConfigOp>,
    /// Whether this scenario exercises release paths instead of an exact monotone oracle.
    frees_allowed: bool,
}

impl bolero::TypeGenerator for Scenario {
    /// Ensure every generated shape has concurrent packet and configuration work.
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        let expose_count = usize::from(driver.produce::<u8>()? % MAX_EXPOSES + 1);
        let mut ranges = Vec::with_capacity(expose_count);
        for _ in 0..expose_count {
            let offset = driver.produce::<u8>()? % u8::try_from(WINDOW).ok()?;
            let length = driver.produce::<u8>()? % MAX_RANGE_LEN + 1;
            ranges.push(vec![(offset, length)]);
        }

        let mut packet_ops: [Vec<PacketOp>; PACKET_WORKERS] = driver.produce()?;
        for ops in &mut packet_ops {
            ops.truncate(MAX_PACKET_OPS);
            if !ops.iter().any(|op| matches!(op, PacketOp::Allocate)) {
                let at = driver.produce::<usize>()? % (ops.len() + 1);
                ops.insert(at, PacketOp::Allocate);
            }
        }

        let mut config_ops: Vec<ConfigOp> = driver.produce()?;
        config_ops.truncate(MAX_CONFIG_OPS);
        if !config_ops
            .iter()
            .any(|op| matches!(op, ConfigOp::Republish))
        {
            let at = driver.produce::<usize>()? % (config_ops.len() + 1);
            config_ops.insert(at, ConfigOp::Republish);
        }

        Some(Self {
            ranges,
            packet_ops,
            config_ops,
            frees_allowed: driver.produce()?,
        })
    }
}

/// A published generation and the reservations carried into it.
struct Published {
    generation: u64,
    pools: Vec<PoolSet<Ipv4Addr>>,
    carried: BTreeSet<(Ipv4Addr, u16)>,
    _reservations: Vec<AllocatedPort<Ipv4Addr>>,
}

impl Published {
    /// Build a generation and reserve its surviving tuples before publication.
    fn build(
        specs: &[PoolSpec],
        generation: u64,
        survivors: &[(usize, Ipv4Addr, NatPort)],
    ) -> Self {
        let pools = pool_sets_for_specs::<Ipv4Addr>(specs, NextHeader::TCP, false);
        let mut carried = BTreeSet::new();
        let mut reservations = Vec::new();

        for &(owner, ip, port) in survivors {
            let Some(pool) = pools.get(owner) else {
                continue;
            };
            match pool.reserve(ip, port) {
                Ok(reservation) => {
                    carried.insert((ip, port.as_u16()));
                    reservations.push(reservation);
                }
                // Same-spec replacement allocators must accept every survivor.
                Err(e) => {
                    panic!("re-reserving {ip}:{port} for generation {generation} failed: {e}")
                }
            }
        }

        Self {
            generation,
            pools,
            carried,
            _reservations: reservations,
        }
    }
}

/// Live tuples, keyed by generation.
///
/// Recording happens after allocation, so release scenarios cannot distinguish a hidden duplicate
/// from legitimate reuse. Scenarios that disable releases provide the exact oracle.
struct Live(Mutex<BTreeSet<(u64, Ipv4Addr, u16)>>);

impl Live {
    fn new() -> Self {
        Self(Mutex::new(BTreeSet::new()))
    }

    /// Record a freshly allocated pair, failing if it is already held.
    fn claim(&self, generation: u64, ip: Ipv4Addr, port: u16) {
        let mut live = self.0.lock();
        assert!(
            live.insert((generation, ip, port)),
            "generation {generation} handed out {ip}:{port} to two flows at once"
        );
    }

    /// Give a pair back, freeing it while the record is still locked so that no other thread can
    /// claim it before the allocator has actually released it.
    fn release(&self, generation: u64, allocation: AllocatedPort<Ipv4Addr>) {
        let mut live = self.0.lock();
        live.remove(&(generation, allocation.ip(), allocation.port().as_u16()));
        drop(allocation);
    }
}

impl Scenario {
    fn specs(&self) -> Vec<PoolSpec> {
        self.ranges
            .iter()
            .map(|ranges| {
                PoolSpec::new(
                    ranges
                        .iter()
                        .map(|&(offset, length)| {
                            let start = u128::from(offset);
                            let end = (start + u128::from(length) - 1).min(WINDOW - 1);
                            AddrInterval::new(BASE + start, BASE + end)
                        })
                        .collect(),
                    IDLE_TIMEOUT,
                )
            })
            .collect()
    }

    /// Race packet workers against allocator publication.
    fn run(&self) {
        let specs = self.specs();

        // The flows that already exist when the config change arrives.
        let initial = pool_sets_for_specs::<Ipv4Addr>(&specs, NextHeader::TCP, false);
        let mut existing = Vec::new();
        let mut survivors = Vec::new();
        for (owner, pool) in initial.iter().enumerate() {
            if let Ok(allocation) = pool.allocate(false) {
                survivors.push((owner, allocation.ip(), allocation.port()));
                existing.push(allocation);
            }
        }

        let slot = Arc::new(SlotOption::new(Some(Arc::new(Published::build(
            &specs, 0, &survivors,
        )))));
        let live = Arc::new(Live::new());

        thread::scope(|scope| {
            let mut packet_handles = Vec::new();

            for (index, ops) in self.packet_ops.iter().enumerate() {
                let slot = slot.clone();
                let live = live.clone();
                let ops = ops.clone();
                let survivors = survivors.clone();
                let frees_allowed = self.frees_allowed;
                packet_handles.push(
                    thread::Builder::new()
                        .name(format!("packet-{index}"))
                        .spawn_scoped(scope, move || {
                            packet_worker(&slot, &live, &ops, &survivors, frees_allowed)
                        })
                        .expect("spawn packet worker"),
                );
            }

            let config_handle = {
                let slot = slot.clone();
                let ops = self.config_ops.clone();
                let specs = specs.clone();
                let survivors = survivors.clone();
                thread::Builder::new()
                    .name("config".to_string())
                    .spawn_scoped(scope, move || {
                        let mut generation = 0u64;
                        for op in ops {
                            match op {
                                ConfigOp::Republish => {
                                    generation += 1;
                                    let next = Published::build(&specs, generation, &survivors);
                                    slot.store(Some(Arc::new(next)));
                                }
                                ConfigOp::Idle => {}
                            }
                            thread::yield_now();
                        }
                    })
                    .expect("spawn config worker")
            };

            // Collect rather than drop: an allocation released while another thread is still
            // allocating is one the record cannot reason about, so everything stays held until
            // every thread has finished.
            let leftovers: Vec<_> = packet_handles
                .into_iter()
                .map(|handle| handle.join().expect("packet worker panicked"))
                .collect();
            config_handle.join().expect("config worker panicked");
            drop(leftovers);
        });

        drop(existing);
    }
}

/// Return remaining allocations so they stay live until all workers finish.
fn packet_worker(
    slot: &SlotOption<Published>,
    live: &Live,
    ops: &[PacketOp],
    survivors: &[(usize, Ipv4Addr, NatPort)],
    frees_allowed: bool,
) -> Vec<(u64, AllocatedPort<Ipv4Addr>)> {
    // What this thread is holding, tagged with the generation it was drawn from.
    let mut held: Vec<(u64, AllocatedPort<Ipv4Addr>)> = Vec::new();

    for (step, op) in ops.iter().enumerate() {
        let published = slot.load_full().expect("pools are always published");

        match op {
            PacketOp::Allocate => {
                if published.pools.is_empty() {
                    continue;
                }
                let owner = step % published.pools.len();
                match published.pools[owner].allocate(false) {
                    Ok(allocation) => {
                        let pair = (allocation.ip(), allocation.port().as_u16());

                        // The writer re-reserved every survivor before publishing, so a new flow
                        // must never be handed what a carried-over flow still holds.
                        assert!(
                            !published.carried.contains(&pair),
                            "generation {} handed out {}:{}, which a carried-over flow holds",
                            published.generation,
                            pair.0,
                            pair.1
                        );

                        live.claim(published.generation, pair.0, pair.1);
                        held.push((published.generation, allocation));
                    }
                    Err(AllocatorError::InternalIssue(message)) => {
                        panic!(
                            "allocating from generation {}: {message}",
                            published.generation
                        )
                    }
                    // Running out of addresses or ports is a legitimate outcome.
                    Err(_) => {}
                }
            }
            PacketOp::FreeOldest => {
                if frees_allowed && !held.is_empty() {
                    let (generation, allocation) = held.remove(0);
                    live.release(generation, allocation);
                }
            }
            PacketOp::ReserveExisting => {
                // A carried tuple must stay unavailable. Hold unexpected successes so the model's
                // live set remains accurate.
                if let Some(&(owner, ip, port)) = survivors.get(step % survivors.len().max(1))
                    && let Some(pool) = published.pools.get(owner)
                {
                    let carried = published.carried.contains(&(ip, port.as_u16()));
                    match pool.reserve(ip, port) {
                        Ok(reservation) => {
                            assert!(
                                !carried,
                                "generation {} reserved {ip}:{port} a second time, although a \
                                 carried-over flow already holds it",
                                published.generation
                            );
                            live.claim(published.generation, ip, port.as_u16());
                            held.push((published.generation, reservation));
                        }
                        Err(AllocatorError::InternalIssue(message)) => panic!(
                            "reserving {ip}:{port} in generation {}: {message}",
                            published.generation
                        ),
                        // Refused because it is held, which is the ordinary outcome here.
                        Err(_) => {}
                    }
                }
            }
        }

        // Give the model checker a preemption point between ops; a cheap hint under std.
        thread::yield_now();
    }

    held
}

#[concurrency::model_test]
fn stress_test_config_change() {
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|scenario: Scenario| {
            concurrency::stress(move || {
                scenario.run();
            });
        });
}

/// Formatting must not drop the last address reference while holding the pool's read lock.
#[concurrency::model_test]
fn printing_the_pool_does_not_wedge_it_against_a_flow_ending() {
    concurrency::stress(|| {
        // One address, so the flow that ends is the last holder of the one being printed.
        let specs = vec![PoolSpec::new(
            vec![AddrInterval::new(BASE, BASE)],
            IDLE_TIMEOUT,
        )];
        let pools = Arc::new(pool_sets_for_specs::<Ipv4Addr>(
            &specs,
            NextHeader::TCP,
            false,
        ));

        let allocation = pools[0].allocate(false).expect("the pool can serve");

        let releaser = thread::spawn(move || drop(allocation));
        let printer = {
            let pools = pools.clone();
            thread::spawn(move || {
                let _ = format!("{}", pools[0]);
            })
        };

        printer.join().expect("the printing thread panicked");
        releaser.join().expect("the releasing thread panicked");
    });
}

/// A reservation racing a block release is contention, not corrupt state.
#[concurrency::model_test]
fn reservation_racing_block_release_is_not_an_internal_error() {
    concurrency::stress(|| {
        let specs = vec![PoolSpec::new(
            vec![AddrInterval::new(BASE, BASE)],
            IDLE_TIMEOUT,
        )];
        let pools = Arc::new(pool_sets_for_specs::<Ipv4Addr>(
            &specs,
            NextHeader::TCP,
            false,
        ));

        let allocation = pools[0].allocate(false).expect("the pool can serve");
        let (ip, port) = (allocation.ip(), allocation.port());

        let releaser = thread::spawn(move || drop(allocation));
        let reserver = {
            let pools = pools.clone();
            thread::spawn(move || pools[0].reserve(ip, port))
        };

        let outcome = reserver.join().expect("the reserving thread panicked");
        releaser.join().expect("the releasing thread panicked");

        if let Err(AllocatorError::InternalIssue(message)) = &outcome {
            panic!("a reservation racing the release of its block was called a bug: {message}");
        }
    });
}

/// An expired weak entry must not erase a block inserted at the same index.
#[concurrency::model_test]
fn tidying_a_dead_block_entry_does_not_drop_a_live_one() {
    concurrency::stress(|| {
        let address = Ipv4Addr::from(u32::try_from(BASE).unwrap_or_else(|_| unreachable!()));
        let specs = vec![PoolSpec::new(
            vec![AddrInterval::new(BASE, BASE)],
            IDLE_TIMEOUT,
        )];
        let pools = Arc::new(pool_sets_for_specs::<Ipv4Addr>(
            &specs,
            NextHeader::TCP,
            false,
        ));

        let keeper_port = NatPort::new_port_checked(1024).unwrap_or_else(|_| unreachable!());
        let _keeper = pools[0]
            .reserve(address, keeper_port)
            .expect("the keeper reservation");
        // This opens the next block and leaves a stale per-thread hint when dropped.
        drop(pools[0].allocate(false).expect("the second block"));

        let holder = {
            let pools = pools.clone();
            thread::spawn(move || pools[0].allocate(false).ok())
        };
        let mine = pools[0].allocate(false).ok();
        let theirs = holder.join().expect("the other task panicked");

        if mine.is_some() || theirs.is_some() {
            let port = NatPort::new_port_checked(1400).unwrap_or_else(|_| unreachable!());
            let outcome = pools[0].reserve(address, port);
            assert!(
                outcome.is_ok(),
                "a block in use was dropped from the list: reserving into it gave {outcome:?}"
            );
        }
    });
}
