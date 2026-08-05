// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Concurrent fuzz test for the masquerade pools across a config change.
//!
//! One test, [`stress_test_config_change`], drives a bolero-generated [`Scenario`] through
//! [`concurrency::stress`] on every backend, mirroring the bolero x model-checker layout used for
//! the flow table (see `flow-entry/src/flow_table/concurrent_fuzz.rs`). bolero is the *outer* loop
//! and picks the shape: which public ranges the exposes claim, and an op stream per thread. The
//! backend is the *inner* loop and explores interleavings of that fixed shape:
//!
//! * **default (std) backend** — one direct run on real OS threads. Build with
//!   `just test sanitize=thread` to surface data races inside the allocator.
//! * **`--features shuttle`** — the full portfolio (Random + PCT [+ DFS]).
//!
//! # What is being raced
//!
//! Applying a new masquerade config is not atomic from the data plane's point of view. The writer
//! builds a fresh allocator, carries the surviving flows over into it by re-reserving the address
//! and port each one holds, and only then publishes it; meanwhile packet threads keep allocating
//! from whichever allocator is currently published. Every lock and atomic the allocator uses comes
//! from `concurrency::sync`, so a model checker sees all of it: the `compare_exchange` that claims
//! a port block, the map of weak references to allocated blocks, the per-thread block hint, and
//! the pool locks.
//!
//! Three properties are asserted:
//!
//! * A published allocator never hands out an address and port that was carried over into it. This
//!   is the safety property of the update: the writer re-reserves before publishing, so a flow that
//!   survived a config change and a flow created just after it must not collide on the reverse key.
//! * An address and port is never handed to two live flows drawn from the same allocator.
//! * Neither allocation nor reservation ever reports [`AllocatorError::InternalIssue`]. That is the
//!   allocator saying its own bookkeeping is inconsistent, and `find_block_for_port` carries a
//!   standing `FIXME` wondering whether the block it just found non-free can be released before it
//!   is looked up. Reserving concurrently with allocating is what would show it.
//!
//! # No loom
//!
//! Gated off under loom, for the same reason `test_alloc`'s concurrency tests are: loom's `Weak`
//! shim never lets an allocator liveness entry die, so the pool's in-use list never drains and the
//! run does not model what production does. Shuttle has no such limitation.
//!
//! # Why `#[concurrency::model_test]`
//!
//! `just features=shuttle test` filters the run down to test names containing `shuttle`, because
//! under that backend `concurrency::sync` types are shuttle primitives and every other test in the
//! workspace would fail spuriously on `ExecutionState NotSet`. `#[concurrency::test]` earns its
//! way past that filter by appending a `concurrency_model::shuttle` leaf, but it also wraps the
//! whole body in [`concurrency::stress`], which is the wrong shape here: bolero has to be the outer
//! loop, so `stress` is called once per generated shape from inside it.
//! [`macro@concurrency::model_test`] emits the same backend-named leaf and leaves the body alone,
//! which is what lets this suite be selected at all.

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
use lpm::prefix::PrefixPortsSet;
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
}

impl bolero::TypeGenerator for Scenario {
    /// Generate a shape, then normalize it so the run always exercises real concurrency.
    ///
    /// shuttle's PCT scheduler panics on a body in which two threads are never simultaneously
    /// runnable. Rather than skip degenerate shapes, every packet stream is given an `Allocate` if
    /// it has none, and the config stream a `Republish`. The splice position comes from the driver,
    /// so the normalization stays a deterministic function of the input and a failure still
    /// reproduces from its seed.
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
        })
    }
}

/// One generation of published pools, together with the flows carried into it.
///
/// The reservations are held for as long as the generation is published, exactly as a surviving
/// flow holds the allocation it was re-reserved.
struct Published {
    generation: u64,
    pools: Vec<PoolSet<Ipv4Addr>>,
    carried: BTreeSet<(Ipv4Addr, u16)>,
    _reservations: Vec<AllocatedPort<Ipv4Addr>>,
}

impl Published {
    /// Build the pools for a new config and carry the surviving flows into them before returning,
    /// so that a generation is only ever published once its survivors hold their addresses again.
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
                Err(AllocatorError::InternalIssue(message)) => {
                    panic!("re-reserving {ip}:{port} for generation {generation}: {message}")
                }
                // The address may no longer be served, or another survivor may already hold it.
                Err(_) => {}
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

/// Every address and port currently held by a flow, with the generation it was drawn from.
///
/// Shared by all threads, because a collision between two threads is the interesting one and a
/// per-thread record would not see it. Two allocations from *different* generations may legitimately
/// repeat: only the survivors carried into a new generation are protected there, which is what
/// [`Published::carried`] covers.
struct Live(Mutex<BTreeSet<(u64, Ipv4Addr, u16)>>);

impl Live {
    fn new() -> Self {
        Self(Mutex::new(BTreeSet::new()))
    }

    /// Record a freshly allocated pair. The allocation already exists by the time this runs, so a
    /// thread that raced us to the same pair has either recorded it already or is about to fail
    /// here itself; either way the collision is caught.
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
            .map(|ranges| PoolSpec {
                public_ranges: ranges
                    .iter()
                    .map(|&(offset, length)| {
                        let start = u128::from(offset);
                        let end = (start + u128::from(length) - 1).min(WINDOW - 1);
                        AddrInterval::new(BASE + start, BASE + end)
                    })
                    .collect(),
                reserved: PrefixPortsSet::new(),
                idle_timeout: IDLE_TIMEOUT,
            })
            .collect()
    }

    /// Run the scenario: stand up a first generation with a few flows already on it, then let the
    /// packet threads and the config thread work against the published slot concurrently.
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
            let mut handles = Vec::new();

            for (index, ops) in self.packet_ops.iter().enumerate() {
                let slot = slot.clone();
                let live = live.clone();
                let ops = ops.clone();
                let survivors = survivors.clone();
                handles.push(
                    thread::Builder::new()
                        .name(format!("packet-{index}"))
                        .spawn_scoped(scope, move || {
                            packet_worker(&slot, &live, &ops, &survivors);
                        })
                        .expect("spawn packet worker"),
                );
            }

            {
                let slot = slot.clone();
                let ops = self.config_ops.clone();
                let specs = specs.clone();
                let survivors = survivors.clone();
                handles.push(
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
                        .expect("spawn config worker"),
                );
            }

            for handle in handles {
                handle.join().expect("worker panicked");
            }
        });

        drop(existing);
    }
}

fn packet_worker(
    slot: &SlotOption<Published>,
    live: &Live,
    ops: &[PacketOp],
    survivors: &[(usize, Ipv4Addr, NatPort)],
) {
    // What this thread is holding, tagged with the generation it was drawn from.
    let mut held: Vec<(u64, AllocatedPort<Ipv4Addr>)> = Vec::new();

    for (step, op) in ops.iter().enumerate() {
        let published = slot.load_full().expect("pools are always published");

        match op {
            PacketOp::Allocate => {
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
                if !held.is_empty() {
                    let (generation, allocation) = held.remove(0);
                    live.release(generation, allocation);
                }
            }
            PacketOp::ReserveExisting => {
                // Race a reservation against the other threads' allocations on pools that are
                // already published and in use. Failing is fine, claiming inconsistent bookkeeping
                // is not.
                if let Some(&(owner, ip, port)) = survivors.get(step % survivors.len().max(1))
                    && let Some(pool) = published.pools.get(owner)
                    && let Err(AllocatorError::InternalIssue(message)) = pool.reserve(ip, port)
                {
                    panic!(
                        "reserving {ip}:{port} in generation {}: {message}",
                        published.generation
                    );
                }
            }
        }

        // Give the model checker a preemption point between ops; a cheap hint under std.
        thread::yield_now();
    }

    // Give everything back through the record, so a thread that finishes early cannot leave
    // entries behind and make a later, legitimate allocation look like a collision.
    for (generation, allocation) in held {
        live.release(generation, allocation);
    }
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
