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
//! * An address and port is never handed to two live flows drawn from the same allocator. Shapes
//!   that hold every allocation for the length of the run check this exactly; those that free as
//!   they go trade that for exercising deallocation. See [`Live`] for why the two differ.
//! * Neither allocation nor reservation ever reports [`AllocatorError::InternalIssue`]. That is
//!   the allocator saying its own bookkeeping is inconsistent.
//!
//!   A limit worth being honest about: `find_block_for_port` carries a standing `FIXME` wondering
//!   whether the block it just found non-free can be released before it is looked up, and this
//!   suite does not reach that interleaving. Reservations here target survivors, and a survivor's
//!   block is pinned for the whole generation by the reservation [`Published`] holds, so it cannot
//!   disappear mid-lookup. Reaching it would take generations whose specs differ, so that a pair
//!   stops being carried and its block can empty while another thread reserves it; that is the
//!   suite's next extension, not something it does today.
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
    /// Whether flows may end while the run is in progress.
    ///
    /// Freeing is worth exercising, because it is what returns an address to a pool, but it costs
    /// the uniqueness oracle its certainty: see [`Live`]. Half the shapes therefore hold every
    /// allocation for the whole run, which makes the record monotone and the oracle exact.
    frees_allowed: bool,
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
            frees_allowed: driver.produce()?,
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
        let pools =
            pool_sets_for_specs::<Ipv4Addr>(specs, &PrefixPortsSet::new(), NextHeader::TCP, false);
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
                // Nothing may refuse a survivor. Every generation is built from the same specs, so
                // the address is still served; the survivors are distinct pairs; and the allocator
                // is fresh, so nothing else holds them. Accepting failure here would let the model
                // publish generations that quietly carried nothing, and every property about
                // carried pairs would pass vacuously.
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

/// Every address and port currently held by a flow, with the generation it was drawn from.
///
/// Shared by all threads, because a collision between two threads is the interesting one and a
/// per-thread record would not see it. Two allocations from *different* generations may legitimately
/// repeat: only the survivors carried into a new generation are protected there, which is what
/// [`Published::carried`] covers.
///
/// # What this catches, and what it cannot
///
/// The record is written after the allocator has already handed a pair out, so it observes
/// allocation rather than being part of it. That is what keeps the threads racing on the
/// allocator's own locks instead of on this mutex, and it costs the oracle something once a pair
/// can be freed: if two threads are wrongly given the same pair and the first releases it before
/// the second records it, the second insertion succeeds and the duplicate goes unseen. That
/// interleaving is *indistinguishable* from one thread legitimately reusing what another gave
/// back, so no record kept at these two points can tell them apart.
///
/// The way out is to leave nothing to give back: when [`Scenario::frees_allowed`] is false no
/// allocation is released for the length of the run, the record only grows, and a duplicate is
/// caught with certainty. Roughly half the generated shapes are of that kind. The rest trade that
/// certainty for exercising deallocation, and still catch every duplicate whose holders overlap in
/// the record, which is the common case.
///
/// Closing the gap outright would take instrumenting the allocator itself, so that a pair is
/// recorded as part of being handed out rather than just after.
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
            .map(|ranges| PoolSpec {
                public_ranges: ranges
                    .iter()
                    .map(|&(offset, length)| {
                        let start = u128::from(offset);
                        let end = (start + u128::from(length) - 1).min(WINDOW - 1);
                        AddrInterval::new(BASE + start, BASE + end)
                    })
                    .collect(),
                idle_timeout: IDLE_TIMEOUT,
            })
            .collect()
    }

    /// Run the scenario: stand up a first generation with a few flows already on it, then let the
    /// packet threads and the config thread work against the published slot concurrently.
    fn run(&self) {
        let specs = self.specs();

        // The flows that already exist when the config change arrives.
        let initial =
            pool_sets_for_specs::<Ipv4Addr>(&specs, &PrefixPortsSet::new(), NextHeader::TCP, false);
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

/// Returns whatever the thread is still holding when its ops run out, rather than releasing it.
///
/// Releasing here would free addresses while other threads are still allocating, which is exactly
/// the ambiguity [`Live`] cannot see through, and it is not needed to keep the record honest: the
/// pairs stay held, so nothing else can legitimately be given them.
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
                // Race a reservation against the other threads' allocations on pools that are
                // already published and in use.
                //
                // Every survivor is carried into every generation -- the builder panics otherwise
                // -- so in a correct allocator this reservation is always refused: the writer's
                // own reservation holds the pair. The refusal is the same rule as for allocation,
                // checked on the path a config change actually takes, and the success arm below is
                // an oracle rather than a covered path: it can only run if a bug lets a held pair
                // be reserved twice, and then it must not be dropped here, or the port would go
                // back to the pools mid-run and the other oracles would be reasoning over a lie.
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

/// Printing the allocator races the last flow on an address ending.
///
/// The pool holds weak references to the addresses in use, and printing upgrades each one while
/// the pool's read guard is held. An address whose last block is released at that moment leaves
/// the upgrade taken for printing as the only strong reference, and dropping it runs
/// `AllocatedIp::drop` on the printing thread, which takes the same lock for writing.
///
/// This is the same self-deadlock the allocation paths guard against, reached from the management
/// side: `NatAllocator` is a `CliSource`, so the table is formatted on a thread of its own while
/// packet threads keep ending flows. A wedged read guard takes the pool with it.
///
/// Shuttle names it directly -- "tried to acquire a `RwLock` it already holds" -- so the
/// assertion is the run completing at all.
#[concurrency::model_test]
fn printing_the_pool_does_not_wedge_it_against_a_flow_ending() {
    concurrency::stress(|| {
        let specs = vec![PoolSpec {
            // One address, so the flow that ends is the last holder of the one being printed.
            public_ranges: vec![AddrInterval::new(BASE, BASE)],
            idle_timeout: IDLE_TIMEOUT,
        }];
        let pools = Arc::new(pool_sets_for_specs::<Ipv4Addr>(
            &specs,
            &PrefixPortsSet::new(),
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
