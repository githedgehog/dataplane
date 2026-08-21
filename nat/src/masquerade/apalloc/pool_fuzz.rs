// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Property tests for pools built over overlapping public ranges.
//!
//! Generated ranges come from a narrow window so overlap is common. The properties require unique
//! live tuples, allocations within each expose's ranges, and safe carry-over between generations.

#![cfg(test)]

use super::alloc::{NatPool, PoolSet, Tenancy, map_address};
use super::region::AddrInterval;
use super::reserved::ReservedPorts;
use super::setup::{PoolSpec, pool_sets_for_specs};
use crate::masquerade::allocation::AllocatorError;
use crate::port::NatPort;
use bolero::{Driver, TypeGenerator};
use concurrency::sync::{Arc, mpsc};
use lpm::prefix::{PortRange, PrefixPortsSet, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::Duration;

// 10.1.0.0, with a window small enough that regions stay cheap to build.
const BASE: u128 = 0x0A01_0000;
const WINDOW: u128 = 16;
const MAX_OWNERS: u8 = 4;
const MAX_RANGES_PER_OWNER: u8 = 2;
const MAX_RANGE_LEN: u8 = 8;
// Enough allocations for several exposes to be served repeatedly out of any shared region.
const ALLOCATIONS: usize = 24;

const IDLE_TIMEOUT: Duration = Duration::from_mins(2);

/// One generated configuration: for each expose, the public ranges it masquerades onto.
#[derive(Debug, Clone)]
struct Config {
    owners: Vec<Vec<(u8, u8)>>,
}

impl TypeGenerator for Config {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let owner_count = usize::from(driver.produce::<u8>()? % MAX_OWNERS + 1);
        let mut owners = Vec::with_capacity(owner_count);
        for _ in 0..owner_count {
            let range_count = usize::from(driver.produce::<u8>()? % MAX_RANGES_PER_OWNER + 1);
            let mut ranges = Vec::with_capacity(range_count);
            for _ in 0..range_count {
                let offset = driver.produce::<u8>()? % u8::try_from(WINDOW).ok()?;
                let length = driver.produce::<u8>()? % MAX_RANGE_LEN + 1;
                ranges.push((offset, length));
            }
            owners.push(ranges);
        }
        Some(Self { owners })
    }
}

impl Config {
    fn owner_ranges(&self) -> Vec<Vec<AddrInterval>> {
        self.owners
            .iter()
            .map(|ranges| {
                ranges
                    .iter()
                    .map(|&(offset, length)| {
                        let start = u128::from(offset);
                        let end = (start + u128::from(length) - 1).min(WINDOW - 1);
                        AddrInterval::new(BASE + start, BASE + end)
                    })
                    .collect()
            })
            .collect()
    }

    fn specs(&self) -> Vec<PoolSpec> {
        self.owner_ranges()
            .into_iter()
            .map(|public_ranges| PoolSpec::new(public_ranges, IDLE_TIMEOUT))
            .collect()
    }

    fn pool_sets(&self) -> Vec<PoolSet<Ipv4Addr>> {
        // No randomization: a failure has to reproduce from its seed alone.
        pool_sets_for_specs::<Ipv4Addr>(&self.specs(), NextHeader::TCP, false)
    }

    fn owner_count(&self) -> usize {
        self.owners.len()
    }
}

fn bits(ip: Ipv4Addr) -> u128 {
    u128::from(ip.to_bits())
}

fn declares(ranges: &[AddrInterval], ip: Ipv4Addr) -> bool {
    ranges.iter().any(|range| range.contains(bits(ip)))
}

/// Allocate round-robin across the exposes, holding every allocation so nothing is freed and
/// reused mid-run. Returns which expose got what.
fn allocate_round_robin(
    pool_sets: &[PoolSet<Ipv4Addr>],
    count: usize,
) -> Vec<(usize, super::AllocatedPort<Ipv4Addr>)> {
    let mut held = Vec::new();
    for step in 0..count {
        let owner = step % pool_sets.len();
        if let Ok(allocation) = pool_sets[owner].allocate(false) {
            held.push((owner, allocation));
        }
    }
    held
}

#[test]
fn allocations_are_unique_and_within_the_declared_ranges() {
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|config: Config| {
            let ranges = config.owner_ranges();
            let pool_sets = config.pool_sets();
            assert_eq!(pool_sets.len(), config.owner_count());

            let mut seen = BTreeSet::new();
            for (owner, allocation) in allocate_round_robin(&pool_sets, ALLOCATIONS) {
                let ip = allocation.ip();
                let port = allocation.port().as_u16();

                // Two live flows may not share a public address and port, whichever exposes they
                // belong to: their reverse flow keys would be identical and return traffic for one
                // would be delivered to the other.
                assert!(
                    seen.insert((ip, port)),
                    "{ip}:{port} was handed out twice, the second time to expose {owner}"
                );

                // An expose may only be given an address it declares, however the space was cut.
                assert!(
                    declares(&ranges[owner], ip),
                    "expose {owner} was given {ip}, which is outside the ranges it declares"
                );

                // TCP pools keep off the IANA system range.
                assert!(port >= 1024, "{ip}:{port} is in the well-known port range");
            }
        });
}

#[test]
fn freed_allocations_become_available_again() {
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|config: Config| {
            let pool_sets = config.pool_sets();

            let first = allocate_round_robin(&pool_sets, ALLOCATIONS);
            let taken: BTreeSet<_> = first
                .iter()
                .map(|(_, allocation)| (allocation.ip(), allocation.port().as_u16()))
                .collect();
            assert!(!taken.is_empty(), "a config with ranges allocated nothing");
            drop(first);

            // Everything was released, so the same space must be servable again. Values need not
            // repeat, but the pools must not have leaked capacity.
            let second = allocate_round_robin(&pool_sets, ALLOCATIONS);
            assert_eq!(
                second.len(),
                taken.len(),
                "the pools served fewer allocations after everything was freed"
            );
        });
}

#[test]
fn a_port_freed_while_neighbours_are_held_is_reused() {
    let specs = vec![PoolSpec::new(
        vec![AddrInterval::new(BASE, BASE)],
        IDLE_TIMEOUT,
    )];
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, NextHeader::TCP, false);

    let mut held: Vec<_> = (0..5)
        .map(|_| pool_sets[0].allocate(false).expect("pool has room"))
        .collect();

    let returned = held.remove(2);
    let tuple = (returned.ip(), returned.port().as_u16());
    drop(returned);

    let next = pool_sets[0].allocate(false).expect("pool has room");
    assert_eq!((next.ip(), next.port().as_u16()), tuple);
}

/// A tuple accepted during carry-over must not be allocated to a new flow.
#[test]
fn re_reservation_after_a_config_change_is_honoured() {
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|(before, after): (Config, Config)| {
            let before_pools = before.pool_sets();
            let held = allocate_round_robin(&before_pools, ALLOCATIONS);

            let after_ranges = after.owner_ranges();
            let after_pools = after.pool_sets();

            // Carry each flow over to the new pools, where the new config still has an expose for
            // it. Flows whose expose is gone would be invalidated instead.
            let mut carried = Vec::new();
            let mut reserved = BTreeSet::new();
            for (owner, allocation) in &held {
                let Some(pool_set) = after_pools.get(*owner) else {
                    continue;
                };
                let ip = allocation.ip();
                let port = allocation.port();
                match pool_set.reserve(ip, port) {
                    Ok(reservation) => {
                        // Accepting an address means the expose really does declare it under the
                        // new config; nothing may be carried over into space it no longer holds.
                        assert!(
                            declares(&after_ranges[*owner], ip),
                            "expose {owner} kept {ip}, which its new config does not declare"
                        );
                        assert!(
                            reserved.insert((ip, port.as_u16())),
                            "{ip}:{port} was reserved twice across exposes"
                        );
                        carried.push(reservation);
                    }
                    Err(AllocatorError::NoPoolFound) => {
                        // The new config dropped that address, so the flow cannot be carried over.
                        assert!(
                            !declares(&after_ranges[*owner], ip),
                            "expose {owner} was refused {ip}, which its new config declares"
                        );
                    }
                    Err(_) => {}
                }
            }

            // New flows arriving under the new config must not be given anything a carried-over
            // flow is still using.
            for (_, allocation) in allocate_round_robin(&after_pools, ALLOCATIONS) {
                let pair = (allocation.ip(), allocation.port().as_u16());
                assert!(
                    !reserved.contains(&pair),
                    "{}:{} was allocated although a carried-over flow holds it",
                    pair.0,
                    pair.1
                );
            }

            drop(carried);
        });
}

#[test]
#[cfg_attr(miri, ignore = "exhaustive allocator walk is too slow under miri")]
fn a_region_can_be_allocated_dry() {
    const PORTS_PER_ADDRESS: usize = 65536 - 1024;
    const ADDRESSES: usize = 2;

    let specs = vec![PoolSpec::new(
        vec![AddrInterval::new(BASE, BASE + ADDRESSES as u128 - 1)],
        IDLE_TIMEOUT,
    )];
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, NextHeader::TCP, false);

    let first = Ipv4Addr::from(u32::try_from(BASE).unwrap_or_else(|_| unreachable!()));
    let mut held = Vec::new();
    let mut seen = BTreeSet::new();
    let mut moved_at = None;

    while let Ok(allocation) = pool_sets[0].allocate(false) {
        let tuple = (allocation.ip(), allocation.port().as_u16());
        assert!(tuple.1 >= 1024);
        assert!(
            seen.insert(tuple),
            "{}:{} was handed out twice",
            tuple.0,
            tuple.1
        );
        if tuple.0 != first && moved_at.is_none() {
            moved_at = Some(held.len());
        }
        held.push(allocation);
        assert!(held.len() <= ADDRESSES * PORTS_PER_ADDRESS);
    }

    assert_eq!(moved_at, Some(PORTS_PER_ADDRESS));
    assert_eq!(held.len(), ADDRESSES * PORTS_PER_ADDRESS);

    drop(held);
    assert!(pool_sets[0].allocate(false).is_ok());
}

#[test]
#[cfg_attr(miri, ignore = "exhaustive allocator walk is too slow under miri")]
fn a_freed_port_block_is_reused_while_its_address_is_held() {
    const PORTS_PER_BLOCK: usize = 256;
    const PORTS_PER_ADDRESS: usize = 65536 - 1024;

    let specs = vec![PoolSpec::new(
        vec![AddrInterval::new(BASE, BASE)],
        IDLE_TIMEOUT,
    )];
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, NextHeader::TCP, false);

    let mut held = Vec::with_capacity(PORTS_PER_ADDRESS);
    while let Ok(allocation) = pool_sets[0].allocate(false) {
        held.push(allocation);
        assert!(held.len() <= PORTS_PER_ADDRESS);
    }
    assert_eq!(held.len(), PORTS_PER_ADDRESS);

    let freed_block = 1024..=1279u16;
    held.retain(|allocation| !freed_block.contains(&allocation.port().as_u16()));
    assert_eq!(held.len(), PORTS_PER_ADDRESS - PORTS_PER_BLOCK);

    for _ in 0..PORTS_PER_BLOCK {
        let allocation = pool_sets[0]
            .allocate(false)
            .expect("the freed block has room");
        assert!(freed_block.contains(&allocation.port().as_u16()));
        held.push(allocation);
    }
    assert!(pool_sets[0].allocate(false).is_err());
}

/// An address that has run out of port blocks must neither strand the addresses behind it nor be
/// reported as an empty pool.
///
/// Both halves are about the *reason* an allocation fails rather than whether it fails. Ending the
/// scan at an exhausted address would refuse a request that the address behind it could have
/// served; and answering `NoFreeIp` -- which the draw step reports whenever the bitmap is empty --
/// hides why the addresses already in use could not help. The two are not the same operational
/// problem: an empty bitmap wants more addresses, whereas exhausted port blocks want the block
/// allocator looked at, and that distinction is read straight off the log line an operator sees.
///
/// Reaching the state needs a second thread but not a race. Port blocks are handed out per thread,
/// so a block held elsewhere keeps `has_free_ports` true on the first address while this thread can
/// no longer obtain a block of its own on it -- which is what makes every later scan reach that
/// address, fail on it, and have to carry on past it. The handshake makes the arrangement
/// deterministic.
#[test]
#[cfg_attr(miri, ignore = "exhaustive allocator walk is too slow under miri")]
fn an_exhausted_address_neither_strands_its_neighbours_nor_reads_as_an_empty_pool() {
    const PORTS_PER_BLOCK: usize = 256;
    const PORTS_PER_ADDRESS: usize = 65536 - 1024;
    const ADDRESSES: u128 = 2;

    let specs = vec![PoolSpec::new(
        vec![AddrInterval::new(BASE, BASE + ADDRESSES - 1)],
        IDLE_TIMEOUT,
    )];
    let pool_sets = Arc::new(pool_sets_for_specs::<Ipv4Addr>(
        &specs,
        NextHeader::TCP,
        false,
    ));

    // The helper takes a block on the first address and keeps a single port in it. The block is no
    // longer free, but it still has room, so that address never stops reporting free ports.
    let (took_block, block_taken) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let helper_sets = Arc::clone(&pool_sets);
    let helper = thread::spawn(move || {
        let held = helper_sets[0]
            .allocate(false)
            .expect("the first allocation on an empty pool");
        took_block.send(()).expect("the test thread is waiting");
        // A failing test drops the sender; the helper has nothing to add to that diagnosis.
        let _ = released.recv();
        drop(held);
    });
    block_taken.recv().expect("the helper takes a block");

    let ports = usize::try_from(ADDRESSES).unwrap_or_else(|_| unreachable!()) * PORTS_PER_ADDRESS;
    let mut held = Vec::with_capacity(ports - PORTS_PER_BLOCK);
    let outcome = loop {
        match pool_sets[0].allocate(false) {
            Ok(allocation) => held.push(allocation),
            Err(e) => break e,
        }
        // The pool cannot hand out more than it holds. Bounding the walk turns a pool that frees
        // an address it should not into a failure rather than a hang.
        assert!(
            held.len() <= ports,
            "the pool handed out more ports than it has"
        );
    };

    assert_eq!(
        held.len(),
        ports - PORTS_PER_BLOCK,
        "the scan stopped at the exhausted address instead of carrying on past it"
    );
    assert_eq!(
        outcome,
        AllocatorError::NoPortBlock,
        "an address out of port blocks was reported as an empty pool"
    );

    // The exhaustion is transient: the block returns once the helper's last port does.
    release.send(()).expect("the helper is waiting");
    helper.join().expect("the helper thread panicked");
    assert!(
        pool_sets[0].allocate(false).is_ok(),
        "the released block was never handed back"
    );
}

/// The in-use list must not grow as allocations come and go.
///
/// An address is handed back by whichever side reaches the pool first, so the bitmap stays honest
/// with or without the sweep -- but nothing else prunes the list itself. An entry left behind is
/// both dead weight the next scan has to walk and a slot that is never reclaimed, so a long-lived
/// pool serving short-lived flows would grow one entry per flow.
#[test]
fn the_in_use_list_does_not_grow_as_allocations_come_and_go() {
    const ROUNDS: usize = 64;

    let specs = vec![PoolSpec::new(
        vec![AddrInterval::new(BASE, BASE)],
        IDLE_TIMEOUT,
    )];
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, NextHeader::TCP, false);
    let allocator = pool_sets[0]
        .regions()
        .next()
        .expect("one region over one address")
        .allocator();

    for _ in 0..ROUNDS {
        // Taking the pool's only address and releasing it again leaves an entry whose weak
        // reference no longer upgrades.
        drop(pool_sets[0].allocate(false).expect("the pool has room"));
    }

    let (_, in_use) = allocator.get_pool_clone_for_tests();
    assert!(
        in_use.len() <= 1,
        "the in-use list grew to {} entries over {ROUNDS} allocations",
        in_use.len()
    );
}

///////////////////////////////////////////////////////////////////////////////
// IPv6
///////////////////////////////////////////////////////////////////////////////

#[test]
fn the_offset_mapping_refuses_an_address_it_cannot_index() {
    let start = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
    let mapping = BTreeMap::from([(start, 0u32)]);

    assert_eq!(map_address(Ipv6Addr::from(start + 1), &mapping), Ok(1));
    assert_eq!(
        map_address(Ipv6Addr::from(start + u128::from(u32::MAX)), &mapping),
        Ok(u32::MAX)
    );
    for beyond in [u128::from(u32::MAX) + 1, 1u128 << 33] {
        assert_eq!(
            map_address(Ipv6Addr::from(start + beyond), &mapping),
            Err(AllocatorError::NoPoolFound)
        );
    }
}

/// A region may hold more addresses than a `u32` can index, in which case the bitmap covers only
/// the first 2^32 of them. An address past that is inside the region but not servable, which a
/// flow carried across a config change can present, and which must be an error rather than a panic
/// part way through applying a config.
#[test]
#[cfg_attr(miri, ignore = "the 2^32-entry bitmap is too slow under miri")]
fn an_address_past_the_indexable_span_is_refused_rather_than_panicking() {
    let start = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
    // Far wider than the bitmap can index.
    let specs = vec![PoolSpec::new(
        vec![AddrInterval::new(start, start + (1u128 << 40))],
        IDLE_TIMEOUT,
    )];
    let pool_sets = pool_sets_for_specs::<Ipv6Addr>(&specs, NextHeader::TCP, false);
    let port = NatPort::new_port_checked(4096).unwrap_or_else(|_| unreachable!());

    // Just inside the indexable span: an ordinary carry-over, which must still work.
    let near = Ipv6Addr::from(start + 1);
    assert!(
        pool_sets[0].reserve(near, port).is_ok(),
        "an address the pool can index was refused"
    );

    // Past it: refused, and specifically not a panic.
    let far = Ipv6Addr::from(start + (1u128 << 33));
    assert_eq!(
        pool_sets[0].reserve(far, port).unwrap_err(),
        AllocatorError::NoPoolFound,
        "an address the pool cannot index should be refused as unserved"
    );
}

/// The pools are generic over the address family but every other test here is IPv4. Allocating
/// from an IPv6 pool goes through the offset mapping that IPv4 skips entirely, so cover it.
#[test]
fn ipv6_pools_allocate_within_their_range() {
    let start = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
    let end = start + 3;
    let specs = vec![PoolSpec::new(
        vec![AddrInterval::new(start, end)],
        IDLE_TIMEOUT,
    )];
    let pool_sets = pool_sets_for_specs::<Ipv6Addr>(&specs, NextHeader::TCP, false);

    let mut held = Vec::new();
    let mut seen = BTreeSet::new();
    for step in 0..8 {
        let allocation = pool_sets[0].allocate(false).expect("pool has room");
        let bits = u128::from(allocation.ip());
        if step == 0 {
            assert_eq!(bits, start, "the offset mapping skipped the range start");
        }
        assert!(
            (start..=end).contains(&bits),
            "{} is outside the range the pool was built for",
            allocation.ip()
        );
        assert!(
            seen.insert((allocation.ip(), allocation.port().as_u16())),
            "{}:{} was handed out twice",
            allocation.ip(),
            allocation.port()
        );
        held.push(allocation);
    }
}

#[test]
fn a_live_tuple_cannot_be_reserved_again() {
    let specs = vec![PoolSpec::new(
        vec![AddrInterval::new(BASE, BASE)],
        IDLE_TIMEOUT,
    )];
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, NextHeader::TCP, false);

    let held = pool_sets[0].allocate(false).expect("pool has room");
    let tuple = (held.ip(), held.port());
    assert!(pool_sets[0].reserve(tuple.0, tuple.1).is_err());

    drop(held);
    assert!(pool_sets[0].reserve(tuple.0, tuple.1).is_ok());
}

/// What port forwarding may serve over a shared region is off limits to every owner of it, not only
/// to the expose the rule was written on: they allocate from one allocator, so a tuple one of them
/// hands out is a tuple the other cannot serve either.
#[test]
fn a_shared_region_honours_the_claims_of_every_owner() {
    let address = Ipv4Addr::from(u32::try_from(BASE).unwrap_or_else(|_| unreachable!()));
    let claimed = PrefixPortsSet::from([PrefixWithOptionalPorts::new(
        format!("{address}/32").as_str().into(),
        Some(PortRange::new(8080, 8080).unwrap_or_else(|_| unreachable!())),
    )]);
    // Both exposes masquerade onto the one address, so they share its region; only the first carries
    // the forwarding rule.
    let specs = vec![
        PoolSpec::new(vec![AddrInterval::new(BASE, BASE)], IDLE_TIMEOUT).claiming(claimed),
        PoolSpec::new(vec![AddrInterval::new(BASE, BASE)], IDLE_TIMEOUT),
    ];
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, NextHeader::TCP, false);

    let claimed_port = NatPort::new_port_checked(8080).unwrap_or_else(|_| unreachable!());
    for (owner, pool_set) in pool_sets.iter().enumerate() {
        assert!(
            matches!(
                pool_set.reserve(address, claimed_port),
                Err(AllocatorError::Denied)
            ),
            "owner {owner} was offered a claimed tuple"
        );
    }

    // Every other port of the shared address is still theirs to hand out.
    let free_port = NatPort::new_port_checked(8081).unwrap_or_else(|_| unreachable!());
    pool_sets[1]
        .reserve(address, free_port)
        .expect("an unclaimed port of a shared region is still available");
}

///////////////////////////////////////////////////////////////////////////////
// Tenancy bookkeeping
///////////////////////////////////////////////////////////////////////////////

/// Addresses in the pool the tenancy properties run against. Small, so operations collide on the
/// same offset often -- re-issue and stale hand-back are the interesting cases and both need two
/// leases on one address.
const TENANCY_POOL_SIZE: u32 = 3;
const TENANCY_OPS: usize = 32;
/// Bitmap indices are zero-based only for IPv6, whose addresses do not fit a `u32`. For IPv4 the
/// index *is* the address, so these properties have to speak in absolute values.
#[allow(clippy::cast_possible_truncation)]
const TENANCY_BASE: u32 = BASE as u32;

/// One step against a pool's tenancy bookkeeping.
///
/// `Abandon` is the state that motivates the whole scheme: an address whose owner is gone without
/// having handed it back. It is reachable in production only by losing a race, so it is modelled
/// directly here rather than waited for.
#[derive(Debug, Clone, Copy, TypeGenerator)]
enum TenancyOp {
    Lease(u8),
    HandBack(u8),
    HandBackStale(u8),
    Abandon(u8),
    Reclaim,
}

impl TenancyOp {
    fn offset(self) -> u32 {
        let raw = match self {
            TenancyOp::Lease(o)
            | TenancyOp::HandBack(o)
            | TenancyOp::HandBackStale(o)
            | TenancyOp::Abandon(o) => o,
            TenancyOp::Reclaim => 0,
        };
        TENANCY_BASE + (u32::from(raw) % TENANCY_POOL_SIZE)
    }
}

/// Every address is either free in the bitmap or currently leased. Never both, never neither.
///
/// "Neither" is the defect this machinery exists to prevent: an address whose owner has released
/// it but whose hand-back has not landed is absent from both, and an allocation that consults them
/// is told the pool is empty while the pool is holding an address belonging to no one. Stating it
/// as a partition means any future change that reintroduces the gap fails here, whatever route it
/// takes to get there.
fn assert_partition(pool: &NatPool<Ipv4Addr>, after: &str) {
    for offset in TENANCY_BASE..TENANCY_BASE + TENANCY_POOL_SIZE {
        let free = pool.bitmap_contains_for_tests(offset);
        let leased = pool.current_tenancy_for_tests(offset).is_some();
        assert!(
            free != leased,
            "offset {offset} is in {} after {after}",
            if free {
                "both the bitmap and a lease"
            } else {
                "neither the bitmap nor a lease"
            },
        );
    }
}

#[test]
fn an_address_is_always_either_free_or_leased() {
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|ops: Vec<TenancyOp>| {
            let mut pool = NatPool::<Ipv4Addr>::for_range(
                AddrInterval::new(BASE, BASE + u128::from(TENANCY_POOL_SIZE) - 1),
                ReservedPorts::default(),
                true,
            );
            // Tenancies handed out per offset, most recent last, so a stale one can be replayed.
            let mut history: BTreeMap<u32, Vec<Tenancy>> = BTreeMap::new();
            let mut every_tenancy = BTreeSet::new();

            assert_partition(&pool, "construction");

            for op in ops.into_iter().take(TENANCY_OPS) {
                let offset = op.offset();
                match op {
                    // Only lease what is free; leasing over a live lease is the re-issue case and
                    // is covered by `Abandon` followed by `Lease`.
                    TenancyOp::Lease(_) => {
                        if pool.current_tenancy_for_tests(offset).is_none() {
                            let tenancy = pool.begin_tenancy_for_tests(offset);
                            assert!(
                                every_tenancy.insert(tenancy),
                                "tenancy {tenancy:?} was handed out twice"
                            );
                            history.entry(offset).or_default().push(tenancy);
                        }
                    }
                    TenancyOp::HandBack(_) => {
                        if let Some(current) = pool.current_tenancy_for_tests(offset) {
                            assert!(
                                pool.end_tenancy_for_tests(offset, current),
                                "the current lease was refused"
                            );
                            assert!(
                                !pool.end_tenancy_for_tests(offset, current),
                                "handing the same lease back twice was accepted"
                            );
                        }
                    }
                    // A lease that has been retired must never free whatever holds the address now.
                    TenancyOp::HandBackStale(_) => {
                        let current = pool.current_tenancy_for_tests(offset);
                        if let Some(stale) = history
                            .get(&offset)
                            .and_then(|seen| seen.iter().find(|t| Some(**t) != current))
                        {
                            assert!(
                                !pool.end_tenancy_for_tests(offset, *stale),
                                "a retired lease was allowed to hand the address back"
                            );
                            assert_eq!(
                                pool.current_tenancy_for_tests(offset),
                                current,
                                "a retired lease disturbed the current one"
                            );
                        }
                    }
                    TenancyOp::Abandon(_) => {
                        if let Some(current) = pool.current_tenancy_for_tests(offset) {
                            pool.plant_dead_entry_for_tests(offset, current);
                        }
                    }
                    TenancyOp::Reclaim => pool.reclaim_ended_tenancies_for_tests(),
                }
                assert_partition(&pool, &format!("{op:?}"));
            }

            // Whatever the sequence, running the backstop leaves no address stranded.
            pool.reclaim_ended_tenancies_for_tests();
            assert_partition(&pool, "a final reclaim");
        });
}
