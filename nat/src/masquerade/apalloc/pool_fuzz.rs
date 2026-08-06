// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Property tests for the pools built over the public address space.
//!
//! [`super::region`] tests the cutting on its own; these drive the real construction
//! ([`pool_sets_for_specs`]) and then allocate through it, so they cover the step where regions
//! become allocators and the step where a config change re-reserves what the previous config had
//! handed out.
//!
//! The properties are the ones return traffic depends on. A public address and port may only be
//! live once at a time towards a given peer, because the reverse flow key is built from it and
//! carries nothing that says which VPC the traffic came from. And an expose may only ever be given
//! an address its own configuration declares.
//!
//! Ranges are drawn from a narrow window so that overlap is the common case rather than
//! astronomically unlikely, and so that a handful of allocations is enough to make two exposes
//! collide if the pools let them.

#![cfg(test)]

use super::alloc::{MAX_ADDRESSES_PER_ALLOCATION, PoolSet};
use super::region::AddrInterval;
use super::setup::{PoolSpec, pool_sets_for_specs};
use crate::masquerade::allocation::AllocatorError;
use crate::port::NatPort;
use bolero::{Driver, TypeGenerator};
use lpm::prefix::{PortRange, PrefixPortsSet, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
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
            .map(|public_ranges| PoolSpec {
                public_ranges,
                idle_timeout: IDLE_TIMEOUT,
            })
            .collect()
    }

    fn pool_sets(&self) -> Vec<PoolSet<Ipv4Addr>> {
        // No randomization: a failure has to reproduce from its seed alone.
        pool_sets_for_specs::<Ipv4Addr>(
            &self.specs(),
            &PrefixPortsSet::new(),
            NextHeader::TCP,
            false,
        )
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

fn port(value: u16) -> NatPort {
    NatPort::new_port_checked(value).unwrap_or_else(|_| unreachable!())
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

/// A config update: flows allocated under one config re-reserve their address and port in the
/// allocator built for the next one, exactly as `check_masquerading_flow` does.
///
/// What must hold is that a re-reservation is honoured. If the new pools accept an address and
/// port, they may not then hand the same pair to a new flow, or the surviving flow and the new one
/// would collide on the reverse key.
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

/// Falling through to the next region is what makes an expose's several regions behave as one
/// pool. Only exhaustion may do it: any other error is about the allocator rather than about how
/// full a region is, and a later region's success would bury it.
///
/// Exhausting a region by allocating from it would take every port of every address it holds, so
/// this reserves them instead, which reaches the same state in one step.
#[test]
fn an_exhausted_region_falls_through_to_the_next() {
    // Not adjacent, or the two would merge into a single region.
    let full = BASE;
    let free = BASE + 4;

    let every_port = PrefixWithOptionalPorts::new(
        "10.1.0.0/32".into(),
        Some(PortRange::new(1024, u16::MAX).unwrap_or_else(|_| unreachable!())),
    );

    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(full, full), AddrInterval::new(free, free)],
        idle_timeout: IDLE_TIMEOUT,
    }];

    let claimed = PrefixPortsSet::from([every_port]);
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, &claimed, NextHeader::TCP, false);
    let allocation = pool_sets[0]
        .allocate(false)
        .expect("the second region has room, so allocation must succeed");
    assert_eq!(
        allocation.ip(),
        Ipv4Addr::from(u32::try_from(free).unwrap_or_else(|_| unreachable!())),
        "allocation did not fall through to the region with room"
    );
}

///////////////////////////////////////////////////////////////////////////////
// Exhaustion
///////////////////////////////////////////////////////////////////////////////

// Claiming every port masquerade could hand out on an address, which is how a test reaches
// address exhaustion without making 64k allocations.
fn claim_whole_address(offset: u128) -> PrefixWithOptionalPorts {
    let address = Ipv4Addr::from(u32::try_from(BASE + offset).unwrap_or_else(|_| unreachable!()));
    PrefixWithOptionalPorts::new(
        format!("{address}/32").as_str().into(),
        Some(PortRange::new(1024, u16::MAX).unwrap_or_else(|_| unreachable!())),
    )
}

/// An address with nothing left to give is passed over, and the next one serves.
///
/// Allocation draws the lowest free address and, finding no port on it, used to hand it straight
/// back. The same address was lowest next time, so the pool served nothing at all for as long as
/// it stayed there: one address fully claimed by port forwarding took a whole region out of
/// service. Claims on a later address never showed it, since allocation stopped before reaching
/// them.
#[test]
fn an_address_with_no_free_port_is_passed_over() {
    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(BASE, BASE + 2)],
        idle_timeout: IDLE_TIMEOUT,
    }];
    let claimed = PrefixPortsSet::from([claim_whole_address(0)]);
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, &claimed, NextHeader::TCP, false);

    // Repeatedly, so that an address taken out of the pool stays out.
    let mut held = Vec::new();
    for _ in 0..4 {
        let allocation = pool_sets[0]
            .allocate(false)
            .expect("two addresses of the region are free");
        assert_ne!(
            allocation.ip(),
            Ipv4Addr::from(u32::try_from(BASE).unwrap()),
            "an address whose ports are all claimed was handed out"
        );
        held.push(allocation);
    }
}

/// With every address claimed the pool has nothing to give, and says so rather than looping.
#[test]
fn a_fully_claimed_region_reports_exhaustion() {
    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(BASE, BASE + 2)],
        idle_timeout: IDLE_TIMEOUT,
    }];
    let claimed: PrefixPortsSet = (0..3).map(claim_whole_address).collect();
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, &claimed, NextHeader::TCP, false);

    let error = pool_sets[0]
        .allocate(false)
        .expect_err("no address in the region can serve");
    assert!(
        error.is_exhaustion(),
        "a region with nothing to give reported {error} rather than being out of space"
    );
}

/// An expose falls through to a region it shares once the region it has to itself is used up.
///
/// The ordinary tests never reach this: a region is only given up when every port of every address
/// in it is taken, and allocation stays on one address for 64k ports, so a handful of allocations
/// never leaves the first address of the first region. Claiming the exclusive region away is how
/// the fallback gets exercised at all.
#[test]
fn an_expose_falls_back_to_shared_space_when_its_own_is_used_up() {
    // Owner 0 has BASE..=BASE+1 to itself and shares BASE+2 with owner 1.
    let specs = vec![
        PoolSpec {
            public_ranges: vec![AddrInterval::new(BASE, BASE + 2)],
            idle_timeout: IDLE_TIMEOUT,
        },
        PoolSpec {
            public_ranges: vec![AddrInterval::new(BASE + 2, BASE + 2)],
            idle_timeout: IDLE_TIMEOUT,
        },
    ];
    // Claim the exclusive region away, leaving owner 0 only the shared one.
    let claimed: PrefixPortsSet = (0..2).map(claim_whole_address).collect();
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, &claimed, NextHeader::TCP, false);

    let allocation = pool_sets[0]
        .allocate(false)
        .expect("the shared region still has room");
    assert_eq!(
        allocation.ip(),
        Ipv4Addr::from(u32::try_from(BASE + 2).unwrap()),
        "the expose did not fall back to the region it shares"
    );
}

/// Addresses are used up in turn, and every address of a region is reachable.
///
/// Claims stand in for the 64k allocations it would otherwise take to move off an address, so the
/// walk over addresses is exercised at every depth rather than only at the first one.
#[test]
fn every_address_of_a_region_can_be_reached() {
    const ADDRESSES: u128 = 6;
    for claimed_count in 0..ADDRESSES {
        let specs = vec![PoolSpec {
            public_ranges: vec![AddrInterval::new(BASE, BASE + ADDRESSES - 1)],
            idle_timeout: IDLE_TIMEOUT,
        }];
        // Claim a prefix of the region away, so the first address left is the one after it.
        let claimed: PrefixPortsSet = (0..claimed_count).map(claim_whole_address).collect();
        let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, &claimed, NextHeader::TCP, false);

        let allocation = pool_sets[0].allocate(false).unwrap_or_else(|e| {
            panic!("{claimed_count} addresses claimed, allocation failed: {e}")
        });
        assert_eq!(
            allocation.ip(),
            Ipv4Addr::from(u32::try_from(BASE + claimed_count).unwrap()),
            "with {claimed_count} addresses claimed the next one should serve"
        );
    }
}

/// A run of claimed addresses costs nothing, however long it is.
///
/// Allocation draws the lowest free address, so a port-forwarded prefix at the bottom of a region
/// is what it meets first. Those addresses used to sit in the pool and be discovered one at a
/// time, and since an allocation gives up after `MAX_ADDRESSES_PER_ALLOCATION` of them, a run shed
/// a dropped packet for every bound's worth -- sixteen for a claimed `/25` -- and shed them again
/// after every config change. They are excluded when the pool is built now.
#[test]
fn a_run_of_claimed_addresses_costs_no_allocations() {
    let bound = u128::try_from(MAX_ADDRESSES_PER_ALLOCATION).unwrap_or_else(|_| unreachable!());

    // Around the old cliff, and then well past it: the last of these used to cost three packets.
    for claimed_count in [0, 1, bound - 1, bound, bound + 1, 3 * bound + 5] {
        let specs = vec![PoolSpec {
            // One address past the claimed run, which is the one that has to serve.
            public_ranges: vec![AddrInterval::new(BASE, BASE + claimed_count)],
            idle_timeout: IDLE_TIMEOUT,
        }];
        let claimed: PrefixPortsSet = (0..claimed_count).map(claim_whole_address).collect();
        let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, &claimed, NextHeader::TCP, false);

        let allocation = pool_sets[0].allocate(false).unwrap_or_else(|e| {
            panic!("a run of {claimed_count} claimed addresses cost the first allocation: {e}")
        });
        assert_eq!(
            allocation.ip(),
            Ipv4Addr::from(u32::try_from(BASE + claimed_count).unwrap_or_else(|_| unreachable!())),
            "the address past a run of {claimed_count} claimed ones should be the one that serves"
        );
    }
}

/// An address the pool may never draw is not put into it by a flow that fails to carry over.
///
/// Reserving reaches addresses allocation never touches. A flow that survives a config change
/// presents the address it already holds, and the pool takes that address into use in order to try
/// to give the port back. Where the new configuration has claimed every port on it the reservation
/// fails, as it must -- but the address has been through the pool by then, and releasing it on the
/// way out used to hand it to the bitmap. The exclusion would undo itself on the first config
/// change that needed it, which is also the first one that could produce such a flow.
#[test]
fn a_failed_carry_over_does_not_put_a_claimed_address_into_the_pool() {
    const ADDRESSES: u128 = 4;
    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(BASE, BASE + ADDRESSES - 1)],
        idle_timeout: IDLE_TIMEOUT,
    }];
    // The lowest two addresses are claimed end to end, so neither may ever be handed out.
    let claimed: PrefixPortsSet = (0..2).map(claim_whole_address).collect();
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, &claimed, NextHeader::TCP, false);
    let claimed_address = Ipv4Addr::from(u32::try_from(BASE).unwrap_or_else(|_| unreachable!()));

    let free_offsets = || {
        let region = pool_sets[0]
            .regions()
            .next()
            .expect("the specs describe one region");
        let (bitmap, _) = region.allocator().get_pool_clone_for_tests();
        bitmap
    };
    assert!(
        !free_offsets().contains(claimed_address.to_bits()),
        "a fully claimed address was in the pool to begin with"
    );

    // Carry a flow over onto it. Refused, and the address goes back where it came from.
    assert!(
        pool_sets[0].reserve(claimed_address, port(5000)).is_err(),
        "a port on a fully claimed address was carried over"
    );

    assert!(
        !free_offsets().contains(claimed_address.to_bits()),
        "a fully claimed address was put into the pool by a carry-over that failed on it"
    );

    // And allocation still goes straight to the first address that can serve.
    let allocation = pool_sets[0]
        .allocate(false)
        .expect("the region has addresses that can serve");
    assert_eq!(
        allocation.ip(),
        Ipv4Addr::from(u32::try_from(BASE + 2).unwrap_or_else(|_| unreachable!())),
        "allocation did not go straight past the claimed addresses"
    );
}

/// An address that still has room is reused, rather than a fresh one being drawn.
///
/// Reuse walks the addresses already in hand and skips those with nothing left. The skip is
/// decided by a count of blocks still free, and a block that port forwarding has claimed used to
/// be marked unusable without being taken off that count. The count then said an address had room
/// when it had none; the attempt failed with "no port block", and the walk gave up on that error
/// rather than trying the next address in hand. Every allocation after that drew a fresh address
/// while addresses already in hand sat with tens of thousands of free ports, until the region ran
/// out of addresses altogether.
#[test]
fn an_address_with_room_is_reused_before_a_fresh_one_is_drawn() {
    const ADDRESSES: u128 = 4;
    // Everything above the first block, so the first address has exactly one block: 1024..=1279.
    let claim = PrefixWithOptionalPorts::new(
        format!("{}/32", Ipv4Addr::from(u32::try_from(BASE).unwrap()))
            .as_str()
            .into(),
        Some(PortRange::new(1280, u16::MAX).unwrap_or_else(|_| unreachable!())),
    );
    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(BASE, BASE + ADDRESSES - 1)],
        idle_timeout: IDLE_TIMEOUT,
    }];
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(
        &specs,
        &PrefixPortsSet::from([claim]),
        NextHeader::TCP,
        false,
    );

    // One block on the first address, then a handful more that the second address can serve
    // many times over.
    let mut held = Vec::new();
    let mut used = BTreeSet::new();
    for step in 0..(256 + 4) {
        let allocation = pool_sets[0]
            .allocate(false)
            .unwrap_or_else(|e| panic!("allocation {step} failed: {e}"));
        used.insert(allocation.ip());
        held.push(allocation);
    }

    assert_eq!(
        used.len(),
        2,
        "the region spent {} addresses on what two can serve: {used:?}",
        used.len()
    );
}

///////////////////////////////////////////////////////////////////////////////
// IPv6
///////////////////////////////////////////////////////////////////////////////

/// A region may hold more addresses than a `u32` can index, in which case the bitmap covers only
/// the first 2^32 of them. An address past that is inside the region but not servable, which a
/// flow carried across a config change can present, and which must be an error rather than a panic
/// part way through applying a config.
#[test]
fn an_address_past_the_indexable_span_is_refused_rather_than_panicking() {
    let start = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
    // Far wider than the bitmap can index.
    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(start, start + (1u128 << 40))],
        idle_timeout: IDLE_TIMEOUT,
    }];
    let pool_sets =
        pool_sets_for_specs::<Ipv6Addr>(&specs, &PrefixPortsSet::new(), NextHeader::TCP, false);
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
    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(start, end)],
        idle_timeout: IDLE_TIMEOUT,
    }];
    let pool_sets =
        pool_sets_for_specs::<Ipv6Addr>(&specs, &PrefixPortsSet::new(), NextHeader::TCP, false);

    let mut held = Vec::new();
    let mut seen = BTreeSet::new();
    for _ in 0..8 {
        let allocation = pool_sets[0].allocate(false).expect("pool has room");
        let bits = u128::from(allocation.ip());
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

///////////////////////////////////////////////////////////////////////////////
// Reserved ports
///////////////////////////////////////////////////////////////////////////////

/// A port range on one public address that port forwarding has claimed, and that masquerade must
/// therefore not hand out.
#[derive(Debug, Clone, Copy)]
struct Reservation {
    offset: u8,
    port_lo: u16,
    port_span: u16,
}

impl Reservation {
    fn address(self) -> Ipv4Addr {
        Ipv4Addr::from(
            u32::try_from(BASE + u128::from(self.offset % 16)).unwrap_or_else(|_| unreachable!()),
        )
    }

    fn ports(self) -> PortRange {
        let lo = self.port_lo.max(1024);
        let hi = lo.saturating_add(self.port_span);
        PortRange::new(lo, hi).unwrap_or_else(|_| unreachable!())
    }

    fn covers(self, ip: Ipv4Addr, port: u16) -> bool {
        let ports = self.ports();
        self.address() == ip && port >= ports.start() && port <= ports.end()
    }

    fn as_prefix(self) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(
            format!("{}/32", self.address()).as_str().into(),
            Some(self.ports()),
        )
    }
}

/// A config where exposes also carry port-forwarding claims on their public addresses.
#[derive(Debug, Clone)]
struct ReservedConfig {
    config: Config,
    reservations: Vec<Vec<Reservation>>,
}

impl TypeGenerator for ReservedConfig {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let config: Config = driver.produce()?;
        let mut reservations = Vec::with_capacity(config.owner_count());
        for _ in 0..config.owner_count() {
            let count = usize::from(driver.produce::<u8>()? % 3);
            let mut claims = Vec::with_capacity(count);
            for _ in 0..count {
                claims.push(Reservation {
                    offset: driver.produce::<u8>()?,
                    port_lo: driver.produce::<u16>()?,
                    port_span: u16::from(driver.produce::<u8>()?),
                });
            }
            reservations.push(claims);
        }
        Some(Self {
            config,
            reservations,
        })
    }
}

impl ReservedConfig {
    fn pool_sets(&self) -> Vec<PoolSet<Ipv4Addr>> {
        let specs: Vec<PoolSpec> = self
            .config
            .owner_ranges()
            .into_iter()
            .map(|public_ranges| PoolSpec {
                public_ranges,
                idle_timeout: IDLE_TIMEOUT,
            })
            .collect();
        // A claim binds the public space towards a peer, whichever expose declared it, so the
        // claims of every expose apply to every pool built over that space.
        let claimed: PrefixPortsSet = self
            .reservations
            .iter()
            .flatten()
            .map(|claim| claim.as_prefix())
            .collect();
        pool_sets_for_specs::<Ipv4Addr>(&specs, &claimed, NextHeader::TCP, false)
    }
}

/// Ports that port forwarding has claimed on a public address may not be handed out by
/// masquerade, whichever expose is allocating.
///
/// A region is shared, so it has to honour the claims of every expose that owns it: a claim made
/// through one expose still has to hold against an allocation made through another, or masquerade
/// would hand out a port that port forwarding is statically mapping elsewhere.
///
/// This is a property of the pools, which are given claims already expressed in public space.
/// Translating a configuration into those claims is a separate step, covered by the tests on
/// `ReserveSets` in `setup.rs` and end to end by `test_forwarded_ports_are_not_masqueraded_onto`.
#[test]
fn reserved_ports_are_never_allocated() {
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|reserved_config: ReservedConfig| {
            let pool_sets = reserved_config.pool_sets();

            for (owner, allocation) in allocate_round_robin(&pool_sets, ALLOCATIONS) {
                let ip = allocation.ip();
                let port = allocation.port().as_u16();

                // A claim binds the public space it names, whoever made it. The pool is built
                // from the union of every claim, so the oracle unions them too: gating on the
                // claimant's own ranges here would let a claim made through one expose go
                // unchecked against an allocation made through another, which is the case the
                // property exists to state.
                for (claimant, claims) in reserved_config.reservations.iter().enumerate() {
                    for claim in claims {
                        assert!(
                            !claim.covers(ip, port),
                            "expose {owner} was allocated {ip}:{port}, which expose {claimant} \
                             has claimed for port forwarding ({:?})",
                            claim.ports()
                        );
                    }
                }
            }
        });
}

/// The minimal shape behind [`reserved_ports_are_never_allocated`]: one public address carrying
/// two port-forwarding claims, both of which have to be honoured.
///
/// This used to hold only the last claim recorded on an address, at three points in a row: the
/// claims were collected into a map keyed by address range, the pool resolved one range per
/// address out of it, and the port allocator stored one range. Each now carries the whole set.
#[test]
fn several_claims_on_one_address_are_all_honoured() {
    let address: u128 = BASE;
    let claim = |start: u16, end: u16| {
        PrefixWithOptionalPorts::new(
            "10.1.0.0/32".into(),
            Some(PortRange::new(start, end).unwrap_or_else(|_| unreachable!())),
        )
    };

    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(address, address)],
        idle_timeout: IDLE_TIMEOUT,
    }];

    let claimed = PrefixPortsSet::from([claim(1024, 1024), claim(2000, 2000)]);
    let pool_sets = pool_sets_for_specs::<Ipv4Addr>(&specs, &claimed, NextHeader::TCP, false);
    let allocated: BTreeSet<u16> = allocate_round_robin(&pool_sets, 4)
        .iter()
        .map(|(_, allocation)| allocation.port().as_u16())
        .collect();

    assert!(
        !allocated.contains(&1024),
        "port 1024 was claimed for port forwarding but handed out: {allocated:?}"
    );
    assert!(
        !allocated.contains(&2000),
        "port 2000 was claimed for port forwarding but handed out: {allocated:?}"
    );
}
