// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Property tests for pools built over overlapping public ranges.
//!
//! Generated ranges come from a narrow window so overlap is common. The properties require unique
//! live tuples, allocations within each expose's ranges, and safe carry-over between generations.

#![cfg(test)]

use super::alloc::PoolSet;
use super::region::AddrInterval;
use super::setup::{PoolSpec, pool_sets_for_specs};
use crate::masquerade::allocation::AllocatorError;
use crate::port::NatPort;
use bolero::{Driver, TypeGenerator};
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
    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(BASE, BASE)],
        idle_timeout: IDLE_TIMEOUT,
    }];
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
    let specs = vec![PoolSpec {
        public_ranges: vec![AddrInterval::new(start, end)],
        idle_timeout: IDLE_TIMEOUT,
    }];
    let pool_sets = pool_sets_for_specs::<Ipv6Addr>(&specs, NextHeader::TCP, false);

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
