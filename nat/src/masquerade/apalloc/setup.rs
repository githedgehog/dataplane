// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Build masquerade pools by grouping exposes per peer VPC and splitting overlapping public ranges
//! into disjoint, shared regions.

use super::alloc::{IpAllocator, NatPool, PoolSet};
use super::region::{AddrInterval, Region, decompose, regions_by_owner};
use super::{NatAllocator, NatIpWithBitmap, PoolTable, PoolTableKey};
use crate::masquerade::allocator_writer::MasqueradeConfig;
use crate::masquerade::natip::NatIp;
use config::external::overlay::vpcpeering::{ValidatedExpose, ValidatedManifest};
use lpm::prefix::{PrefixPortsSet, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::debug;

const DEFAULT_MASQUERADE_IDLE_TIMEOUT: Duration = Duration::from_mins(2);

impl NatAllocator {
    pub(crate) fn build_pools(&mut self, config: &MasqueradeConfig) {
        build_pools_generic(
            config,
            ValidatedManifest::masquerade_exposes_44,
            &mut self.pools_src44,
            NextHeader::ICMP,
            self.randomize,
        );

        build_pools_generic(
            config,
            ValidatedManifest::masquerade_exposes_66,
            &mut self.pools_src66,
            NextHeader::ICMP6,
            self.randomize,
        );
    }
}

///////////////////////////////////////////////////////////////////////////////
// Gathering
///////////////////////////////////////////////////////////////////////////////

/// One masquerade expose, with everything the pools need from it.
struct GatheredExpose<'a> {
    src_vpc_id: VpcDiscriminant,
    // The private prefixes this expose masquerades, which is what the pool table is keyed by.
    private_prefixes: &'a PrefixPortsSet,
    // The public range this expose allocates from, as raw address intervals.
    public_ranges: Vec<AddrInterval>,
    idle_timeout: Duration,
}

// Exposes toward different peers may safely reuse the same public range.
fn gather_exposes<'a, J, F, FIter>(
    config: &'a MasqueradeConfig,
    exposes_filter: &F,
) -> BTreeMap<VpcDiscriminant, Vec<GatheredExpose<'a>>>
where
    J: NatIp,
    F: Fn(&'a ValidatedManifest) -> FIter,
    FIter: Iterator<Item = &'a ValidatedExpose>,
{
    let mut groups: BTreeMap<VpcDiscriminant, Vec<GatheredExpose<'a>>> = BTreeMap::new();

    for nat_peering in config.iter() {
        let manifest = nat_peering.peering.local();
        for expose in exposes_filter(manifest) {
            let public_ranges = public_intervals::<J>(expose.as_range_or_empty());
            if public_ranges.is_empty() {
                // A masquerade expose is validated to have a non-empty as_range, so this only
                // happens if none of its prefixes are of the version we are building.
                continue;
            }
            groups
                .entry(nat_peering.dst_vpcd)
                .or_default()
                .push(GatheredExpose {
                    src_vpc_id: nat_peering.src_vpcd,
                    private_prefixes: expose.ips(),
                    public_ranges,
                    idle_timeout: expose
                        .idle_timeout()
                        .unwrap_or(DEFAULT_MASQUERADE_IDLE_TIMEOUT),
                });
        }
    }

    groups
}

// Convert a set of public prefixes into raw address intervals, dropping any that are not of the
// version being built.
fn public_intervals<J: NatIp>(ranges: &PrefixPortsSet) -> Vec<AddrInterval> {
    ranges
        .iter()
        .filter_map(|prefix| {
            // FIXME: Account for port ranges. A public range may be restricted to a port range,
            // which the pools do not model, so the whole port space of the address is used.
            let start = J::try_from_addr(prefix.prefix().as_address()).ok()?;
            let end = J::try_from_addr(prefix.prefix().last_address()).ok()?;
            Some(AddrInterval::new(start.to_addr_bits(), end.to_addr_bits()))
        })
        .collect()
}

///////////////////////////////////////////////////////////////////////////////
// Building
///////////////////////////////////////////////////////////////////////////////

fn build_pools_generic<'a, I, J, F, FIter>(
    config: &'a MasqueradeConfig,
    exposes_filter: F,
    table: &mut PoolTable<I, J>,
    icmp_proto: NextHeader,
    randomize: bool,
) where
    I: NatIpWithBitmap,
    J: NatIpWithBitmap,
    F: Fn(&'a ValidatedManifest) -> FIter,
    FIter: Iterator<Item = &'a ValidatedExpose>,
{
    let groups = gather_exposes::<J, _, _>(config, &exposes_filter);

    for (dst_vpc_id, exposes) in groups {
        // Allocations for TCP, for example, do not affect allocations for UDP or for ICMP: the
        // space made of addresses and L4 ports or identifiers is distinct for each protocol. So
        // each region backs one allocator per protocol, over the same addresses.
        for protocol in [NextHeader::TCP, NextHeader::UDP, icmp_proto] {
            let specs: Vec<PoolSpec> = exposes
                .iter()
                .map(|expose| PoolSpec {
                    public_ranges: expose.public_ranges.clone(),
                    idle_timeout: expose.idle_timeout,
                })
                .collect();

            let pool_sets = pool_sets_for_specs::<J>(&specs, protocol, randomize);
            for (expose, pool_set) in exposes.iter().zip(pool_sets) {
                add_pool_entries(
                    table,
                    expose.private_prefixes,
                    expose.src_vpc_id,
                    dst_vpc_id,
                    protocol,
                    &pool_set,
                );
            }
        }
    }
}

/// The config-independent inputs for one expose's pools.
#[derive(Clone)]
pub(crate) struct PoolSpec {
    pub(crate) public_ranges: Vec<AddrInterval>,
    pub(crate) idle_timeout: Duration,
}

/// Cut the space the given exposes claim into disjoint regions, build one allocator per region,
/// and return the pools each expose may allocate from, in the same order as `specs`.
///
/// This is where the guarantee lives: exposes sharing a region share its allocator, so a public
/// address and port cannot be handed out twice, and an expose is only ever offered regions its own
/// ranges cover.
pub(crate) fn pool_sets_for_specs<J: NatIpWithBitmap>(
    specs: &[PoolSpec],
    protocol: NextHeader,
    randomize: bool,
) -> Vec<PoolSet<J>> {
    let owner_ranges: Vec<Vec<AddrInterval>> = specs
        .iter()
        .map(|spec| spec.public_ranges.clone())
        .collect();
    let regions = decompose(&owner_ranges);
    debug!(
        "Public space cut into {} region(s) for {} expose(s) ({protocol})",
        regions.len(),
        specs.len()
    );

    let allocators = build_region_allocators::<J>(&regions, protocol, randomize);
    let by_owner = regions_by_owner(&regions);

    specs
        .iter()
        .enumerate()
        .map(|(owner, spec)| {
            let mut pool_set = PoolSet::new(spec.idle_timeout);
            for &region_index in by_owner.get(&owner).map_or(&[][..], Vec::as_slice) {
                pool_set.push_region(
                    regions[region_index].range,
                    allocators[region_index].clone(),
                );
            }
            pool_set
        })
        .collect()
}

// One allocator per region. Every expose owning a region shares that allocator, which is what
// keeps a public address and port from being handed out twice.
fn build_region_allocators<J: NatIpWithBitmap>(
    regions: &[Region],
    protocol: NextHeader,
    randomize: bool,
) -> Vec<IpAllocator<J>> {
    // TCP and UDP masquerade allocators should avoid the IANA system/well-known range (0-1023).
    // ICMP identifiers are allocated independently and are not subject to that policy.
    let exclude_wellknown_ports = matches!(protocol, NextHeader::TCP | NextHeader::UDP);

    regions
        .iter()
        .map(|region| {
            let pool = NatPool::for_range(region.range, exclude_wellknown_ports);
            IpAllocator::new(pool, randomize)
        })
        .collect()
}

fn pool_table_key_for_expose<I: NatIp>(
    prefix: &PrefixWithOptionalPorts,
    protocol: NextHeader,
    src_vpc_id: VpcDiscriminant,
    dst_vpc_id: VpcDiscriminant,
) -> PoolTableKey<I> {
    let (addr, addr_range_end) = prefix_bounds(prefix);
    PoolTableKey::new(protocol, src_vpc_id, dst_vpc_id, addr, addr_range_end)
}

fn add_pool_entries<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    prefixes: &PrefixPortsSet,
    src_vpc_id: VpcDiscriminant,
    dst_vpc_id: VpcDiscriminant,
    protocol: NextHeader,
    pool_set: &PoolSet<J>,
) {
    for prefix in prefixes {
        let key = pool_table_key_for_expose(prefix, protocol, src_vpc_id, dst_vpc_id);
        table.add_entry(key, pool_set.clone());
    }
}

fn prefix_bounds<I: NatIp>(prefix: &PrefixWithOptionalPorts) -> (I, I) {
    let addr = I::try_from_addr(prefix.prefix().as_address()).unwrap_or_else(|()| unreachable!());
    let addr_range_end =
        I::try_from_addr(prefix.prefix().last_address()).unwrap_or_else(|()| unreachable!());
    // FIXME: Account for port ranges
    (addr, addr_range_end)
}
