// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Build masquerade pools by grouping exposes per peer VPC and splitting overlapping public ranges
//! into disjoint, shared regions.
//!
//! This is also where the public tuples port forwarding may claim are withheld from the pools, so
//! that the two translations of a peering cannot end up claiming one public tuple.

use super::alloc::{IpAllocator, NatPool, PoolSet};
use super::region::{AddrInterval, Region, decompose, regions_by_owner};
use super::reserved::ReservedPorts;
use super::{NatAllocator, NatIpWithBitmap, PoolTable, PoolTableKey};
use crate::masquerade::allocator_writer::MasqueradeConfig;
use crate::masquerade::natip::NatIp;
use config::external::overlay::vpcpeering::{ValidatedExpose, ValidatedManifest};
use lpm::prefix::{L4Protocol, PrefixPortsSet, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::{debug, error};

const DEFAULT_MASQUERADE_IDLE_TIMEOUT: Duration = Duration::from_mins(2);

impl NatAllocator {
    pub(crate) fn build_pools(&mut self, config: &MasqueradeConfig) {
        build_pools_generic(
            config,
            ValidatedManifest::masquerade_exposes_44,
            ValidatedManifest::port_forwarding_exposes_44,
            &mut self.pools_src44,
            NextHeader::ICMP,
            self.randomize,
        );

        build_pools_generic(
            config,
            ValidatedManifest::masquerade_exposes_66,
            ValidatedManifest::port_forwarding_exposes_66,
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
    // The port-forwarding exposes of the same peering, whose public tuples this expose's pools must
    // leave alone.
    port_forwarding: Vec<&'a ValidatedExpose>,
}

/// The public tuples the given port-forwarding exposes may claim for one protocol.
///
/// A claim bears only on the protocol its rule forwards, so a TCP rule leaves the UDP pools alone.
/// ICMP pools are never claimed from: port forwarding is validated to carry port ranges, which
/// identifiers are not.
///
/// The claims are deliberately not intersected with the masquerade ranges: a claim on an address no
/// masquerade pool holds costs nothing, because the pools only ever consult the claims covering the
/// addresses they own. That leaves one description of which tuples port forwarding may use, rather
/// than a second one here that has to keep agreeing with the port forwarder.
fn claims_for(protocol: NextHeader, exposes: &[&ValidatedExpose]) -> PrefixPortsSet {
    let wanted = match protocol {
        NextHeader::TCP => L4Protocol::Tcp,
        NextHeader::UDP => L4Protocol::Udp,
        _ => return PrefixPortsSet::new(),
    };

    let mut claimed = PrefixPortsSet::new();
    for expose in exposes {
        // A port-forwarding expose is validated to carry NAT configuration.
        let Some(nat) = expose.nat() else {
            error!("Port-forwarding expose without NAT configuration. This is a bug");
            continue;
        };
        if nat.proto.intersection(&wanted).is_some() {
            claimed.extend(expose.as_range_or_empty().clone());
        }
    }
    claimed
}

// Exposes toward different peers may safely reuse the same public range.
fn gather_exposes<'a, J, F, FIter, P, PIter>(
    config: &'a MasqueradeConfig,
    exposes_filter: &F,
    port_forwarding_filter: &P,
) -> BTreeMap<VpcDiscriminant, Vec<GatheredExpose<'a>>>
where
    J: NatIp,
    F: Fn(&'a ValidatedManifest) -> FIter,
    FIter: Iterator<Item = &'a ValidatedExpose>,
    P: Fn(&'a ValidatedManifest) -> PIter,
    PIter: Iterator<Item = &'a ValidatedExpose>,
{
    let mut groups: BTreeMap<VpcDiscriminant, Vec<GatheredExpose<'a>>> = BTreeMap::new();

    for nat_peering in config.iter() {
        let manifest = nat_peering.peering.local();
        // Port forwarding and masquerade of one peering share a public space, so the exposes of this
        // manifest are the ones whose claims the pools built from it must honour.
        let port_forwarding: Vec<&'a ValidatedExpose> = port_forwarding_filter(manifest).collect();
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
                    port_forwarding: port_forwarding.clone(),
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

fn build_pools_generic<'a, I, J, F, FIter, P, PIter>(
    config: &'a MasqueradeConfig,
    exposes_filter: F,
    port_forwarding_filter: P,
    table: &mut PoolTable<I, J>,
    icmp_proto: NextHeader,
    randomize: bool,
) where
    I: NatIpWithBitmap,
    J: NatIpWithBitmap,
    F: Fn(&'a ValidatedManifest) -> FIter,
    FIter: Iterator<Item = &'a ValidatedExpose>,
    P: Fn(&'a ValidatedManifest) -> PIter,
    PIter: Iterator<Item = &'a ValidatedExpose>,
{
    let groups = gather_exposes::<J, _, _, _, _>(config, &exposes_filter, &port_forwarding_filter);

    for (dst_vpc_id, exposes) in groups {
        // Allocations for TCP, for example, do not affect allocations for UDP or for ICMP: the
        // space made of addresses and L4 ports or identifiers is distinct for each protocol. So
        // each region backs one allocator per protocol, over the same addresses.
        for protocol in [NextHeader::TCP, NextHeader::UDP, icmp_proto] {
            let specs: Vec<PoolSpec> = exposes
                .iter()
                .map(|expose| PoolSpec {
                    public_ranges: expose.public_ranges.clone(),
                    claimed: claims_for(protocol, &expose.port_forwarding),
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
#[derive(Clone, Default)]
pub(crate) struct PoolSpec {
    pub(crate) public_ranges: Vec<AddrInterval>,
    /// The public tuples port forwarding may claim over this expose's ranges, for the protocol the
    /// pools are being built for.
    pub(crate) claimed: PrefixPortsSet,
    pub(crate) idle_timeout: Duration,
}

impl PoolSpec {
    /// A spec with nothing claimed by port forwarding.
    #[cfg(test)]
    pub(crate) fn new(public_ranges: Vec<AddrInterval>, idle_timeout: Duration) -> Self {
        Self {
            public_ranges,
            idle_timeout,
            ..Self::default()
        }
    }

    /// The same spec, with public tuples a forwarding rule may serve.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn claiming(mut self, claimed: PrefixPortsSet) -> Self {
        self.claimed = claimed;
        self
    }
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

    let allocators = build_region_allocators::<J>(&regions, specs, protocol, randomize);
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
    specs: &[PoolSpec],
    protocol: NextHeader,
    randomize: bool,
) -> Vec<IpAllocator<J>> {
    // TCP and UDP masquerade allocators should avoid the IANA system/well-known range (0-1023).
    // ICMP identifiers are allocated independently and are not subject to that policy.
    let exclude_wellknown_ports = matches!(protocol, NextHeader::TCP | NextHeader::UDP);

    regions
        .iter()
        .map(|region| {
            // A region is shared, so it must honour every claim on it: what port forwarding may take
            // from any of its owners is off limits to all of them.
            let claimed = region
                .owners
                .iter()
                .fold(PrefixPortsSet::new(), |accumulated, &owner| {
                    accumulated.union_prefixes_and_ports(&specs[owner].claimed)
                });

            let pool = NatPool::for_range(
                region.range,
                ReservedPorts::from_set(&claimed),
                exclude_wellknown_ports,
            );
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
