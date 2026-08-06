// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Construction of the masquerade address and port pools.
//!
//! Pools cannot be built one expose at a time, because exposes that masquerade towards the same
//! peer VPC may claim overlapping public ranges and a public address may only be handed out by one
//! allocator. Building happens in two passes instead: collect every masquerade expose, group them
//! by peer VPC, cut the public space each group claims into disjoint regions (see [`super::region`])
//! and build one allocator per region, then give each expose the regions its own range covers.

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
}

/// Everything masquerading towards one peer VPC: the exposes that allocate from its public space,
/// and the public ports port forwarding has already claimed in that same space.
#[derive(Default)]
struct GatheredGroup<'a> {
    exposes: Vec<GatheredExpose<'a>>,
    claimed: ReserveSets,
}

/// Public ports that port forwarding has claimed, and that masquerade must not hand out.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ReserveSets {
    tcp: PrefixPortsSet,
    udp: PrefixPortsSet,
}

impl ReserveSets {
    fn for_protocol(&self, protocol: NextHeader) -> Option<&PrefixPortsSet> {
        match protocol {
            NextHeader::TCP => Some(&self.tcp),
            NextHeader::UDP => Some(&self.udp),
            // ICMP identifiers are a space of their own, untouched by port forwarding.
            _ => None,
        }
    }

    // Record what a port-forwarding expose has taken, under the protocols it applies to. The claim
    // is on the public side, which is the space masquerade allocates from and the space a pool is
    // asked about; the private side describes addresses the pools never see.
    fn add(&mut self, expose: &ValidatedExpose) {
        let claimed = expose.as_range_or_empty();
        let proto = expose.nat().map_or(L4Protocol::Any, |nat| nat.proto);
        match proto {
            L4Protocol::Tcp => self.tcp.extend(claimed.clone()),
            L4Protocol::Udp => self.udp.extend(claimed.clone()),
            L4Protocol::Any => {
                self.tcp.extend(claimed.clone());
                self.udp.extend(claimed.clone());
            }
        }
    }
}

// Collect the masquerade exposes of every peering, grouped by the VPC they masquerade towards.
// Grouping by peer VPC is what matters, because return traffic is only told apart by the peer it
// comes back from: exposes towards different peers can safely claim the same public range.
fn gather_exposes<'a, J, F, FIter, P, PIter>(
    config: &'a MasqueradeConfig,
    exposes_filter: &F,
    port_forwarding_exposes_filter: &P,
) -> BTreeMap<VpcDiscriminant, GatheredGroup<'a>>
where
    J: NatIp,
    F: Fn(&'a ValidatedManifest) -> FIter,
    FIter: Iterator<Item = &'a ValidatedExpose>,
    P: Fn(&'a ValidatedManifest) -> PIter,
    PIter: Iterator<Item = &'a ValidatedExpose>,
{
    let mut groups: BTreeMap<VpcDiscriminant, GatheredGroup<'a>> = BTreeMap::new();

    for nat_peering in config.iter() {
        let manifest = nat_peering.peering.local();
        let group = groups.entry(nat_peering.dst_vpcd).or_default();

        // Port forwarding claims public space towards this peer whichever VPC declared it, because
        // the public space towards a peer is shared: return traffic carries nothing that says
        // which VPC it belongs to. Claims are therefore collected per peer VPC rather than per
        // manifest, so a claim made by one VPC is honoured by another VPC's pools, and a peering
        // that port-forwards without masquerading still has its claims respected.
        for pf_expose in port_forwarding_exposes_filter(manifest) {
            group.claimed.add(pf_expose);
        }

        for expose in exposes_filter(manifest) {
            let public_ranges = public_intervals::<J>(expose.as_range_or_empty());
            if public_ranges.is_empty() {
                // A masquerade expose is validated to have a non-empty as_range, so this only
                // happens if none of its prefixes are of the version we are building.
                continue;
            }
            group.exposes.push(GatheredExpose {
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

fn build_pools_generic<'a, I, J, F, FIter, P, PIter>(
    config: &'a MasqueradeConfig,
    exposes_filter: F,
    port_forwarding_exposes_filter: P,
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
    let groups =
        gather_exposes::<J, _, _, _, _>(config, &exposes_filter, &port_forwarding_exposes_filter);

    for (dst_vpc_id, group) in groups {
        // Allocations for TCP, for example, do not affect allocations for UDP or for ICMP: the
        // space made of addresses and L4 ports or identifiers is distinct for each protocol. So
        // each region backs one allocator per protocol, over the same addresses.
        for protocol in [NextHeader::TCP, NextHeader::UDP, icmp_proto] {
            let specs: Vec<PoolSpec> = group
                .exposes
                .iter()
                .map(|expose| PoolSpec {
                    public_ranges: expose.public_ranges.clone(),
                    idle_timeout: expose.idle_timeout,
                })
                .collect();

            let claimed = group
                .claimed
                .for_protocol(protocol)
                .cloned()
                .unwrap_or_default();
            let pool_sets = pool_sets_for_specs::<J>(&specs, &claimed, protocol, randomize);
            for (expose, pool_set) in group.exposes.iter().zip(pool_sets) {
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

/// What building a pool needs to know about one expose, independent of where it came from. Keeping
/// this free of config types is what lets the property tests drive the real construction.
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
    claimed: &PrefixPortsSet,
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

    let allocators = build_region_allocators::<J>(&regions, claimed, protocol, randomize);
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
    claimed: &PrefixPortsSet,
    protocol: NextHeader,
    randomize: bool,
) -> Vec<IpAllocator<J>> {
    // TCP and UDP masquerade allocators should avoid the IANA system/well-known range (0-1023).
    // ICMP identifiers are allocated independently and are not subject to that policy.
    let exclude_wellknown_ports = matches!(protocol, NextHeader::TCP | NextHeader::UDP);

    // The claims cover the whole public space towards this peer VPC, so every region gets the
    // same set and each pool keeps only what covers an address when it hands one out. A region is
    // shared between exposes, and a claim binds the space rather than the expose that declared it,
    // so there is nothing per-owner to work out here.
    let reserved = build_reserved_ports(claimed);

    regions
        .iter()
        .map(|region| {
            let pool = NatPool::for_range(region.range, reserved.clone(), exclude_wellknown_ports);
            IpAllocator::new(pool, randomize)
        })
        .collect()
}

// Every claim is kept, including several on one address: a set of claims is not a map from
// address to port range, and recording it as one silently honoured whichever came last.
fn build_reserved_ports(
    prefixes_and_ports_to_exclude_from_pools: &PrefixPortsSet,
) -> ReservedPorts {
    let mut reserved = ReservedPorts::default();
    for prefix in prefixes_and_ports_to_exclude_from_pools {
        debug_assert!(prefix.ports().is_some());
        let Some(ports) = prefix.ports() else {
            error!("Stepped on a port-forwarding prefix without ports. This is a bug");
            continue;
        };
        reserved.claim(prefix.prefix().into(), ports);
    }
    reserved
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

#[cfg(test)]
mod tests {
    use super::ReserveSets;
    use config::external::overlay::vpcpeering::VpcExpose;
    use lpm::prefix::{L4Protocol, PortRange, PrefixPortsSet, PrefixWithOptionalPorts};

    fn prefix_with_ports(s: &str, start: u16, end: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(s.into(), Some(PortRange::new(start, end).unwrap()))
    }

    // A port-forwarding expose, mapping a private range onto a public one.
    fn port_forwarding(private: &str, public: &str, proto: Option<L4Protocol>) -> VpcExpose {
        VpcExpose::empty()
            .make_port_forwarding(None, proto)
            .unwrap()
            .ip(prefix_with_ports(private, 8080, 8090))
            .as_range(prefix_with_ports(public, 8080, 8090))
            .unwrap()
    }

    fn claims_of(exposes: &[VpcExpose]) -> ReserveSets {
        let mut sets = ReserveSets::default();
        for expose in exposes {
            sets.add(&expose.clone().validate().unwrap());
        }
        sets
    }

    // The claim is on the public address and ports, because that is what masquerade allocates and
    // what a pool is asked about. Recording the private side instead described a space the pools
    // never look in, so nothing was ever actually reserved.
    #[test]
    fn a_claim_is_recorded_on_the_public_range() {
        let claims = claims_of(&[port_forwarding("10.0.0.0/24", "192.168.1.0/24", None)]);
        let expected = PrefixPortsSet::from([prefix_with_ports("192.168.1.0/24", 8080, 8090)]);
        assert_eq!(
            claims,
            ReserveSets {
                tcp: expected.clone(),
                udp: expected,
            }
        );
    }

    #[test]
    fn a_protocol_specific_claim_only_binds_that_protocol() {
        let claims = claims_of(&[port_forwarding(
            "10.0.0.0/24",
            "192.168.1.0/24",
            Some(L4Protocol::Tcp),
        )]);
        assert_eq!(
            claims,
            ReserveSets {
                tcp: PrefixPortsSet::from([prefix_with_ports("192.168.1.0/24", 8080, 8090)]),
                udp: PrefixPortsSet::default(),
            }
        );
    }

    #[test]
    fn claims_from_several_exposes_accumulate() {
        let claims = claims_of(&[
            port_forwarding("10.0.1.0/24", "192.168.1.0/24", None),
            port_forwarding("172.16.5.0/24", "192.168.2.0/24", None),
        ]);
        let expected = PrefixPortsSet::from([
            prefix_with_ports("192.168.1.0/24", 8080, 8090),
            prefix_with_ports("192.168.2.0/24", 8080, 8090),
        ]);
        assert_eq!(
            claims,
            ReserveSets {
                tcp: expected.clone(),
                udp: expected,
            }
        );
    }

    // Two exposes forwarding different private ranges onto one public range describe one claim.
    #[test]
    fn duplicate_public_claims_collapse() {
        let claims = claims_of(&[
            port_forwarding("10.0.1.0/24", "192.168.1.0/24", None),
            port_forwarding("10.0.2.0/24", "192.168.1.0/24", None),
        ]);
        assert_eq!(claims.tcp.len(), 1);
        assert_eq!(claims.udp.len(), 1);
    }
}
