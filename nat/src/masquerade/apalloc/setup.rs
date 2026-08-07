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
use super::{NatAllocator, NatIpWithBitmap, PoolTable, PoolTableKey};
use crate::masquerade::allocator_writer::MasqueradeConfig;
use crate::masquerade::natip::NatIp;
use crate::ranges::IpRange;
use config::external::overlay::vpcpeering::{ValidatedExpose, ValidatedManifest};
use lpm::prefix::range_map::DisjointRangesBTreeMap;
use lpm::prefix::{L4Protocol, PortRange, PrefixPortsSet, PrefixWithOptionalPorts};
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
    reserved: ReserveSets,
}

/// Ports that port forwarding has claimed, and that masquerade must not hand out.
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
}

// Collect the masquerade exposes of every peering, grouped by the VPC they masquerade towards.
// Grouping by peer VPC is what matters, because return traffic is only told apart by the peer it
// comes back from: exposes towards different peers can safely claim the same public range.
fn gather_exposes<'a, J, F, FIter, P, PIter>(
    config: &'a MasqueradeConfig,
    exposes_filter: &F,
    port_forwarding_exposes_filter: &P,
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
        let port_forwarding_exposes: Vec<&'a ValidatedExpose> =
            port_forwarding_exposes_filter(manifest).collect();

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
                    reserved: find_masquerade_portfw_overlap(&port_forwarding_exposes, expose),
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

    for (dst_vpc_id, exposes) in groups {
        // Allocations for TCP, for example, do not affect allocations for UDP or for ICMP: the
        // space made of addresses and L4 ports or identifiers is distinct for each protocol. So
        // each region backs one allocator per protocol, over the same addresses.
        for protocol in [NextHeader::TCP, NextHeader::UDP, icmp_proto] {
            let specs: Vec<PoolSpec> = exposes
                .iter()
                .map(|expose| PoolSpec {
                    public_ranges: expose.public_ranges.clone(),
                    reserved: expose
                        .reserved
                        .for_protocol(protocol)
                        .cloned()
                        .unwrap_or_default(),
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

/// What building a pool needs to know about one expose, independent of where it came from. Keeping
/// this free of config types is what lets the property tests drive the real construction.
#[derive(Clone)]
pub(crate) struct PoolSpec {
    pub(crate) public_ranges: Vec<AddrInterval>,
    pub(crate) reserved: PrefixPortsSet,
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
            // A region is shared, so it must honour every claim on it: reserve what port
            // forwarding has taken from any of its owners.
            let reserved = region
                .owners
                .iter()
                .fold(PrefixPortsSet::new(), |accumulated, &owner| {
                    accumulated.union_prefixes_and_ports(&specs[owner].reserved)
                });

            let pool = NatPool::for_range(
                region.range,
                build_reserved_prefixes_ports(&reserved),
                exclude_wellknown_ports,
            );
            IpAllocator::new(pool, randomize)
        })
        .collect()
}

fn find_masquerade_portfw_overlap<'a>(
    port_forwarding_exposes: &Vec<&'a ValidatedExpose>,
    expose: &'a ValidatedExpose,
) -> ReserveSets {
    let expose_nat = expose.nat().unwrap_or_else(|| unreachable!());
    let mut reserve_sets = ReserveSets::default();

    for pf_expose in port_forwarding_exposes {
        let pf_nat = pf_expose.nat().unwrap_or_else(|| unreachable!());
        let Some(relevant_proto) = expose_nat.proto.intersection(&pf_nat.proto) else {
            // No overlap on L4 protocols, so no overlap for prefixes and ports.
            continue;
        };
        let ranges_intersection = pf_expose
            .ips()
            .intersection_prefixes_and_ports(expose.ips());
        match relevant_proto {
            L4Protocol::Tcp => reserve_sets.tcp.extend(ranges_intersection),
            L4Protocol::Udp => reserve_sets.udp.extend(ranges_intersection),
            L4Protocol::Any => {
                reserve_sets.tcp.extend(ranges_intersection.clone());
                reserve_sets.udp.extend(ranges_intersection);
            }
        }
    }
    reserve_sets
}

fn build_reserved_prefixes_ports(
    prefixes_and_ports_to_exclude_from_pools: &PrefixPortsSet,
) -> Option<DisjointRangesBTreeMap<IpRange, PortRange>> {
    if prefixes_and_ports_to_exclude_from_pools.is_empty() {
        return None;
    }
    let mut reserved_prefixes_ports = DisjointRangesBTreeMap::new();
    for prefix in prefixes_and_ports_to_exclude_from_pools {
        debug_assert!(prefix.ports().is_some());
        let Some(ports) = prefix.ports() else {
            error!("Stepped on a port-forwarding prefix without ports. This is a bug");
            continue;
        };
        reserved_prefixes_ports.insert(prefix.prefix().into(), ports);
    }
    Some(reserved_prefixes_ports)
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
    use super::{ReserveSets, find_masquerade_portfw_overlap};
    use config::external::overlay::vpcpeering::VpcExpose;
    use lpm::prefix::{L4Protocol, PortRange, PrefixPortsSet, PrefixWithOptionalPorts};

    fn prefix_with_ports(s: &str, start: u16, end: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(s.into(), Some(PortRange::new(start, end).unwrap()))
    }

    // tests for find_masquerade_portfw_overlap()

    #[test]
    fn find_masquerade_portfw_overlap_multiple_pf_exposes() {
        let expose = VpcExpose::empty()
            .make_masquerade(None)
            .unwrap()
            .ip("10.0.0.0/16".into())
            .ip("172.16.0.0/16".into())
            .as_range("192.168.0.0/16".into())
            .unwrap()
            .validate()
            .unwrap();
        let pf_expose1 = VpcExpose::empty()
            .make_port_forwarding(None, None)
            .unwrap()
            .ip(prefix_with_ports("10.0.1.0/24", 8080, 8090))
            .as_range(prefix_with_ports("192.168.1.0/24", 8080, 8090))
            .unwrap()
            .validate()
            .unwrap();
        let pf_expose2 = VpcExpose::empty()
            .make_port_forwarding(None, None)
            .unwrap()
            .ip(prefix_with_ports("172.16.5.0/24", 8080, 8090))
            .as_range(prefix_with_ports("192.168.2.0/24", 8080, 8090))
            .unwrap()
            .validate()
            .unwrap();
        let pf_exposes_vec = vec![&pf_expose1, &pf_expose2];
        let result = find_masquerade_portfw_overlap(&pf_exposes_vec, &expose);
        assert_eq!(
            result,
            ReserveSets {
                tcp: PrefixPortsSet::from([
                    prefix_with_ports("10.0.1.0/24", 8080, 8090),
                    prefix_with_ports("172.16.5.0/24", 8080, 8090),
                ]),
                udp: PrefixPortsSet::from([
                    prefix_with_ports("10.0.1.0/24", 8080, 8090),
                    prefix_with_ports("172.16.5.0/24", 8080, 8090),
                ]),
            }
        );
    }

    #[test]
    fn find_masquerade_portfw_overlap_with_ports() {
        let expose = VpcExpose::empty()
            .make_masquerade(None)
            .unwrap()
            .ip("10.0.0.0/24".into())
            .as_range("192.168.0.0/24".into())
            .unwrap()
            .validate()
            .unwrap();
        let pf_expose = VpcExpose::empty()
            .make_port_forwarding(None, None)
            .unwrap()
            .ip(prefix_with_ports("10.0.0.0/24", 8080, 8090))
            .as_range(prefix_with_ports("192.168.1.0/24", 8080, 8090))
            .unwrap()
            .validate()
            .unwrap();
        let pf_exposes_vec = vec![&pf_expose];
        let result = find_masquerade_portfw_overlap(&pf_exposes_vec, &expose);
        assert_eq!(
            result,
            ReserveSets {
                tcp: PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 8080, 8090)]),
                udp: PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 8080, 8090)]),
            }
        );
    }

    #[test]
    fn find_masquerade_portfw_overlap_with_ports_tcp() {
        let expose = VpcExpose::empty()
            .make_masquerade(None)
            .unwrap()
            .ip("10.0.0.0/24".into())
            .as_range("192.168.0.0/24".into())
            .unwrap()
            .validate()
            .unwrap();
        let pf_expose = VpcExpose::empty()
            .make_port_forwarding(None, Some(L4Protocol::Tcp)) // TCP only
            .unwrap()
            .ip(prefix_with_ports("10.0.0.0/24", 8080, 8090))
            .as_range(prefix_with_ports("192.168.1.0/24", 8080, 8090))
            .unwrap()
            .validate()
            .unwrap();
        let pf_exposes_vec = vec![&pf_expose];
        let result = find_masquerade_portfw_overlap(&pf_exposes_vec, &expose);
        assert_eq!(
            result,
            ReserveSets {
                tcp: PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 8080, 8090)]),
                udp: PrefixPortsSet::default()
            }
        );
    }

    #[test]
    fn find_masquerade_portfw_overlap_duplicates_collapsed() {
        // Two port-forwarding exposes with the same prefix should produce one entry
        let expose = VpcExpose::empty()
            .make_masquerade(None)
            .unwrap()
            .ip("10.0.0.0/16".into())
            .as_range("192.168.0.0/24".into())
            .unwrap()
            .validate()
            .unwrap();
        let pf_expose1 = VpcExpose::empty()
            .make_port_forwarding(None, None)
            .unwrap()
            .ip(prefix_with_ports("10.0.1.0/24", 8080, 8090))
            .as_range(prefix_with_ports("192.168.1.0/24", 8080, 8090))
            .unwrap()
            .validate()
            .unwrap();
        let pf_expose2 = VpcExpose::empty()
            .make_port_forwarding(None, None)
            .unwrap()
            .ip(prefix_with_ports("10.0.1.0/24", 8080, 8090))
            .as_range(prefix_with_ports("192.168.1.0/24", 8080, 8090))
            .unwrap()
            .validate()
            .unwrap();
        let pf_exposes_vec = vec![&pf_expose1, &pf_expose2];
        let result = find_masquerade_portfw_overlap(&pf_exposes_vec, &expose);
        assert_eq!(
            result,
            ReserveSets {
                tcp: PrefixPortsSet::from([prefix_with_ports("10.0.1.0/24", 8080, 8090)]),
                udp: PrefixPortsSet::from([prefix_with_ports("10.0.1.0/24", 8080, 8090)]),
            }
        );
    }
}
