// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIpWithBitmap;
use super::alloc::{IpAllocator, NatPool, PoolBitmap};
use super::{NatAllocator, PoolTable, PoolTableKey};
use crate::masquerade::natip::NatIp;
use crate::ranges::IpRange;
use config::external::overlay::vpc::ValidatedPeering;
use config::external::overlay::vpcpeering::{ValidatedExpose, ValidatedManifest};
use lpm::prefix::range_map::DisjointRangesBTreeMap;
use lpm::prefix::{
    IpPrefix, L4Protocol, PortRange, Prefix, PrefixPortsSet, PrefixWithOptionalPorts,
};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tracing::{error, warn};

const DEFAULT_MASQUERADE_IDLE_TIMEOUT: Duration = Duration::from_mins(2);

impl NatAllocator {
    pub(crate) fn add_peering_addresses(
        &mut self,
        peering: &ValidatedPeering,
        src_vpc_id: VpcDiscriminant,
        dst_vpc_id: VpcDiscriminant,
        registries: &mut PoolRegistries,
    ) {
        build_nat_pool_generic(
            peering.local(),
            src_vpc_id,
            dst_vpc_id,
            ValidatedManifest::masquerade_exposes_44,
            ValidatedManifest::port_forwarding_exposes_44,
            &mut self.pools_src44,
            &mut registries.v4,
            NextHeader::ICMP,
            self.randomize,
        );

        build_nat_pool_generic(
            peering.local(),
            src_vpc_id,
            dst_vpc_id,
            ValidatedManifest::masquerade_exposes_66,
            ValidatedManifest::port_forwarding_exposes_66,
            &mut self.pools_src66,
            &mut registries.v6,
            NextHeader::ICMP6,
            self.randomize,
        );
    }
}

///////////////////////////////////////////////////////////////////////////////
// Pool identity and registry
///////////////////////////////////////////////////////////////////////////////

/// Identity of an address and port pool, as seen from the *public* side of the NAT.
///
/// What an allocator hands out is a public `(address, port)` pair, so the public range is what
/// decides whether two exposes describe the same pool. Two allocators built over the same public
/// range, for the same protocol and towards the same peer VPC, would each believe they owned the
/// whole range, hand out the same `(address, port)` twice, and produce colliding reverse flow
/// keys.
///
/// Pools are *identified* here by their public range. They are separately *looked up* by the
/// private prefixes they serve, in [`PoolTable`], because the private source address is all we
/// have on the first packet of a flow.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PoolIdentity {
    protocol: NextHeader,
    dst_vpc_id: VpcDiscriminant,
    public_range: PrefixPortsSet,
}

/// How a pool allocates, as opposed to [`PoolIdentity`], which is what a pool *is*. The policy
/// plays no part in deciding whether two exposes share a pool.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PoolPolicy {
    idle_timeout: Duration,
    reserved: PrefixPortsSet,
    exclude_wellknown_ports: bool,
}

#[derive(Debug)]
struct RegisteredPool<J: NatIpWithBitmap> {
    allocator: IpAllocator<J>,
    policy: PoolPolicy,
}

/// The allocators built for one IP version, keyed by [`PoolIdentity`].
///
/// A configuration can describe the same public pool more than once. Exposes are only checked for
/// collisions against the other exposes of the same manifest, and a manifest belongs to a single
/// peering, so two VPCs that both peer with the same destination VPC can masquerade onto the same
/// public range without anything rejecting it. Both reach the allocator under the same protocol
/// and destination discriminant, and have to share one allocator.
#[derive(Debug)]
struct PoolRegistry<J: NatIpWithBitmap> {
    pools: BTreeMap<PoolIdentity, RegisteredPool<J>>,
}

impl<J: NatIpWithBitmap> Default for PoolRegistry<J> {
    fn default() -> Self {
        Self {
            pools: BTreeMap::new(),
        }
    }
}

impl<J: NatIpWithBitmap> PoolRegistry<J> {
    /// Return the allocator that owns `public_range`, building it if this is the first expose to
    /// claim that range for this protocol and peer VPC. The returned allocator shares its
    /// underlying pool with every other holder of the same identity.
    fn get_or_create(
        &mut self,
        protocol: NextHeader,
        dst_vpc_id: VpcDiscriminant,
        public_range: &PrefixPortsSet,
        policy: PoolPolicy,
        randomize: bool,
    ) -> IpAllocator<J> {
        let identity = PoolIdentity {
            protocol,
            dst_vpc_id,
            public_range: public_range.clone(),
        };

        if let Some(registered) = self.pools.get(&identity) {
            if registered.policy != policy {
                warn!(
                    "Public range {public_range:?} is masqueraded onto more than once for \
                     {protocol} towards {dst_vpc_id}, with differing allocation policies. \
                     Sharing the pool, and keeping the policy that was declared first."
                );
            }
            return registered.allocator.clone();
        }

        self.report_partial_overlaps(&identity);

        let allocator = ip_allocator_for_prefixes(
            public_range,
            policy.idle_timeout,
            &policy.reserved,
            randomize,
            policy.exclude_wellknown_ports,
        );
        self.pools.insert(
            identity,
            RegisteredPool {
                allocator: allocator.clone(),
                policy,
            },
        );
        allocator
    }

    // Pools are shared only when their public ranges match exactly. Ranges that merely overlap
    // still end up with one allocator each, neither aware of what the other hands out, so report
    // them: that is a configuration we cannot serve correctly.
    fn report_partial_overlaps(&self, identity: &PoolIdentity) {
        for existing in self.pools.keys() {
            if existing.protocol != identity.protocol || existing.dst_vpc_id != identity.dst_vpc_id
            {
                continue;
            }
            if !existing
                .public_range
                .intersection_prefixes_and_ports(&identity.public_range)
                .is_empty()
            {
                error!(
                    "Public ranges {:?} and {:?} overlap without being identical, for {} towards \
                     {}. The same address and port may be allocated twice.",
                    existing.public_range,
                    identity.public_range,
                    identity.protocol,
                    identity.dst_vpc_id,
                );
            }
        }
    }
}

/// The [`PoolRegistry`] for each IP version, held only while a [`NatAllocator`] is being built.
/// The allocators themselves are kept alive afterwards by the pool tables referencing them.
#[derive(Debug, Default)]
pub(crate) struct PoolRegistries {
    v4: PoolRegistry<Ipv4Addr>,
    v6: PoolRegistry<Ipv6Addr>,
}

#[allow(clippy::too_many_arguments)]
fn build_nat_pool_generic<'a, I: NatIpWithBitmap, J: NatIpWithBitmap, F, FIter, P, PIter>(
    manifest: &'a ValidatedManifest,
    src_vpc_id: VpcDiscriminant,
    dst_vpc_id: VpcDiscriminant,
    // A filter to select relevant exposes: those with masquerade, for the relevant IP version
    exposes_filter: F,
    // A filter to select other exposes with port forwarding, for the relevant IP version
    port_forwarding_exposes_filter: P,
    table: &mut PoolTable<I, J>,
    registry: &mut PoolRegistry<J>,
    icmp_proto: NextHeader,
    randomize: bool,
) where
    F: FnOnce(&'a ValidatedManifest) -> FIter,
    FIter: Iterator<Item = &'a ValidatedExpose>,
    P: FnOnce(&'a ValidatedManifest) -> PIter,
    PIter: Iterator<Item = &'a ValidatedExpose>,
{
    let port_forwarding_exposes: Vec<&'a ValidatedExpose> =
        port_forwarding_exposes_filter(manifest).collect();

    exposes_filter(manifest).for_each(|expose| {
        let ReserveSets {
            tcp: tcp_reserved,
            udp: udp_reserved,
        } = find_masquerade_portfw_overlap(&port_forwarding_exposes, expose);

        let idle_timeout = expose
            .idle_timeout()
            .unwrap_or(DEFAULT_MASQUERADE_IDLE_TIMEOUT);
        let public_range = expose.as_range_or_empty();

        // TCP/UDP masquerade allocators should avoid the IANA system/well-known range
        // (0-1023). ICMP identifiers are allocated independently and are not subject to that
        // TCP/UDP source-port policy.
        let tcp_ip_allocator = registry.get_or_create(
            NextHeader::TCP,
            dst_vpc_id,
            public_range,
            PoolPolicy {
                idle_timeout,
                reserved: tcp_reserved,
                exclude_wellknown_ports: true,
            },
            randomize,
        );
        let udp_ip_allocator = registry.get_or_create(
            NextHeader::UDP,
            dst_vpc_id,
            public_range,
            PoolPolicy {
                idle_timeout,
                reserved: udp_reserved,
                exclude_wellknown_ports: true,
            },
            randomize,
        );
        let icmp_ip_allocator = registry.get_or_create(
            icmp_proto,
            dst_vpc_id,
            public_range,
            PoolPolicy {
                idle_timeout,
                reserved: PrefixPortsSet::default(),
                exclude_wellknown_ports: false,
            },
            randomize,
        );

        add_pool_entries(
            table,
            expose.ips(),
            src_vpc_id,
            dst_vpc_id,
            &tcp_ip_allocator,
            &udp_ip_allocator,
            &icmp_ip_allocator,
            icmp_proto,
        );
    });
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ReserveSets {
    tcp: PrefixPortsSet,
    udp: PrefixPortsSet,
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

fn pool_table_key_for_expose<I: NatIp>(
    prefix: &PrefixWithOptionalPorts,
    protocol: NextHeader,
    src_vpc_id: VpcDiscriminant,
    dst_vpc_id: VpcDiscriminant,
) -> PoolTableKey<I> {
    let (addr, addr_range_end) = prefix_bounds(prefix);
    PoolTableKey::new(protocol, src_vpc_id, dst_vpc_id, addr, addr_range_end)
}

#[allow(clippy::too_many_arguments)]
fn add_pool_entries<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    prefixes: &PrefixPortsSet,
    src_vpc_id: VpcDiscriminant,
    dst_vpc_id: VpcDiscriminant,
    tcp_allocator: &IpAllocator<J>,
    udp_allocator: &IpAllocator<J>,
    icmp_allocator: &IpAllocator<J>,
    icmp_proto: NextHeader,
) {
    for prefix in prefixes {
        // We insert three times the entry, once for TCP, once for UDP and once for ICMP (v4 or v6
        // depending on the case). Allocations for TCP, for example, do not affect allocations for UDP
        // or for ICMP, the space defined by the combination of IP addresses and L4 ports/id is distinct
        // for each protocol.

        let tcp_key = pool_table_key_for_expose(prefix, NextHeader::TCP, src_vpc_id, dst_vpc_id);
        let udp_key = pool_table_key_for_expose(prefix, NextHeader::UDP, src_vpc_id, dst_vpc_id);
        let icmp_key = pool_table_key_for_expose(prefix, icmp_proto, src_vpc_id, dst_vpc_id);

        table.add_entry(tcp_key, tcp_allocator.clone());
        table.add_entry(udp_key, udp_allocator.clone());
        table.add_entry(icmp_key, icmp_allocator.clone());
    }
}

fn ip_allocator_for_prefixes<J: NatIpWithBitmap>(
    prefixes: &PrefixPortsSet,
    idle_timeout: Duration,
    prefixes_and_ports_to_exclude_from_pools: &PrefixPortsSet,
    randomize: bool,
    exclude_wellknown_ports: bool,
) -> IpAllocator<J> {
    let pool = create_natpool(
        prefixes,
        prefixes_and_ports_to_exclude_from_pools,
        idle_timeout,
        exclude_wellknown_ports,
    );
    IpAllocator::new(pool, randomize)
}

fn create_natpool<J: NatIpWithBitmap>(
    prefixes: &PrefixPortsSet,
    prefixes_and_ports_to_exclude_from_pools: &PrefixPortsSet,
    idle_timeout: Duration,
    exclude_wellknown_ports: bool,
) -> NatPool<J> {
    // Build mappings for IPv6 <-> u32 bitmap translation
    let (bitmap_mapping, reverse_bitmap_mapping) = create_ipv6_bitmap_mappings(
        &prefixes
            .iter()
            // FIXME: Add port range, too
            .map(PrefixWithOptionalPorts::prefix)
            .collect::<BTreeSet<Prefix>>(),
    );

    // Mark all addresses as available (free) in bitmap
    let mut bitmap = PoolBitmap::new();
    prefixes
        .iter()
        // FIXME: Add port range, too
        .for_each(|prefix| bitmap.add_prefix(&prefix.prefix(), &reverse_bitmap_mapping));

    let reserved_prefixes_ports =
        build_reserved_prefixes_ports(prefixes_and_ports_to_exclude_from_pools);

    NatPool::new(
        bitmap,
        bitmap_mapping,
        reverse_bitmap_mapping,
        reserved_prefixes_ports,
        idle_timeout,
        exclude_wellknown_ports,
    )
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

fn prefix_bounds<I: NatIp>(prefix: &PrefixWithOptionalPorts) -> (I, I) {
    let addr = I::try_from_addr(prefix.prefix().as_address()).unwrap_or_else(|()| unreachable!());
    let addr_range_end =
        I::try_from_addr(prefix.prefix().last_address()).unwrap_or_else(|()| unreachable!());
    // FIXME: Account for port ranges
    (addr, addr_range_end)
}

// The allocator's bitmap contains u32 only. For IPv4, it maps well to the address space. For IPv6,
// we need some mapping to associate IPv6 addresses with u32 indices. This also means that we cannot
// use more than 2^32 addresses for one expose, for NAT. If the prefixes we get contain more, we'll
// just ignore the remaining addresses. Hardware limitations are such that working with 4 billion
// allocated addresses is unreallistic anyway.
#[allow(clippy::type_complexity)]
fn create_ipv6_bitmap_mappings(
    prefixes: &BTreeSet<Prefix>,
) -> (BTreeMap<u32, u128>, BTreeMap<u128, u32>) {
    let mut bitmap_mapping = BTreeMap::new();
    let mut reverse_bitmap_mapping = BTreeMap::new();
    let mut index = 0;

    for prefix in prefixes {
        if let Prefix::IPV6(p) = prefix {
            let start_address = p.network().to_bits();
            bitmap_mapping.insert(index, start_address);
            reverse_bitmap_mapping.insert(start_address, index);
            if p.size() + u128::from(index) >= 2_u128.pow(32) {
                break;
            }
            let Ok(psize) = u128::try_from(p.size()) else {
                error!("Failed to get u128 from prefix {:#?}", p.size());
                continue;
            };
            let Ok(psize_u32) = u32::try_from(psize) else {
                error!("Failed to convert {psize} to u32");
                continue;
            };
            index += psize_u32;
        }
    }
    (bitmap_mapping, reverse_bitmap_mapping)
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
