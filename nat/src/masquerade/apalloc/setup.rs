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
use std::time::Duration;
use tracing::{error, warn};

const DEFAULT_MASQUERADE_IDLE_TIMEOUT: Duration = Duration::from_mins(2);

impl NatAllocator {
    pub(crate) fn add_peering_addresses(
        &mut self,
        peering: &ValidatedPeering,
        dst_vpc_id: VpcDiscriminant,
    ) {
        build_nat_pool_generic(
            peering.local(),
            dst_vpc_id,
            ValidatedManifest::masquerade_exposes_44,
            ValidatedManifest::port_forwarding_exposes_44,
            &mut self.pools_src44,
            NextHeader::ICMP,
            self.randomize,
        );

        build_nat_pool_generic(
            peering.local(),
            dst_vpc_id,
            ValidatedManifest::masquerade_exposes_66,
            ValidatedManifest::port_forwarding_exposes_66,
            &mut self.pools_src66,
            NextHeader::ICMP6,
            self.randomize,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn build_nat_pool_generic<'a, I: NatIpWithBitmap, J: NatIpWithBitmap, F, FIter, P, PIter>(
    manifest: &'a ValidatedManifest,
    dst_vpc_id: VpcDiscriminant,
    // A filter to select relevant exposes: those with masquerade, for the relevant IP version
    exposes_filter: F,
    // A filter to select other exposes with port forwarding, for the relevant IP version
    port_forwarding_exposes_filter: P,
    table: &mut PoolTable<I, J>,
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
        let prefixes_and_ports_to_exclude_from_pools =
            find_masquerade_portfw_overlap(&port_forwarding_exposes, expose);

        let idle_timeout = expose
            .idle_timeout()
            .unwrap_or(DEFAULT_MASQUERADE_IDLE_TIMEOUT);

        // TCP/UDP masquerade allocators should avoid the IANA system/well-known range
        // (0-1023). ICMP identifiers are allocated independently and are not subject to that
        // TCP/UDP source-port policy.
        let tcp_ip_allocator = ip_allocator_for_prefixes(
            expose.as_range_or_empty(),
            idle_timeout,
            &prefixes_and_ports_to_exclude_from_pools.tcp,
            randomize,
            true,
        );
        let udp_ip_allocator = ip_allocator_for_prefixes(
            expose.as_range_or_empty(),
            idle_timeout,
            &prefixes_and_ports_to_exclude_from_pools.udp,
            randomize,
            true,
        );
        let icmp_ip_allocator = ip_allocator_for_prefixes(
            expose.as_range_or_empty(),
            idle_timeout,
            &PrefixPortsSet::default(),
            randomize,
            false,
        );

        add_pool_entries(
            table,
            expose.ips(),
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
    dst_vpc_id: VpcDiscriminant,
) -> PoolTableKey<I> {
    let (addr, addr_range_end) = prefix_bounds(prefix);
    PoolTableKey::new(protocol, dst_vpc_id, addr, addr_range_end)
}

#[allow(clippy::too_many_arguments)]
fn add_pool_entries<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    prefixes: &PrefixPortsSet,
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

        let tcp_key = pool_table_key_for_expose(prefix, NextHeader::TCP, dst_vpc_id);
        let udp_key = pool_table_key_for_expose(prefix, NextHeader::UDP, dst_vpc_id);
        let icmp_key = pool_table_key_for_expose(prefix, icmp_proto, dst_vpc_id);

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
    let mappings = create_ipv6_bitmap_mappings(
        &prefixes
            .iter()
            // FIXME: Add port range, too
            .map(PrefixWithOptionalPorts::prefix)
            .collect::<BTreeSet<Prefix>>(),
    );

    // Mark all addresses as available (free) in bitmap.
    //
    // IPv4 prefixes index by address directly.  IPv6 prefixes come from the mapping's `ranges`
    // rather than from the prefixes themselves, because only the mapping knows how much of each
    // prefix fits in the bitmap -- deriving the range from a prefix's own size would ask the bitmap
    // for offsets it does not have.
    let mut bitmap = PoolBitmap::new();
    prefixes
        .iter()
        // FIXME: Add port range, too
        .map(PrefixWithOptionalPorts::prefix)
        .for_each(|prefix| bitmap.add_v4_prefix(&prefix));
    for &(base, end) in &mappings.ranges {
        bitmap.add_offset_range(base, end);
    }

    let bitmap_mapping = mappings.forward;
    let reverse_bitmap_mapping = mappings.reverse;

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

/// IPv6 prefixes, projected onto the allocator's `u32` bitmap index space.
///
/// The bitmap indexes addresses with a `u32`. For IPv4 an address *is* its index. For IPv6 the
/// address space is far larger, so prefixes are laid end to end in a `u32` offset space, which caps
/// the total usable at `2^32` addresses across all of an expose's prefixes. Anything beyond that is
/// dropped: allocating four billion addresses is not reachable in practice, and a masquerade pool
/// does not need to offer every address of a large prefix to work.
pub(crate) struct Ipv6BitmapMappings {
    /// Offset -> network address of the prefix that offset falls in.
    pub(crate) forward: BTreeMap<u32, u128>,
    /// Network address of a prefix -> its base offset.
    pub(crate) reverse: BTreeMap<u128, u32>,
    /// `(first offset, last offset)` inclusive, per mapped prefix.
    ///
    /// Carried separately because it is the *usable* window, not the prefix's own extent: the last
    /// prefix to fit may be truncated, and a prefix that does not fit at all is absent entirely.
    /// The bitmap must be populated from this rather than from prefix sizes.
    ///
    /// An inclusive end rather than a count, because a full budget is `2^32` addresses, which is one
    /// more than a `u32` can hold; the last *offset* is `u32::MAX` and always fits.
    pub(crate) ranges: Vec<(u32, u32)>,
}

/// Lay `prefixes`' IPv6 members out in the bitmap's `u32` offset space.
///
/// Truncates the address space to `u32::MAX + 1` addresses in total, dropping whole prefixes once
/// the budget is exhausted. A prefix is only ever mapped together with the number of its addresses
/// that are actually representable, so no part of the allocator can be asked for an offset outside
/// the bitmap.
fn create_ipv6_bitmap_mappings(prefixes: &BTreeSet<Prefix>) -> Ipv6BitmapMappings {
    /// Addresses representable by a `u32` index.
    const BUDGET: u128 = 1 << 32;

    let mut mappings = Ipv6BitmapMappings {
        forward: BTreeMap::new(),
        reverse: BTreeMap::new(),
        ranges: Vec::new(),
    };
    let mut index: u128 = 0;

    for prefix in prefixes {
        let Prefix::IPV6(p) = prefix else { continue };

        let remaining = BUDGET - index;
        if remaining == 0 {
            warn!("Ran out of NAT bitmap space before prefix {p}; it will not be used");
            continue;
        }

        // `PrefixSize` is not always a `u128` -- a `::/0` holds `2^128` addresses -- so treat
        // anything that does not convert as "larger than the budget", which it necessarily is.
        let size = u128::try_from(p.size()).unwrap_or(u128::MAX);
        let usable = size.min(remaining);
        if usable < size {
            warn!(
                "NAT bitmap space exhausted within prefix {p}: using {usable} of {size} addresses"
            );
        }

        // Exact by construction: `index < BUDGET` and `index + usable <= BUDGET`, so both the base
        // and the inclusive end land in `0..=u32::MAX`.
        let (Ok(base), Ok(end)) = (u32::try_from(index), u32::try_from(index + usable - 1)) else {
            error!(
                "Bitmap window {index}..={} exceeds u32; dropping prefix {p}",
                index + usable - 1
            );
            continue;
        };

        let start_address = p.network().to_bits();
        mappings.forward.insert(base, start_address);
        mappings.reverse.insert(start_address, base);
        mappings.ranges.push((base, end));

        index += usable;
    }
    mappings
}

#[cfg(test)]
mod tests {
    use super::{ReserveSets, create_ipv6_bitmap_mappings, find_masquerade_portfw_overlap};
    use lpm::prefix::Prefix;
    use std::collections::BTreeSet;
    use std::str::FromStr;

    /// Addresses a `u32` bitmap index can address.
    const BUDGET: u128 = 1 << 32;

    fn v6_set(cidrs: &[&str]) -> BTreeSet<Prefix> {
        cidrs
            .iter()
            .map(|c| Prefix::from_str(c).expect("test prefixes must parse"))
            .collect()
    }

    /// The whole budget, and not one address more.
    ///
    /// A `/96` holds exactly `2^32` addresses, so its window runs to `u32::MAX` inclusive.  Counting
    /// addresses rather than offsets would need `2^32`, which does not fit a `u32` -- an earlier cut
    /// of this fix dropped the prefix outright rather than truncating it.
    #[test]
    fn test_prefix_of_exactly_the_budget_fills_the_bitmap() {
        let mappings = create_ipv6_bitmap_mappings(&v6_set(&["2001:db8::/96"]));
        assert_eq!(mappings.ranges, vec![(0, u32::MAX)]);
        assert_eq!(mappings.forward.len(), 1);
        assert_eq!(mappings.reverse.len(), 1);
    }

    /// A prefix wider than the bitmap is truncated to what fits, not dropped and not fatal.
    #[test]
    fn test_prefix_wider_than_the_budget_is_truncated() {
        let mappings = create_ipv6_bitmap_mappings(&v6_set(&["2001:db8::/64"]));
        assert_eq!(
            mappings.ranges,
            vec![(0, u32::MAX)],
            "a /64 should yield the full budget, truncated"
        );
    }

    /// Once the budget is gone, later prefixes are dropped rather than aliasing earlier ones.
    #[test]
    fn test_prefixes_after_the_budget_is_exhausted_are_dropped() {
        let mappings = create_ipv6_bitmap_mappings(&v6_set(&["2001:db8::/64", "2001:db9::/96"]));
        assert_eq!(mappings.ranges.len(), 1, "only the first prefix fits");
        assert_eq!(mappings.forward.len(), 1);
        assert_eq!(mappings.reverse.len(), 1);
    }

    /// Prefixes that fit are laid end to end with no gap and no overlap.
    #[test]
    fn test_prefixes_are_packed_contiguously() {
        // Two /97s: half the budget each, so both fit exactly.
        let mappings = create_ipv6_bitmap_mappings(&v6_set(&["2001:db8::/97", "2001:db9::/97"]));
        let half = u32::try_from(BUDGET / 2).expect("half the budget fits a u32");
        assert_eq!(mappings.ranges, vec![(0, half - 1), (half, u32::MAX)]);
    }

    /// Every offset a mapped window contains must round-trip back to an address, and back again.
    #[test]
    fn test_window_bounds_round_trip() {
        use super::super::alloc::{map_address, map_offset};

        let mappings = create_ipv6_bitmap_mappings(&v6_set(&["2001:db8::/112", "2001:db9::/112"]));
        for &(base, end) in &mappings.ranges {
            for offset in [base, end] {
                let address = map_offset(offset, &mappings.forward)
                    .unwrap_or_else(|e| panic!("offset {offset} should map to an address: {e}"));
                let back = map_address(address, &mappings.reverse)
                    .unwrap_or_else(|e| panic!("address {address} should map back: {e}"));
                assert_eq!(offset, back, "round trip changed offset {offset}");
            }
        }
    }

    /// An address past a truncated prefix's window has no index, and says so rather than panicking.
    ///
    /// This is the path a flow allocated under a previous config takes when its address is no longer
    /// representable; it must invalidate the flow, not abort the process.
    #[test]
    fn test_address_beyond_truncated_window_is_an_error() {
        use super::super::alloc::map_address;
        use std::net::Ipv6Addr;

        let mappings = create_ipv6_bitmap_mappings(&v6_set(&["2001:db8::/64"]));
        // Inside the /64, but far past the first 2^32 addresses of it.
        let beyond =
            Ipv6Addr::from_str("2001:db8::ffff:ffff:ffff").expect("test address must parse");
        assert!(
            map_address(beyond, &mappings.reverse).is_err(),
            "an address outside the mapped window must not produce an index"
        );
    }

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
