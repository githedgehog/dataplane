// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIpWithBitmap;
use super::alloc::{IpAllocator, NatPool, PoolBitmap};
use super::{NatDefaultAllocator, PoolTable, PoolTableKey};
use crate::ranges::IpRange;
use crate::stateful::allocator::AllocatorError;
use crate::stateful::allocator_writer::StatefulNatConfig;
use crate::stateful::{NatAllocator, NatIp};
use config::ConfigError;
use config::external::overlay::vpc::Peering;
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
use config::utils::collapse_prefixes_peering;
use lpm::prefix::range_map::DisjointRangesBTreeMap;
use lpm::prefix::{IpPrefix, PortRange, Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tracing::debug;

impl NatDefaultAllocator {
    /// Build a [`NatDefaultAllocator`] from information collected from a [`VpcTable`] object. This
    /// information is passed as a [`StatefulNatConfig`].
    ///
    /// # Returns
    ///
    /// A [`NatDefaultAllocator`] that can be used to allocate NAT addresses, or a [`ConfigError`]
    /// if building the allocator fails.
    ///
    /// # Errors
    ///
    /// [`ConfigError::FailureApply`] if adding a peering fails.
    pub(crate) fn build_nat_allocator(config: &StatefulNatConfig) -> Result<Self, ConfigError> {
        debug!(
            "Building allocator for stateful NAT, from config: {:?}",
            config
        );
        let mut allocator = NatDefaultAllocator::new();
        for peering_data in config.iter() {
            allocator
                .add_peering_addresses(&peering_data.peering, peering_data.dst_vpc_id)
                .map_err(|e| ConfigError::FailureApply(e.to_string()))?;
        }
        Ok(allocator)
    }

    fn add_peering_addresses(
        &mut self,
        peering: &Peering,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<(), AllocatorError> {
        let new_peering = collapse_prefixes_peering(peering)
            .map_err(|e| AllocatorError::InternalIssue(e.to_string()))?;

        // Update tables for source NAT
        self.build_src_nat_pool_for_expose(&new_peering, dst_vpc_id)?;

        // Update table for destination NAT
        self.build_dst_nat_pool_for_expose(&new_peering, dst_vpc_id)?;

        Ok(())
    }

    fn build_src_nat_pool_for_expose(
        &mut self,
        peering: &Peering,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<(), AllocatorError> {
        build_nat_pool_generic(
            &peering.local,
            dst_vpc_id,
            VpcManifest::stateful_nat_exposes_44,
            VpcManifest::port_forwarding_exposes_44,
            VpcExpose::as_range_or_empty,
            |expose| &expose.ips,
            &mut self.pools_src44,
            NextHeader::ICMP,
        )?;

        build_nat_pool_generic(
            &peering.local,
            dst_vpc_id,
            VpcManifest::stateful_nat_exposes_66,
            VpcManifest::port_forwarding_exposes_66,
            VpcExpose::as_range_or_empty,
            |expose| &expose.ips,
            &mut self.pools_src66,
            NextHeader::ICMP6,
        )
    }

    fn build_dst_nat_pool_for_expose(
        &mut self,
        peering: &Peering,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<(), AllocatorError> {
        build_nat_pool_generic(
            &peering.remote,
            dst_vpc_id,
            VpcManifest::stateful_nat_exposes_44,
            VpcManifest::port_forwarding_exposes_44,
            |expose| &expose.ips,
            VpcExpose::as_range_or_empty,
            &mut self.pools_dst44,
            NextHeader::ICMP,
        )?;

        build_nat_pool_generic(
            &peering.remote,
            dst_vpc_id,
            VpcManifest::stateful_nat_exposes_66,
            VpcManifest::port_forwarding_exposes_66,
            |expose| &expose.ips,
            VpcExpose::as_range_or_empty,
            &mut self.pools_dst66,
            NextHeader::ICMP6,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn build_nat_pool_generic<'a, I: NatIpWithBitmap, J: NatIpWithBitmap, F, FIter, G, H, P, PIter>(
    manifest: &'a VpcManifest,
    dst_vpc_id: VpcDiscriminant,
    // A filter to select relevant exposes: those with stateful NAT, for the relevant IP version
    exposes_filter: F,
    // A filter to select other exposes with port forwarding, for the relevant IP version
    port_forwarding_exposes_filter: P,
    // A function to get the list of prefixes to translate into
    original_prefixes_from_expose: G,
    // A function to get the list of prefixes to translate from
    target_prefixes_from_expose: H,
    table: &mut PoolTable<I, J>,
    icmp_proto: NextHeader,
) -> Result<(), AllocatorError>
where
    F: FnOnce(&'a VpcManifest) -> FIter,
    FIter: Iterator<Item = &'a VpcExpose>,
    P: FnOnce(&'a VpcManifest) -> PIter,
    PIter: Iterator<Item = &'a VpcExpose>,
    G: Fn(&'a VpcExpose) -> &'a PrefixPortsSet,
    H: Fn(&'a VpcExpose) -> &'a PrefixPortsSet,
{
    let port_forwarding_exposes: Vec<&'a VpcExpose> =
        port_forwarding_exposes_filter(manifest).collect();
    exposes_filter(manifest).try_for_each(|expose| {
        let prefixes_and_ports_to_exclude_from_pools =
            find_masquerade_portfw_overlap(&port_forwarding_exposes, expose);

        // We should always have an idle timeout if we process this expose for stateful NAT.
        let idle_timeout = expose.idle_timeout().unwrap_or_else(|| unreachable!());

        let tcp_ip_allocator = ip_allocator_for_prefixes(
            original_prefixes_from_expose(expose),
            idle_timeout,
            &prefixes_and_ports_to_exclude_from_pools,
        )?;
        let udp_ip_allocator = tcp_ip_allocator.deep_clone()?;
        let icmp_ip_allocator = tcp_ip_allocator.deep_clone()?;

        add_pool_entries(
            table,
            target_prefixes_from_expose(expose),
            dst_vpc_id,
            &tcp_ip_allocator,
            &udp_ip_allocator,
            &icmp_ip_allocator,
            icmp_proto,
        )
    })
}

fn find_masquerade_portfw_overlap<'a>(
    port_forwarding_exposes: &Vec<&'a VpcExpose>,
    expose: &'a VpcExpose,
) -> PrefixPortsSet {
    port_forwarding_exposes
        .iter()
        .flat_map(|pf_expose| pf_expose.ips.intersection_prefixes_and_ports(&expose.ips))
        .collect()
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
) -> Result<(), AllocatorError> {
    for prefix in prefixes {
        let key = pool_table_tcp_key_for_expose(prefix, dst_vpc_id)?;
        insert_per_proto_entries(
            table,
            key,
            tcp_allocator,
            udp_allocator,
            icmp_allocator,
            icmp_proto,
        );
    }
    Ok(())
}

fn insert_per_proto_entries<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    key: PoolTableKey<I>,
    tcp_allocator: &IpAllocator<J>,
    udp_allocator: &IpAllocator<J>,
    icmp_allocator: &IpAllocator<J>,
    icmp_proto: NextHeader,
) {
    // We insert three times the entry, once for TCP, once for UDP and once for ICMP (v4 or v6
    // depending on the case). Allocations for TCP, for example, do not affect allocations for UDP
    // or for ICMP, the space defined by the combination of IP addresses and L4 ports/id is distinct
    // for each protocol.

    let mut tcp_key = key.clone();
    tcp_key.protocol = NextHeader::TCP;
    table.add_entry(tcp_key, tcp_allocator.clone());

    let mut udp_key = key.clone();
    udp_key.protocol = NextHeader::UDP;
    table.add_entry(udp_key, udp_allocator.clone());

    let mut icmp_key = key;
    icmp_key.protocol = icmp_proto;
    table.add_entry(icmp_key, icmp_allocator.clone());
}

fn ip_allocator_for_prefixes<J: NatIpWithBitmap>(
    prefixes: &PrefixPortsSet,
    idle_timeout: Duration,
    prefixes_and_ports_to_exclude_from_pools: &PrefixPortsSet,
) -> Result<IpAllocator<J>, AllocatorError> {
    let pool = create_natpool(
        prefixes,
        prefixes_and_ports_to_exclude_from_pools,
        idle_timeout,
    )?;
    let allocator = IpAllocator::new(pool);
    Ok(allocator)
}

fn create_natpool<J: NatIpWithBitmap>(
    prefixes: &PrefixPortsSet,
    prefixes_and_ports_to_exclude_from_pools: &PrefixPortsSet,
    idle_timeout: Duration,
) -> Result<NatPool<J>, AllocatorError> {
    // Build mappings for IPv6 <-> u32 bitmap translation
    let (bitmap_mapping, reverse_bitmap_mapping) = create_ipv6_bitmap_mappings(
        &prefixes
            .iter()
            // FIXME: Add port range, too
            .map(PrefixWithOptionalPorts::prefix)
            .collect::<BTreeSet<Prefix>>(),
    )?;

    // Mark all addresses as available (free) in bitmap
    let mut bitmap = PoolBitmap::new();
    prefixes
        .iter()
        // FIXME: Add port range, too
        .try_for_each(|prefix| bitmap.add_prefix(&prefix.prefix(), &reverse_bitmap_mapping))?;

    let reserved_prefixes_ports =
        build_reserved_prefixes_ports(prefixes_and_ports_to_exclude_from_pools)?;

    Ok(NatPool::new(
        bitmap,
        bitmap_mapping,
        reverse_bitmap_mapping,
        reserved_prefixes_ports,
        idle_timeout,
    ))
}

fn build_reserved_prefixes_ports(
    prefixes_and_ports_to_exclude_from_pools: &PrefixPortsSet,
) -> Result<Option<DisjointRangesBTreeMap<IpRange, PortRange>>, AllocatorError> {
    if prefixes_and_ports_to_exclude_from_pools.is_empty() {
        return Ok(None);
    }
    let mut reserved_prefixes_ports = DisjointRangesBTreeMap::new();
    for prefix in prefixes_and_ports_to_exclude_from_pools {
        reserved_prefixes_ports.insert(
            prefix.prefix().into(),
            prefix.ports().ok_or(AllocatorError::InternalIssue(format!(
                "Expected port range for port forwarding prefix {prefix:?}"
            )))?,
        );
    }
    Ok(Some(reserved_prefixes_ports))
}

fn pool_table_tcp_key_for_expose<I: NatIp>(
    prefix: &PrefixWithOptionalPorts,
    dst_vpc_id: VpcDiscriminant,
) -> Result<PoolTableKey<I>, AllocatorError> {
    let (addr, addr_range_end) = prefix_bounds(prefix)?;
    Ok(PoolTableKey::new(
        NextHeader::TCP,
        dst_vpc_id,
        addr,
        addr_range_end,
    ))
}

fn prefix_bounds<I: NatIp>(prefix: &PrefixWithOptionalPorts) -> Result<(I, I), AllocatorError> {
    let addr = I::try_from_addr(prefix.prefix().as_address())
        .map_err(|()| AllocatorError::InternalIssue("Failed to build IP address".to_string()))?;
    let addr_range_end = match prefix.prefix() {
        Prefix::IPV4(p) => I::try_from_ipv4_addr(p.last_address()).map_err(|()| {
            AllocatorError::InternalIssue("Failed to build IPv4 address from prefix".to_string())
        })?,
        Prefix::IPV6(p) => I::try_from_ipv6_addr(p.last_address()).map_err(|()| {
            AllocatorError::InternalIssue("Failed to build IPv6 address from prefix".to_string())
        })?,
    };
    // FIXME: Account for port ranges
    Ok((addr, addr_range_end))
}

// The allocator's bitmap contains u32 only. For IPv4, it maps well to the address space. For IPv6,
// we need some mapping to associate IPv6 addresses with u32 indices. This also means that we cannot
// use more than 2^32 addresses for one expose, for NAT. If the prefixes we get contain more, we'll
// just ignore the remaining addresses. Hardware limitations are such that working with 4 billion
// allocated addresses is unreallistic anyway.
#[allow(clippy::type_complexity)]
fn create_ipv6_bitmap_mappings(
    prefixes: &BTreeSet<Prefix>,
) -> Result<(BTreeMap<u32, u128>, BTreeMap<u128, u32>), AllocatorError> {
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
            index += u32::try_from(u128::try_from(p.size()).map_err(|_| {
                AllocatorError::InternalIssue("Failed to convert prefix size to u128".to_string())
            })?)
            .map_err(|_| {
                AllocatorError::InternalIssue("Failed to convert prefix size to u32".to_string())
            })?;
        }
    }
    Ok((bitmap_mapping, reverse_bitmap_mapping))
}

#[cfg(test)]
mod tests {
    use super::find_masquerade_portfw_overlap;
    use config::external::overlay::vpcpeering::VpcExpose;
    use lpm::prefix::{PortRange, PrefixPortsSet, PrefixWithOptionalPorts};

    fn prefix_with_ports(s: &str, start: u16, end: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(s.into(), Some(PortRange::new(start, end).unwrap()))
    }

    // find_masquerade_portfw_overlap()

    #[test]
    fn find_masquerade_portfw_overlap_multiple_pf_exposes() {
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .ip("172.16.0.0/16".into());
        let pf_expose1 = VpcExpose::empty().ip("10.0.1.0/24".into());
        let pf_expose2 = VpcExpose::empty().ip("172.16.5.0/24".into());
        let pf_exposes_vec = vec![&pf_expose1, &pf_expose2];
        let result = find_masquerade_portfw_overlap(&pf_exposes_vec, &expose);
        assert_eq!(
            result,
            PrefixPortsSet::from(["10.0.1.0/24".into(), "172.16.5.0/24".into()])
        );
    }

    #[test]
    fn find_masquerade_portfw_overlap_with_ports() {
        let expose = VpcExpose::empty().ip("10.0.0.0/24".into());
        let pf_expose = VpcExpose::empty().ip(prefix_with_ports("10.0.0.0/24", 8080, 8090));
        let pf_exposes_vec = vec![&pf_expose];
        let result = find_masquerade_portfw_overlap(&pf_exposes_vec, &expose);
        assert_eq!(
            result,
            PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 8080, 8090)])
        );
    }

    #[test]
    fn find_masquerade_portfw_overlap_duplicates_collapsed() {
        // Two port-forwarding exposes with the same prefix should produce one entry
        let expose = VpcExpose::empty().ip("10.0.0.0/16".into());
        let pf_expose1 = VpcExpose::empty().ip("10.0.1.0/24".into());
        let pf_expose2 = VpcExpose::empty().ip("10.0.1.0/24".into());
        let pf_exposes_vec = vec![&pf_expose1, &pf_expose2];
        let result = find_masquerade_portfw_overlap(&pf_exposes_vec, &expose);
        assert_eq!(result.len(), 1);
        assert_eq!(result, PrefixPortsSet::from(["10.0.1.0/24".into()]));
    }
}
