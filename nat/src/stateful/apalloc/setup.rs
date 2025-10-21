// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIpWithBitmap;
use super::alloc::{IpAllocator, NatPool, PoolBitmap};
use super::{NatDefaultAllocator, PoolTable, PoolTableKey};
use crate::stateful::allocator::AllocatorError;
use crate::stateful::allocator_writer::StatefulNatConfig;
use crate::stateful::{NatAllocator, NatIp};
use config::ConfigError;
use config::external::overlay::vpc::Peering;
use config::external::overlay::vpcpeering::VpcExpose;
use config::utils::collapse_prefixes_peering;
use lpm::prefix::{IpPrefix, Prefix};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

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
        let mut allocator = NatDefaultAllocator::new();
        for peering_data in config.iter() {
            allocator
                .add_peering_addresses(
                    &peering_data.peering,
                    peering_data.src_vpc_id,
                    peering_data.dst_vpc_id,
                )
                .map_err(|e| ConfigError::FailureApply(e.to_string()))?;
        }
        Ok(allocator)
    }

    fn add_peering_addresses(
        &mut self,
        peering: &Peering,
        src_vpc_id: VpcDiscriminant,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<(), AllocatorError> {
        let new_peering = collapse_prefixes_peering(peering)
            .map_err(|e| AllocatorError::InternalIssue(e.to_string()))?;

        // Update table for source NAT
        self.build_src_nat_pool_for_expose(&new_peering, src_vpc_id, dst_vpc_id)?;

        // Update table for destination NAT
        self.build_dst_nat_pool_for_expose(&new_peering, src_vpc_id, dst_vpc_id)?;

        Ok(())
    }

    fn build_src_nat_pool_for_expose(
        &mut self,
        peering: &Peering,
        src_vpc_id: VpcDiscriminant,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<(), AllocatorError> {
        peering
            .local
            .stateful_nat_exposes_44()
            .try_for_each(|expose| {
                // We should always have an idle timeout if we process this expose for stateful NAT.
                let idle_timeout = expose.idle_timeout().unwrap_or_else(|| unreachable!());
                let tcp_ip_allocator =
                    ip_allocator_for_prefixes(expose.as_range_or_empty(), idle_timeout)?;
                let udp_ip_allocator = tcp_ip_allocator.deep_clone()?;
                build_src_nat_pool_generic(
                    &mut self.pools_src44,
                    expose,
                    src_vpc_id,
                    dst_vpc_id,
                    &tcp_ip_allocator,
                    &udp_ip_allocator,
                )
            })?;

        peering
            .local
            .stateful_nat_exposes_66()
            .try_for_each(|expose| {
                // We should always have an idle timeout if we process this expose for stateful NAT.
                let idle_timeout = expose.idle_timeout().unwrap_or_else(|| unreachable!());
                let tcp_ip_allocator =
                    ip_allocator_for_prefixes(expose.as_range_or_empty(), idle_timeout)?;
                let udp_ip_allocator = tcp_ip_allocator.deep_clone()?;
                build_src_nat_pool_generic(
                    &mut self.pools_src66,
                    expose,
                    src_vpc_id,
                    dst_vpc_id,
                    &tcp_ip_allocator,
                    &udp_ip_allocator,
                )
            })?;

        Ok(())
    }

    fn build_dst_nat_pool_for_expose(
        &mut self,
        peering: &Peering,
        src_vpc_id: VpcDiscriminant,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<(), AllocatorError> {
        peering
            .remote
            .stateful_nat_exposes_44()
            .try_for_each(|expose| {
                // We should always have an idle timeout if we process this expose for stateful NAT.
                let idle_timeout = expose.idle_timeout().unwrap_or_else(|| unreachable!());
                let tcp_ip_allocator = ip_allocator_for_prefixes(&expose.ips, idle_timeout)?;
                let udp_ip_allocator = tcp_ip_allocator.deep_clone()?;
                build_dst_nat_pool_generic(
                    &mut self.pools_dst44,
                    expose,
                    src_vpc_id,
                    dst_vpc_id,
                    &tcp_ip_allocator,
                    &udp_ip_allocator,
                )
            })?;

        peering
            .remote
            .stateful_nat_exposes_66()
            .try_for_each(|expose| {
                // We should always have an idle timeout if we process this expose for stateful NAT.
                let idle_timeout = expose.idle_timeout().unwrap_or_else(|| unreachable!());
                let tcp_ip_allocator = ip_allocator_for_prefixes(&expose.ips, idle_timeout)?;
                let udp_ip_allocator = tcp_ip_allocator.deep_clone()?;
                build_dst_nat_pool_generic(
                    &mut self.pools_dst66,
                    expose,
                    src_vpc_id,
                    dst_vpc_id,
                    &tcp_ip_allocator,
                    &udp_ip_allocator,
                )
            })?;

        Ok(())
    }
}

fn build_src_nat_pool_generic<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    expose: &VpcExpose,
    src_vpc_id: VpcDiscriminant,
    dst_vpc_id: VpcDiscriminant,
    tcp_allocator: &IpAllocator<J>,
    udp_allocator: &IpAllocator<J>,
) -> Result<(), AllocatorError> {
    add_pool_entries(
        table,
        &expose.ips,
        src_vpc_id,
        dst_vpc_id,
        tcp_allocator,
        udp_allocator,
    )
}

fn build_dst_nat_pool_generic<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    expose: &VpcExpose,
    src_vpc_id: VpcDiscriminant,
    dst_vpc_id: VpcDiscriminant,
    tcp_allocator: &IpAllocator<J>,
    udp_allocator: &IpAllocator<J>,
) -> Result<(), AllocatorError> {
    add_pool_entries(
        table,
        expose.as_range_or_empty(),
        src_vpc_id,
        dst_vpc_id,
        tcp_allocator,
        udp_allocator,
    )
}

fn add_pool_entries<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    prefixes: &BTreeSet<Prefix>,
    src_vpc_id: VpcDiscriminant,
    dst_vpc_id: VpcDiscriminant,
    tcp_allocator: &IpAllocator<J>,
    udp_allocator: &IpAllocator<J>,
) -> Result<(), AllocatorError> {
    for prefix in prefixes {
        let key = pool_table_key_for_expose(prefix, src_vpc_id, dst_vpc_id)?;
        insert_per_proto_entries(table, key, tcp_allocator, udp_allocator);
    }
    Ok(())
}

fn insert_per_proto_entries<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    key: PoolTableKey<I>,
    tcp_allocator: &IpAllocator<J>,
    udp_allocator: &IpAllocator<J>,
) {
    // We insert twice the entry, once for TCP and once for UDP. Allocations for TCP do not affect
    // allocations for UDP, the space defined by the combination of IP addresses and L4 ports is
    // distinct for each protocol.

    let mut tcp_key = key.clone();
    tcp_key.protocol = NextHeader::TCP;
    table.add_entry(tcp_key, tcp_allocator.clone());

    let mut udp_key = key;
    udp_key.protocol = NextHeader::UDP;
    table.add_entry(udp_key, udp_allocator.clone());
}

fn ip_allocator_for_prefixes<J: NatIpWithBitmap>(
    prefixes: &BTreeSet<Prefix>,
    idle_timeout: Duration,
) -> Result<IpAllocator<J>, AllocatorError> {
    let pool = create_natpool(prefixes, idle_timeout)?;
    let allocator = IpAllocator::new(pool);
    Ok(allocator)
}

fn create_natpool<J: NatIpWithBitmap>(
    prefixes: &BTreeSet<Prefix>,
    idle_timeout: Duration,
) -> Result<NatPool<J>, AllocatorError> {
    // Build mappings for IPv6 <-> u32 bitmap translation
    let (bitmap_mapping, reverse_bitmap_mapping) = create_ipv6_bitmap_mappings(prefixes)?;

    // Mark all addresses as available (free) in bitmap
    let mut bitmap = PoolBitmap::new();
    prefixes
        .iter()
        .try_for_each(|prefix| bitmap.add_prefix(prefix, &reverse_bitmap_mapping))?;

    Ok(NatPool::new(
        bitmap,
        bitmap_mapping,
        reverse_bitmap_mapping,
        idle_timeout,
    ))
}

fn pool_table_key_for_expose<I: NatIp>(
    prefix: &Prefix,
    src_vpc_id: VpcDiscriminant,
    dst_vpc_id: VpcDiscriminant,
) -> Result<PoolTableKey<I>, AllocatorError> {
    Ok(PoolTableKey::new(
        NextHeader::TCP,
        src_vpc_id,
        dst_vpc_id,
        I::try_from_addr(prefix.as_address()).map_err(|()| {
            AllocatorError::InternalIssue("Failed to build IP address".to_string())
        })?,
        match prefix {
            Prefix::IPV4(p) => I::try_from_ipv4_addr(p.last_address()).map_err(|()| {
                AllocatorError::InternalIssue(
                    "Failed to build IPv4 address from prefix".to_string(),
                )
            })?,
            Prefix::IPV6(p) => I::try_from_ipv6_addr(p.last_address()).map_err(|()| {
                AllocatorError::InternalIssue(
                    "Failed to build IPv6 address from prefix".to_string(),
                )
            })?,
        },
    ))
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
