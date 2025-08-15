// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIpWithBitmap;
use super::alloc::{IpAllocator, NatPool, PoolBitmap};
use super::{NatDefaultAllocator, PoolTable, PoolTableKey};
use crate::stateful::allocator::AllocatorError;
use crate::stateful::{NatAllocator, NatIp, NatVpcId};
use config::ConfigError;
use config::external::overlay::vpc::{Peering, VpcTable};
use config::external::overlay::vpcpeering::VpcExpose;
use config::utils::collapse_prefixes_peering;
use lpm::prefix::{IpPrefix, Prefix};
use net::ip::NextHeader;
use std::collections::{BTreeMap, BTreeSet};

/// Build a [`NatDefaultAllocator`] from a [`VpcTable`]
///
/// # Returns
///
/// A [`NatDefaultAllocator`] that can be used to allocate NAT addresses, or a [`ConfigError`]
/// if building the allocator fails.
///
/// # Errors
///
/// [`ConfigError::FailureApply`] if adding a peering fails.
//
// TODO: Call me maybe
#[allow(dead_code)]
pub fn build_nat_allocator(vpc_table: &VpcTable) -> Result<NatDefaultAllocator, ConfigError> {
    let mut allocator = NatDefaultAllocator::new();
    for vpc in vpc_table.values() {
        for peering in &vpc.peerings {
            let dst_vni = vpc_table.get_remote_vni(peering);
            allocator
                .add_peering_addresses(peering, vpc.vni, dst_vni)
                .map_err(|e| ConfigError::FailureApply(e.to_string()))?;
        }
    }
    Ok(allocator)
}

impl NatDefaultAllocator {
    fn add_peering_addresses(
        &mut self,
        peering: &Peering,
        src_vpc_id: NatVpcId,
        dst_vpc_id: NatVpcId,
    ) -> Result<(), AllocatorError> {
        let new_peering = collapse_prefixes_peering(peering)
            .map_err(|e| AllocatorError::InternalIssue(e.to_string()))?;

        // Update table for source NAT
        self.update_src_nat_pool_for_expose(&new_peering, src_vpc_id, dst_vpc_id)?;

        // Update table for destination NAT
        self.update_dst_nat_pool_for_expose(&new_peering, src_vpc_id, dst_vpc_id)?;

        Ok(())
    }

    fn update_src_nat_pool_for_expose(
        &mut self,
        peering: &Peering,
        src_vpc_id: NatVpcId,
        dst_vpc_id: NatVpcId,
    ) -> Result<(), AllocatorError> {
        filter_v4_exposes(&peering.local.exposes).try_for_each(|expose| {
            let ip_allocator = ip_allocator_for_prefixes(&expose.as_range)?;
            update_src_nat_pool_generic(
                &mut self.pools_src44,
                expose,
                src_vpc_id,
                dst_vpc_id,
                &ip_allocator,
            )
        })?;

        filter_v6_exposes(&peering.local.exposes).try_for_each(|expose| {
            let ip_allocator = ip_allocator_for_prefixes(&expose.as_range)?;
            update_src_nat_pool_generic(
                &mut self.pools_src66,
                expose,
                src_vpc_id,
                dst_vpc_id,
                &ip_allocator,
            )
        })?;

        Ok(())
    }

    fn update_dst_nat_pool_for_expose(
        &mut self,
        peering: &Peering,
        src_vpc_id: NatVpcId,
        dst_vpc_id: NatVpcId,
    ) -> Result<(), AllocatorError> {
        filter_v4_exposes(&peering.remote.exposes).try_for_each(|expose| {
            let ip_allocator = ip_allocator_for_prefixes(&expose.ips)?;
            update_dst_nat_pool_generic(
                &mut self.pools_dst44,
                expose,
                src_vpc_id,
                dst_vpc_id,
                &ip_allocator,
            )
        })?;

        filter_v6_exposes(&peering.remote.exposes).try_for_each(|expose| {
            let ip_allocator = ip_allocator_for_prefixes(&expose.ips)?;
            update_dst_nat_pool_generic(
                &mut self.pools_dst66,
                expose,
                src_vpc_id,
                dst_vpc_id,
                &ip_allocator,
            )
        })?;

        Ok(())
    }
}

fn filter_v4_exposes(exposes: &[VpcExpose]) -> impl Iterator<Item = &VpcExpose> {
    exposes.iter().filter(|e| {
        matches!(
            (e.ips.first(), e.as_range.first()),
            (Some(Prefix::IPV4(_)), Some(Prefix::IPV4(_)))
        )
    })
}

fn filter_v6_exposes(exposes: &[VpcExpose]) -> impl Iterator<Item = &VpcExpose> {
    exposes.iter().filter(|e| {
        matches!(
            (e.ips.first(), e.as_range.first()),
            (Some(Prefix::IPV6(_)), Some(Prefix::IPV6(_)))
        )
    })
}

fn update_src_nat_pool_generic<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    expose: &VpcExpose,
    src_vpc_id: NatVpcId,
    dst_vpc_id: NatVpcId,
    allocator: &IpAllocator<J>,
) -> Result<(), AllocatorError> {
    add_pool_entries(table, &expose.ips, src_vpc_id, dst_vpc_id, allocator)
}

fn update_dst_nat_pool_generic<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    expose: &VpcExpose,
    src_vpc_id: NatVpcId,
    dst_vpc_id: NatVpcId,
    allocator: &IpAllocator<J>,
) -> Result<(), AllocatorError> {
    add_pool_entries(table, &expose.as_range, src_vpc_id, dst_vpc_id, allocator)
}

fn add_pool_entries<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    prefixes: &BTreeSet<Prefix>,
    src_vpc_id: NatVpcId,
    dst_vpc_id: NatVpcId,
    allocator: &IpAllocator<J>,
) -> Result<(), AllocatorError> {
    for prefix in prefixes {
        let key = pool_table_key_for_expose(prefix, src_vpc_id, dst_vpc_id)?;
        insert_per_proto_entries(table, key, allocator);
    }
    Ok(())
}

fn insert_per_proto_entries<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    table: &mut PoolTable<I, J>,
    key: PoolTableKey<I>,
    allocator: &IpAllocator<J>,
) {
    // We insert twice the entry, once for TCP and once for UDP. Allocations for TCP do not affect
    // allocations for UDP, the space defined by the combination of IP addresses and L4 ports is
    // distinct for each protocol.

    let mut tcp_key = key.clone();
    tcp_key.protocol = NextHeader::TCP;
    table.add_entry(tcp_key, allocator.clone());

    let mut udp_key = key;
    udp_key.protocol = NextHeader::UDP;
    table.add_entry(udp_key, allocator.clone());
}

fn ip_allocator_for_prefixes<J: NatIpWithBitmap>(
    prefixes: &BTreeSet<Prefix>,
) -> Result<IpAllocator<J>, AllocatorError> {
    let pool = create_natpool(prefixes)?;
    let allocator = IpAllocator::new(pool);
    Ok(allocator)
}

fn create_natpool<J: NatIpWithBitmap>(
    prefixes: &BTreeSet<Prefix>,
) -> Result<NatPool<J>, AllocatorError> {
    // Build mappings for IPv6 <-> u32 bitmap translation
    let (bitmap_mapping, reverse_bitmap_mapping) = create_ipv6_bitmap_mappings(prefixes)?;

    // Mark all addresses as available (free) in bitmap
    let mut bitmap = PoolBitmap::new();
    prefixes
        .iter()
        .try_for_each(|prefix| bitmap.add_prefix(prefix, &reverse_bitmap_mapping))?;

    Ok(NatPool::new(bitmap, bitmap_mapping, reverse_bitmap_mapping))
}

fn pool_table_key_for_expose<I: NatIp>(
    prefix: &Prefix,
    src_vpc_id: NatVpcId,
    dst_vpc_id: NatVpcId,
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
