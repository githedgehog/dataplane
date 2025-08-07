// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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
use net::vxlan::Vni;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

fn get_remote_vni(peering: &Peering, vpc_table: &VpcTable) -> Vni {
    vpc_table
        .get_vpc_by_vpcid(&peering.remote_id)
        .unwrap_or_else(|| unreachable!())
        .vni
}

#[allow(dead_code)]
pub fn build_nat_allocator(vpc_table: &VpcTable) -> Result<NatDefaultAllocator, ConfigError> {
    let mut allocator = NatDefaultAllocator::new();
    for vpc in vpc_table.values() {
        for peering in &vpc.peerings {
            let dst_vni = get_remote_vni(peering, vpc_table);
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

        let v4_local_exposes = filter_v4_exposes(&new_peering.local.exposes);
        let v6_local_exposes = filter_v6_exposes(&new_peering.local.exposes);

        let allocators_local_exposes =
            ip_allocator_for_local_exposes(&v4_local_exposes, &v6_local_exposes)?;

        // Update table for source NAT
        self.update_src_nat_pool_for_expose(
            &v4_local_exposes,
            &v6_local_exposes,
            src_vpc_id,
            dst_vpc_id,
            &allocators_local_exposes,
        )?;

        let v4_remote_exposes = filter_v4_exposes(&new_peering.remote.exposes);
        let v6_remote_exposes = filter_v6_exposes(&new_peering.remote.exposes);

        let allocators_remote_exposes =
            ip_allocator_for_remote_exposes(&v4_remote_exposes, &v6_remote_exposes)?;

        // Update table for destination NAT
        self.update_dst_nat_pool_for_expose(
            &v4_remote_exposes,
            &v6_remote_exposes,
            src_vpc_id,
            dst_vpc_id,
            &allocators_remote_exposes,
        )?;

        Ok(())
    }

    fn update_src_nat_pool_for_expose(
        &mut self,
        v4_local_exposes: &Vec<&VpcExpose>,
        v6_local_exposes: &Vec<&VpcExpose>,
        src_vpc_id: NatVpcId,
        dst_vpc_id: NatVpcId,
        allocators_local_exposes: &(IpAllocator<Ipv4Addr>, IpAllocator<Ipv6Addr>),
    ) -> Result<(), AllocatorError> {
        v4_local_exposes.iter().try_for_each(|expose| {
            update_src_nat_pool_generic(
                &mut self.pools_src44,
                expose,
                src_vpc_id,
                dst_vpc_id,
                &allocators_local_exposes.0,
            )
        })?;
        v6_local_exposes.iter().try_for_each(|expose| {
            update_src_nat_pool_generic(
                &mut self.pools_src66,
                expose,
                src_vpc_id,
                dst_vpc_id,
                &allocators_local_exposes.1,
            )
        })
    }

    fn update_dst_nat_pool_for_expose(
        &mut self,
        v4_remote_exposes: &Vec<&VpcExpose>,
        v6_remote_exposes: &Vec<&VpcExpose>,
        src_vpc_id: NatVpcId,
        dst_vpc_id: NatVpcId,
        allocators_remote_exposes: &(IpAllocator<Ipv4Addr>, IpAllocator<Ipv6Addr>),
    ) -> Result<(), AllocatorError> {
        v4_remote_exposes.iter().try_for_each(|expose| {
            update_dst_nat_pool_generic(
                &mut self.pools_dst44,
                expose,
                src_vpc_id,
                dst_vpc_id,
                &allocators_remote_exposes.0,
            )
        })?;
        v6_remote_exposes.iter().try_for_each(|expose| {
            update_dst_nat_pool_generic(
                &mut self.pools_dst66,
                expose,
                src_vpc_id,
                dst_vpc_id,
                &allocators_remote_exposes.1,
            )
        })
    }
}

fn filter_v4_exposes(exposes: &[VpcExpose]) -> Vec<&VpcExpose> {
    exposes
        .iter()
        .filter(|e| {
            matches!(
                (e.ips.first(), e.as_range.first()),
                (Some(Prefix::IPV4(_)), Some(Prefix::IPV4(_)))
            )
        })
        .collect()
}

fn filter_v6_exposes(exposes: &[VpcExpose]) -> Vec<&VpcExpose> {
    exposes
        .iter()
        .filter(|e| {
            matches!(
                (e.ips.first(), e.as_range.first()),
                (Some(Prefix::IPV6(_)), Some(Prefix::IPV6(_)))
            )
        })
        .collect()
}

fn update_src_nat_pool_generic<I: NatIp, J: NatIp>(
    table: &mut PoolTable<I, J>,
    expose: &VpcExpose,
    src_vpc_id: NatVpcId,
    dst_vpc_id: NatVpcId,
    allocator: &IpAllocator<J>,
) -> Result<(), AllocatorError> {
    add_pool_entries(
        table,
        &expose.ips,
        &expose.as_range,
        src_vpc_id,
        dst_vpc_id,
        allocator,
    )
}

fn update_dst_nat_pool_generic<I: NatIp, J: NatIp>(
    table: &mut PoolTable<I, J>,
    expose: &VpcExpose,
    src_vpc_id: NatVpcId,
    dst_vpc_id: NatVpcId,
    allocator: &IpAllocator<J>,
) -> Result<(), AllocatorError> {
    add_pool_entries(
        table,
        &expose.as_range,
        &expose.ips,
        src_vpc_id,
        dst_vpc_id,
        allocator,
    )
}

fn add_pool_entries<I: NatIp, J: NatIp>(
    table: &mut PoolTable<I, J>,
    prefixes: &BTreeSet<Prefix>,
    target_prefixes: &BTreeSet<Prefix>,
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

fn insert_per_proto_entries<I: NatIp, J: NatIp>(
    table: &mut PoolTable<I, J>,
    key: PoolTableKey<I>,
    allocator: &IpAllocator<J>,
) {
    let mut tcp_key = key.clone();
    tcp_key.protocol = NextHeader::TCP;
    table.add_entry(tcp_key, allocator.clone());

    let mut udp_key = key;
    udp_key.protocol = NextHeader::UDP;
    table.add_entry(udp_key, allocator.clone());
}

fn ip_allocator_for_local_exposes(
    v4_exposes: &Vec<&VpcExpose>,
    v6_exposes: &Vec<&VpcExpose>,
) -> Result<(IpAllocator<Ipv4Addr>, IpAllocator<Ipv6Addr>), AllocatorError> {
    let v4_prefixes = v4_exposes.iter().flat_map(|e| e.as_range.iter()).collect();
    let v4_allocator = ip_allocator_for_prefixes(&v4_prefixes)?;

    let v6_prefixes = v6_exposes.iter().flat_map(|e| e.as_range.iter()).collect();
    let v6_allocator = ip_allocator_for_prefixes(&v6_prefixes)?;

    Ok((v4_allocator, v6_allocator))
}

fn ip_allocator_for_remote_exposes(
    v4_exposes: &Vec<&VpcExpose>,
    v6_exposes: &Vec<&VpcExpose>,
) -> Result<(IpAllocator<Ipv4Addr>, IpAllocator<Ipv6Addr>), AllocatorError> {
    let v4_prefixes = v4_exposes.iter().flat_map(|e| e.ips.iter()).collect();
    let v4_allocator = ip_allocator_for_prefixes(&v4_prefixes)?;

    let v6_prefixes = v6_exposes.iter().flat_map(|e| e.ips.iter()).collect();
    let v6_allocator = ip_allocator_for_prefixes(&v6_prefixes)?;

    Ok((v4_allocator, v6_allocator))
}

fn ip_allocator_for_prefixes<J: NatIp>(
    prefixes: &Vec<&Prefix>,
) -> Result<IpAllocator<J>, AllocatorError> {
    let pool = create_natpool(prefixes)?;
    let allocator = IpAllocator::new(pool);
    Ok(allocator)
}

fn create_natpool<J: NatIp>(prefixes: &Vec<&Prefix>) -> Result<NatPool<J>, AllocatorError> {
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

#[allow(clippy::type_complexity)]
fn create_ipv6_bitmap_mappings(
    prefixes: &Vec<&Prefix>,
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
