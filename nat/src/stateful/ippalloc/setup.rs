// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::alloc::{IpAllocator, NatPool, PoolBitmap};
use super::{NatDefaultAllocator, PoolTable, PoolTableKey};
use crate::stateful::allocator::AllocatorError;
use crate::stateful::{NatAllocator, NatIp};
use config::ConfigError;
use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Peering, VpcTable};
use config::external::overlay::vpcpeering::VpcExpose;
use config::utils::collapse_prefixes_peering;
use lpm::prefix::{IpPrefix, Prefix};
use net::ip::NextHeader;
use net::vxlan::Vni;
use std::collections::{BTreeMap, BTreeSet};

fn get_remote_vni(peering: &Peering, vpc_table: &VpcTable) -> Vni {
    vpc_table
        .get_vpc_by_vpcid(&peering.remote_id)
        .unwrap_or_else(|| unreachable!())
        .vni
}

pub fn build_nat_allocator(overlay: &Overlay) -> Result<NatDefaultAllocator, ConfigError> {
    let mut allocator = NatDefaultAllocator::new();
    for vpc in overlay.vpc_table.values() {
        for peering in &vpc.peerings {
            let dst_vni = get_remote_vni(peering, &overlay.vpc_table);
            allocator
                .add_peering_addresses(peering, dst_vni)
                .map_err(|e| ConfigError::FailureApply(e.to_string()))?;
        }
    }
    Ok(allocator)
}

impl NatDefaultAllocator {
    fn add_peering_addresses(
        &mut self,
        peering: &Peering,
        dst_vni: Vni,
    ) -> Result<(), AllocatorError> {
        let new_peering =
            collapse_prefixes_peering(peering).map_err(|e| AllocatorError::InternalIssue)?;

        new_peering.local.exposes.iter().try_for_each(|expose| {
            if expose.as_range.is_empty() {
                // Nothing to do for source NAT, get out of here
                return Ok(());
            }
            self.update_src_nat_pool_for_expose(expose)
        })?;

        // Update table for destination NAT
        new_peering.remote.exposes.iter().try_for_each(|expose| {
            if expose.as_range.is_empty() {
                // Nothing to do for destination NAT, get out of here
                return Ok(());
            }
            self.update_dst_nat_pool_for_expose(expose)
        })?;

        Ok(())
    }

    fn update_src_nat_pool_for_expose(&mut self, expose: &VpcExpose) -> Result<(), AllocatorError> {
        match expose.ips.first() {
            Some(Prefix::IPV4(_)) => update_entry_for_src_nat(&mut self.pools_src44, expose),
            Some(Prefix::IPV6(_)) => update_entry_for_src_nat(&mut self.pools_src66, expose),
            None => Err(AllocatorError::InternalIssue),
        }
    }

    fn update_dst_nat_pool_for_expose(&mut self, expose: &VpcExpose) -> Result<(), AllocatorError> {
        match expose.as_range.first() {
            Some(Prefix::IPV4(_)) => update_entry_for_dst_nat(&mut self.pools_dst44, expose),
            Some(Prefix::IPV6(_)) => update_entry_for_dst_nat(&mut self.pools_dst66, expose),
            None => Err(AllocatorError::InternalIssue),
        }
    }
}

fn update_entry_for_dst_nat<I: NatIp, J: NatIp>(
    table: &mut PoolTable<I, J>,
    expose: &VpcExpose,
) -> Result<(), AllocatorError> {
    update_entry(table, &expose.as_range, &expose.ips)
}

fn update_entry_for_src_nat<I: NatIp, J: NatIp>(
    table: &mut PoolTable<I, J>,
    expose: &VpcExpose,
) -> Result<(), AllocatorError> {
    update_entry(table, &expose.ips, &expose.as_range)
}

fn update_entry<I: NatIp, J: NatIp>(
    table: &mut PoolTable<I, J>,
    prefixes: &BTreeSet<Prefix>,
    target_prefixes: &BTreeSet<Prefix>,
) -> Result<(), AllocatorError> {
    let allocator = ip_allocator_for_expose(target_prefixes)?;
    for prefix in prefixes {
        let key = pool_table_key_for_expose(prefix)?;

        let mut tcp_key = key.clone();
        tcp_key.protocol = NextHeader::TCP;
        table.add_entry(tcp_key, allocator.clone());

        let mut udp_key = key;
        udp_key.protocol = NextHeader::UDP;
        table.add_entry(udp_key, allocator.clone());
    }

    Ok(())
}

fn ip_allocator_for_expose<J: NatIp>(
    prefixes: &BTreeSet<Prefix>,
) -> Result<IpAllocator<J>, AllocatorError> {
    let pool = create_natpool(prefixes)?;
    let allocator = IpAllocator::new(pool);
    Ok(allocator)
}

fn pool_table_key_for_expose<I: NatIp>(prefix: &Prefix) -> Result<PoolTableKey<I>, AllocatorError> {
    let vrf_id = 0; // FIXME
    Ok(PoolTableKey::new(
        NextHeader::TCP,
        vrf_id,
        I::try_from_addr(prefix.as_address()).map_err(|()| AllocatorError::InternalIssue)?,
    ))
}

fn create_natpool<J: NatIp>(prefixes: &BTreeSet<Prefix>) -> Result<NatPool<J>, AllocatorError> {
    let (bitmap_mapping, reverse_bitmap_mapping) = create_ipv6_bitmap_mappings(prefixes)?;

    let mut bitmap = PoolBitmap::new();
    prefixes
        .iter()
        .try_for_each(|prefix| bitmap.add_prefix(prefix, &reverse_bitmap_mapping))?;

    Ok(NatPool::new(bitmap, bitmap_mapping, reverse_bitmap_mapping))
}

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
            index +=
                u32::try_from(u128::try_from(p.size()).map_err(|_| AllocatorError::InternalIssue)?)
                    .map_err(|_| AllocatorError::InternalIssue)?;
        }
    }
    Ok((bitmap_mapping, reverse_bitmap_mapping))
}
