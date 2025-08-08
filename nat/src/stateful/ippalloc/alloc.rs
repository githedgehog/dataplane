// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::{NatIpWithBitmap, port_alloc};
use crate::stateful::NatIp;
use crate::stateful::allocator::AllocatorError;
use crate::stateful::port::NatPort;
use concurrency::sync::{Arc, RwLock, Weak};
use lpm::prefix::{IpPrefix, Prefix};
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, VecDeque};

///////////////////////////////////////////////////////////////////////////////
// IpAllocator
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone)]
pub struct IpAllocator<I: NatIpWithBitmap> {
    pool: Arc<RwLock<NatPool<I>>>,
}

impl<I: NatIpWithBitmap> IpAllocator<I> {
    pub(crate) fn new(pool: NatPool<I>) -> Self {
        Self {
            pool: Arc::new(RwLock::new(pool)),
        }
    }

    fn deallocate_ip(&self, ip: I) {
        self.pool.write().unwrap().deallocate_from_pool(ip);
    }

    fn reuse_allocated_ip(&self) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        let allocated_ips = self.pool.read().unwrap();
        for ip_weak in allocated_ips.ips_in_use() {
            let Some(ip) = ip_weak.upgrade() else {
                continue;
            };
            if !ip.has_free_ports() {
                continue;
            }
            match ip.allocate_port_for_ip() {
                Ok(port) => return Ok(port),
                Err(AllocatorError::NoFreePort(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Err(AllocatorError::NoFreeIp)
    }

    fn allocate_new_ip_from_pool(&self) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        let mut allocated_ips = self.pool.write().unwrap();
        let new_ip = allocated_ips.use_new_ip(self.clone())?;
        let arc_ip = Arc::new(new_ip);
        allocated_ips.add_in_use(&arc_ip);
        Ok(arc_ip)
    }

    fn allocate_from_new_ip(&self) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        self.allocate_new_ip_from_pool()
            .and_then(AllocatedIp::allocate_port_for_ip)
    }

    fn cleanup_used_ips(&self) {
        let mut allocated_ips = self.pool.write().unwrap();
        allocated_ips.cleanup();
    }

    pub fn allocate(&self) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        // FIXME: Should we clean up every time??
        self.cleanup_used_ips();

        if let Ok(port) = self.reuse_allocated_ip() {
            return Ok(port);
        }

        self.allocate_from_new_ip()
    }

    fn get_allocated_ip(&self, ip: I) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        self.pool
            .write()
            .unwrap()
            .reserve_from_pool(ip, self.clone())
    }

    pub fn reserve(
        &self,
        ip: I,
        port: NatPort,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        self.get_allocated_ip(ip)
            .and_then(|allocated_ip| allocated_ip.reserve_port_for_ip(port))
    }

    #[cfg(test)]
    pub fn get_pool_clone_for_tests(&self) -> (RoaringBitmap, VecDeque<Weak<AllocatedIp<I>>>) {
        let pool = self.pool.read().unwrap();
        (pool.bitmap.0.clone(), pool.in_use.clone())
    }
}

///////////////////////////////////////////////////////////////////////////////
// AllocatedIp
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct AllocatedIp<I: NatIpWithBitmap> {
    ip: I,
    port_allocator: port_alloc::PortAllocator<I>,
    ip_allocator: IpAllocator<I>,
}

impl<I: NatIpWithBitmap> AllocatedIp<I> {
    fn new(ip: I, ip_allocator: IpAllocator<I>) -> Self {
        Self {
            ip,
            port_allocator: port_alloc::PortAllocator::new(),
            ip_allocator,
        }
    }

    pub fn ip(&self) -> I {
        self.ip
    }

    fn has_free_ports(&self) -> bool {
        self.port_allocator.has_free_ports()
    }

    pub(crate) fn deallocate_block_for_ip(self: Arc<Self>, index: usize) {
        self.port_allocator.deallocate_block(index);
    }

    fn allocate_port_for_ip(
        self: Arc<Self>,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        self.port_allocator.allocate_port(self.clone())
    }

    fn reserve_port_for_ip(
        self: Arc<Self>,
        port: NatPort,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        self.port_allocator.reserve_port(self.clone(), port)
    }
}

impl<I: NatIpWithBitmap> Drop for AllocatedIp<I> {
    fn drop(&mut self) {
        self.ip_allocator.deallocate_ip(self.ip);
    }
}

///////////////////////////////////////////////////////////////////////////////
// NatPool
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub(crate) struct NatPool<I: NatIpWithBitmap> {
    bitmap: PoolBitmap,
    bitmap_mapping: BTreeMap<u32, u128>,
    reverse_bitmap_mapping: BTreeMap<u128, u32>,
    in_use: VecDeque<Weak<AllocatedIp<I>>>,
}

impl<I: NatIpWithBitmap> NatPool<I> {
    pub(crate) fn new(
        bitmap: PoolBitmap,
        bitmap_mapping: BTreeMap<u32, u128>,
        reverse_bitmap_mapping: BTreeMap<u128, u32>,
    ) -> Self {
        Self {
            bitmap,
            bitmap_mapping,
            reverse_bitmap_mapping,
            in_use: VecDeque::new(),
        }
    }

    fn add_in_use(&mut self, ip: &Arc<AllocatedIp<I>>) {
        self.in_use.push_back(Arc::downgrade(ip));
    }

    fn cleanup(&mut self) {
        self.in_use.retain(|ip| ip.upgrade().is_some());
    }

    fn ips_in_use(&self) -> impl Iterator<Item = &Weak<AllocatedIp<I>>> {
        self.in_use.iter()
    }

    fn use_new_ip(
        &mut self,
        ip_allocator: IpAllocator<I>,
    ) -> Result<AllocatedIp<I>, AllocatorError> {
        // Retrieve the first available offset
        let offset = self.bitmap.pop_ip()?;

        let ip = I::try_from_offset(offset, &self.bitmap_mapping)?;
        Ok(AllocatedIp::new(ip, ip_allocator))
    }

    fn deallocate_from_pool(&mut self, ip: I) {
        let offset = I::try_to_offset(ip, &self.reverse_bitmap_mapping).unwrap();
        self.bitmap.set_ip_free(offset);
    }

    fn reserve_from_pool(
        &mut self,
        ip: I,
        ip_allocator: IpAllocator<I>,
    ) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        let offset = I::try_to_offset(ip, &self.reverse_bitmap_mapping)?;
        if self.bitmap.set_ip_allocated(offset) {
            // The IP was free in the bitmap, allocate it now
            let arc_ip = Arc::new(AllocatedIp::new(ip, ip_allocator));
            self.add_in_use(&arc_ip);
            return Ok(arc_ip);
        }

        let ip_opt = self.ips_in_use().find(|weak_in_use| {
            weak_in_use
                .upgrade()
                .is_some_and(|in_use| in_use.ip() == ip)
        });
        let Some(ip_weak) = ip_opt else {
            // We didn't find the IP in the list of in-use IPs, but it was marked as allocated in
            // the bitmap. Something's amiss.
            return Err(AllocatorError::InternalIssue(
                "IP allocated in bitmap but not found in list of in-use IPs".to_string(),
            ));
        };
        let Some(ip_arc) = ip_weak.upgrade() else {
            // The IP was marked as allocated in the bitmap, but the weak reference no longer
            // resolves. It should have been removed from the bitmap, something's amiss.
            return Err(AllocatorError::InternalIssue(
                "IP allocated in bitmap but weak reference does not resolve".to_string(),
            ));
        };

        // We found the allocated IP in the list of IPs in use, return it
        Ok(ip_arc)
    }
}

///////////////////////////////////////////////////////////////////////////////
// PoolBitmap
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct PoolBitmap(RoaringBitmap);

impl PoolBitmap {
    pub fn new() -> Self {
        Self(RoaringBitmap::new())
    }

    fn pop_ip(&mut self) -> Result<u32, AllocatorError> {
        let offset = self.0.min().ok_or(AllocatorError::NoFreeIp)?;
        self.0.remove(offset);
        Ok(offset)
    }

    fn set_ip_allocated(&mut self, index: u32) -> bool {
        self.0.remove(index)
    }

    fn set_ip_free(&mut self, index: u32) -> bool {
        self.0.insert(index)
    }

    pub fn add_prefix(
        &mut self,
        prefix: &Prefix,
        bitmap_mapping: &BTreeMap<u128, u32>,
    ) -> Result<(), AllocatorError> {
        match prefix {
            Prefix::IPV4(p) => {
                let start = p.network().to_bits();
                let end = p.last_address().to_bits();
                self.0.insert_range(start..=end);
            }
            Prefix::IPV6(p) => {
                let start = map_address(p.network(), bitmap_mapping)?;
                let end = map_address(p.last_address(), bitmap_mapping)?;
                self.0.insert_range(start..=end);
            }
        }
        Ok(())
    }
}

///////////////////////////////////////////////////////////////////////////////
// IPv6 <-> u32-offset mapping functions
///////////////////////////////////////////////////////////////////////////////

pub(crate) fn map_offset<I: NatIp>(
    offset: u32,
    bitmap_mapping: &BTreeMap<u32, u128>,
) -> Result<I, AllocatorError> {
    // Field bitmap_mapping is a BTreeMap that associates, to each given u32 offset, an IPv6
    // address, as a u128, corresponding to the network address of the corresponding prefix in
    // the list.
    // Here we lookup for the closest lower offset in the tree, which returns the network
    // address for the prefix start address and its offset, and we deduce the IPv6 address we're
    // looking for.
    let (prefix_offset, prefix_start_bits) =
        bitmap_mapping
            .range(..=offset)
            .next_back()
            .ok_or(AllocatorError::InternalIssue(
                "Failed to find offset in map for IPv6".to_string(),
            ))?;

    // Generate the IPv6 address: prefix network address - prefix offset + address offset
    I::try_from_bits(prefix_start_bits + u128::from(offset - prefix_offset))
        .map_err(|()| AllocatorError::InternalIssue("Failed to convert offset to IPv6".to_string()))
}

pub(crate) fn map_address<I: NatIp>(
    address: I,
    bitmap_mapping: &BTreeMap<u128, u32>,
) -> Result<u32, AllocatorError> {
    let (prefix_start_bits, prefix_offset) = bitmap_mapping
        .range(..=address.to_bits())
        .next_back()
        .ok_or(AllocatorError::InternalIssue(
            "Failed to find prefix in map for IPv6".to_string(),
        ))?;

    Ok(prefix_offset
        + u32::try_from(address.to_bits() - prefix_start_bits).map_err(|_| {
            AllocatorError::InternalIssue("Failed to convert Ipv6 to offset".to_string())
        })?)
}
