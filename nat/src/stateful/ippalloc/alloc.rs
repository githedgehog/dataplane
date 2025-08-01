// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::port_alloc;
use crate::stateful::NatIp;
use crate::stateful::allocator::AllocatorError;
use crate::stateful::port::NatPort;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, RwLock, Weak};

///////////////////////////////////////////////////////////////////////////////
// Allocators
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct IpAllocator<I: NatIpWithBitmap> {
    pool: RwLock<NatPool<I>>,
}

impl<I: NatIpWithBitmap> IpAllocator<I> {
    pub fn new(ip_allocator: Arc<IpAllocator<I>>) -> Self {
        Self {
            pool: NatPool {
                bitmap: PoolBitmap::new(),
                bitmap_mapping: BTreeMap::new(),
                reverse_bitmap_mapping: BTreeMap::new(),
                in_use: VecDeque::new(),
                ip_allocator,
            }
            .into(),
        }
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
        let new_ip = allocated_ips.use_new_ip()?;
        allocated_ips.add_in_use(&Arc::new(new_ip))
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
        self.pool.write().unwrap().reserve_from_pool(ip)
    }

    pub fn reserve(
        &self,
        ip: I,
        port: NatPort,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        self.get_allocated_ip(ip)
            .and_then(|allocated_ip| allocated_ip.reserve_port_for_ip(port))
    }
}

///////////////////////////////////////////////////////////////////////////////
// Allocated components
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct AllocatedIp<I: NatIp> {
    ip: I,
    port_allocator: port_alloc::PortAllocator<I>,
    ip_allocator: Arc<IpAllocator<I>>,
}

impl<I: NatIp> AllocatedIp<I> {
    fn new(ip: I, ip_allocator: Arc<IpAllocator<I>>) -> Self {
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

impl<I: NatIp> Drop for AllocatedIp<I> {
    fn drop(&mut self) {
        todo!()
    }
}

///////////////////////////////////////////////////////////////////////////////
// Low-level map structures
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct NatPool<I: NatIpWithBitmap> {
    bitmap: PoolBitmap,
    bitmap_mapping: BTreeMap<u32, u128>,
    reverse_bitmap_mapping: BTreeMap<u128, u32>,
    in_use: VecDeque<Weak<AllocatedIp<I>>>,
    ip_allocator: Arc<IpAllocator<I>>,
}

impl<I: NatIpWithBitmap> NatPool<I> {
    fn get_first(&self) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        self.in_use
            .front()
            .unwrap()
            .upgrade()
            .ok_or(AllocatorError::InternalIssue)
    }

    fn add_in_use(
        &mut self,
        ip: &Arc<AllocatedIp<I>>,
    ) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        self.in_use.push_back(Arc::downgrade(ip));
        self.get_first()
    }

    fn cleanup(&mut self) {
        self.in_use.retain(|ip| ip.upgrade().is_some());
    }

    fn ips_in_use(&self) -> impl Iterator<Item = &Weak<AllocatedIp<I>>> {
        self.in_use.iter()
    }

    fn use_new_ip(&mut self) -> Result<AllocatedIp<I>, AllocatorError> {
        // Retrieve the first available offset
        let offset = self.bitmap.pop_ip()?;

        let ip = I::try_from_offset(offset, &self.bitmap_mapping)?;
        Ok(AllocatedIp::new(ip, self.ip_allocator.clone()))
    }

    fn reserve_from_pool(&mut self, ip: I) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        let offset = I::try_to_offset(ip, &self.reverse_bitmap_mapping)?;
        if self.bitmap.set_ip(offset) {
            // The IP was free in the bitmap, allocate it now
            return self.add_in_use(&Arc::new(AllocatedIp::new(ip, self.ip_allocator.clone())));
        }

        let ip_opt = self.ips_in_use().find(|weak_in_use| {
            weak_in_use
                .upgrade()
                .is_some_and(|in_use| in_use.ip() == ip)
        });
        let Some(ip_weak) = ip_opt else {
            // We didn't find the IP in the list of in-use IPs, but it was marked as allocated in
            // the bitmap. Something's amiss.
            return Err(AllocatorError::InternalIssue);
        };
        let Some(ip_arc) = ip_weak.upgrade() else {
            // The IP was marked as allocated in the bitmap, but the weak reference no longer
            // resolves. It should have been removed from the bitmap, something's amiss.
            return Err(AllocatorError::InternalIssue);
        };

        // We found the allocated IP in the list of IPs in use, return it
        Ok(ip_arc)
    }
}

// FIXME: No need for Mutex around bitmap if we're always under NatPool's RwLock
#[derive(Debug)]
struct PoolBitmap(Mutex<RoaringBitmap>);

impl PoolBitmap {
    fn new() -> Self {
        Self(Mutex::new(RoaringBitmap::new()))
    }

    fn pop_ip(&mut self) -> Result<u32, AllocatorError> {
        let mut bitmap = self.0.lock().unwrap();
        let offset = bitmap.min().ok_or(AllocatorError::NoFreeIp)?;
        bitmap.remove(offset);
        Ok(offset)
    }

    fn set_ip(&mut self, offset: u32) -> bool {
        self.0.lock().unwrap().insert(offset)
    }
}

///////////////////////////////////////////////////////////////////////////////
// IP types
///////////////////////////////////////////////////////////////////////////////

pub(crate) trait NatIpWithBitmap: NatIp {
    fn try_from_offset(
        offset: u32,
        bitmap_mapping: &BTreeMap<u32, u128>,
    ) -> Result<Self, AllocatorError>;

    fn try_to_offset(
        address: Self,
        bitmap_mapping: &BTreeMap<u128, u32>,
    ) -> Result<u32, AllocatorError>;
}

impl NatIpWithBitmap for Ipv4Addr {
    fn try_from_offset(
        offset: u32,
        _bitmap_mapping: &BTreeMap<u32, u128>,
    ) -> Result<Self, AllocatorError> {
        Ok(Ipv4Addr::from(offset))
    }

    fn try_to_offset(
        address: Self,
        _bitmap_mapping: &BTreeMap<u128, u32>,
    ) -> Result<u32, AllocatorError> {
        Ok(u32::from(address))
    }
}

impl NatIpWithBitmap for Ipv6Addr {
    fn try_from_offset(
        offset: u32,
        bitmap_mapping: &BTreeMap<u32, u128>,
    ) -> Result<Self, AllocatorError> {
        // For IPv6, the offset does not directly convert to an IP address because the bitmap space
        // is lower than the IPv6 addressing space. Instead, we need to map the offset to the
        // corresponding address within our list of prefixes.
        map_offset(offset, bitmap_mapping)
    }

    fn try_to_offset(
        address: Self,
        bitmap_mapping: &BTreeMap<u128, u32>,
    ) -> Result<u32, AllocatorError> {
        // Reverse operation of map_offset()
        map_address(address, bitmap_mapping)
    }
}

fn map_offset(
    offset: u32,
    bitmap_mapping: &BTreeMap<u32, u128>,
) -> Result<Ipv6Addr, AllocatorError> {
    // Field bitmap_mapping is a BTreeMap that associates, to each given u32 offset, an IPv6
    // address, as a u128, corresponding to the network address of the corresponding prefix in
    // the list.
    // Here we lookup for the closest lower offset in the tree, which returns the network
    // address for the prefix start address and its offset, and we deduce the IPv6 address we're
    // looking for.
    let (prefix_offset, prefix_start_bits) = bitmap_mapping
        .range(..=offset)
        .next_back()
        .ok_or(AllocatorError::InternalIssue)?;

    // Generate the IPv6 address: prefix network address - prefix offset + address offset
    Ok(Ipv6Addr::from(
        prefix_start_bits + u128::from(offset - prefix_offset),
    ))
}

fn map_address(
    address: Ipv6Addr,
    bitmap_mapping: &BTreeMap<u128, u32>,
) -> Result<u32, AllocatorError> {
    let (prefix_start_bits, prefix_offset) = bitmap_mapping
        .range(..=address.to_bits())
        .next_back()
        .ok_or(AllocatorError::InternalIssue)?;

    Ok(prefix_offset
        + u32::try_from(address.to_bits() - prefix_start_bits)
            .map_err(|_| AllocatorError::InternalIssue)?)
}
