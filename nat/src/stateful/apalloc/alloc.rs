// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP allocation components for the default allocator for stateful NAT.
//!
//! This submodule focuses on allocating IP addresses, and it gets an address, calls the methods
//! from its port allocator to allocate ports for this IP address. The [`IpAllocator`] is the main
//! entry point.
//!
//! See also the architecture diagram at the top of mod.rs.

use super::{NatIpWithBitmap, port_alloc};
use crate::port::NatPort;
use crate::stateful::NatIp;
use crate::stateful::allocator::AllocatorError;
use concurrency::sync::{Arc, RwLock, Weak};
use lpm::prefix::{IpPrefix, Prefix};
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv6Addr;

///////////////////////////////////////////////////////////////////////////////
// IpAllocator
///////////////////////////////////////////////////////////////////////////////

/// [`IpAllocator`] is a thread-safe allocator for IP addresses. It wraps around a [`NatPool`]
/// object that contains IP availables for a given
/// [`VpcExpose`](config::external::overlay::vpcpeering::VpcExpose). It can allocate an IP and
/// (using this IP) a port.
#[derive(Debug, Clone)]
pub(crate) struct IpAllocator<I: NatIpWithBitmap> {
    pool: Arc<RwLock<NatPool<I>>>,
}

impl<I: NatIpWithBitmap> IpAllocator<I> {
    pub(crate) fn new(pool: NatPool<I>) -> Self {
        Self {
            pool: Arc::new(RwLock::new(pool)),
        }
    }

    pub(crate) fn deep_clone(&self) -> Result<IpAllocator<I>, AllocatorError> {
        let nat_pool = self
            .pool
            .read()
            .map_err(|_| AllocatorError::InternalIssue("Failed to read pool".to_string()))?;
        Ok(IpAllocator::new((*nat_pool).clone()))
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
                // If there is no free port left, loop again to try another IP address
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

    pub(crate) fn allocate(&self) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
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

    pub(crate) fn reserve(
        &self,
        ip: I,
        port: NatPort,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        self.get_allocated_ip(ip)
            .and_then(|allocated_ip| allocated_ip.reserve_port_for_ip(port))
    }

    // Helper to access IpAllocator's internals for tests. Not to be used outside of tests.
    #[cfg(test)]
    pub fn get_pool_clone_for_tests(&self) -> (RoaringBitmap, VecDeque<Weak<AllocatedIp<I>>>) {
        let pool = self.pool.read().unwrap();
        (pool.bitmap.0.clone(), pool.in_use.clone())
    }
}

///////////////////////////////////////////////////////////////////////////////
// AllocatedIp
///////////////////////////////////////////////////////////////////////////////

/// An [`AllocatedIp`] is an IP address that has been allocated from a [`NatPool`]. It contains a
/// [`PortAllocator`](port_alloc::PortAllocator), to further allocate ports for this IP address. It
/// also contains a back reference to the parent [`IpAllocator`], to free up the IP address when it
/// is dropped.
#[derive(Debug)]
pub(crate) struct AllocatedIp<I: NatIpWithBitmap> {
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

    pub(crate) fn ip(&self) -> I {
        self.ip
    }

    fn has_free_ports(&self) -> bool {
        self.port_allocator.has_free_ports()
    }

    pub(crate) fn deallocate_block_for_ip(&self, index: usize) {
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

/// A [`NatPool`] is a pool of IP addresses that can be allocated from. It contains a bitmap of
/// available IP addresses, and a list of weak references to [`AllocatedIp`] objects representing
/// the allocated IPs potentially available for use (if they still have free ports)
#[derive(Debug, Clone)]
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

        for ip_weak in self.ips_in_use() {
            if let Some(ip_arc) = ip_weak.upgrade()
                && ip_arc.ip() == ip
            {
                // We found the allocated IP in the list of IPs in use, return it
                return Ok(ip_arc);
            }
        }

        // Allocate the IP now.
        //
        // If the IP was already allocated in the bitmap, this is OK: it means that the IP was
        // allocated in the past, it is no longer in used (because it is not in the list of in-use
        // IPs), but we haven't deallocated from the bitmap yet (this happens when another thread
        // drops an AllocatedIp and its reference count goes to 0, but it hasn't called the drop()
        // function to remove the IP from the bitmap in that other thread yet).
        let _ = self.bitmap.set_ip_allocated(offset);
        let arc_ip = Arc::new(AllocatedIp::new(ip, ip_allocator));
        self.add_in_use(&arc_ip);
        Ok(arc_ip)
    }
}

///////////////////////////////////////////////////////////////////////////////
// PoolBitmap
///////////////////////////////////////////////////////////////////////////////

/// A [`PoolBitmap`] is a bitmap of available IP addresses in a [`NatPool`]. It wraps around a
/// [`RoaringBitmap`], and provides a few methods to manage the bitmap.
#[derive(Debug, Clone)]
pub(crate) struct PoolBitmap(RoaringBitmap);

impl PoolBitmap {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn add_prefix(
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

pub(crate) fn map_offset(
    offset: u32,
    bitmap_mapping: &BTreeMap<u32, u128>,
) -> Result<Ipv6Addr, AllocatorError> {
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
    NatIp::try_from_bits(prefix_start_bits + u128::from(offset - prefix_offset))
        .map_err(|()| AllocatorError::InternalIssue("Failed to convert offset to IPv6".to_string()))
}

// Reverse operation from map_offset()
pub(crate) fn map_address(
    address: Ipv6Addr,
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
