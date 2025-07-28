// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::NatIp;
use crate::stateful::allocator::AllocatorError;
use crate::stateful::port::NatPort;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex, RwLock, Weak};

mod port_alloc;

// FIXME: No need for Mutex around bitmap if we're always under NatPool's RwLock
#[derive(Debug)]
pub struct PoolBitmap(Mutex<RoaringBitmap>);

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
}

#[derive(Debug)]
struct NatPool<I: NatIp> {
    bitmap: PoolBitmap,
    bitmap_mapping: BTreeMap<u32, u128>,
    in_use: VecDeque<Weak<AllocatedIp<I>>>,
}

impl<I: NatIp> NatPool<I> {
    fn add_in_use(&mut self, ip: &Arc<AllocatedIp<I>>) {
        self.in_use.push_back(Arc::downgrade(ip));
    }

    fn get_first(&self) -> Option<&Weak<AllocatedIp<I>>> {
        self.in_use.front()
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
        Ok(AllocatedIp::new(ip))
    }
}

#[derive(Debug)]
pub struct IpAllocator<I: NatIp> {
    pool: RwLock<NatPool<I>>,
}

impl<I: NatIp> IpAllocator<I> {
    pub fn new() -> Self {
        Self {
            pool: NatPool {
                bitmap: PoolBitmap::new(),
                bitmap_mapping: BTreeMap::new(),
                in_use: VecDeque::new(),
            }
            .into(),
        }
    }
}

impl<I: NatIp> IpAllocator<I> {
    fn reuse_allocated_ip(&self) -> Result<AllocatedPort<I>, AllocatorError> {
        let allocated_ips = self.pool.read().unwrap();
        for ip_weak in allocated_ips.ips_in_use() {
            let Some(ip) = ip_weak.upgrade() else {
                continue;
            };
            if !ip.has_free_ports() {
                continue;
            }
            match ip.allocate_port() {
                Ok(port) => return Ok(port),
                Err(AllocatorError::NoFreePort(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Err(AllocatorError::NoFreeIp)
    }

    fn allocate_new_ip(&self) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        let mut allocated_ips = self.pool.write().unwrap();
        let new_ip = allocated_ips.use_new_ip()?;
        allocated_ips.add_in_use(&Arc::new(new_ip));

        allocated_ips
            .get_first()
            .unwrap()
            .upgrade()
            .ok_or(AllocatorError::InternalIssue)
    }

    fn cleanup_used_ips(&self) {
        let mut allocated_ips = self.pool.write().unwrap();
        allocated_ips.cleanup();
    }

    pub fn allocate(&self) -> Result<AllocatedPort<I>, AllocatorError> {
        // FIXME: Should we clean up every time??
        self.cleanup_used_ips();

        if let Ok(port) = self.reuse_allocated_ip() {
            return Ok(port);
        }

        if let Ok(ip) = self.allocate_new_ip() {
            return ip.allocate_port();
        }

        Err(AllocatorError::NoFreeIp)
    }
}

pub fn map_offset(
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

#[derive(Debug)]
struct AllocatedIp<I: NatIp> {
    ip: I,
    block_allocator: port_alloc::BlockAllocator,
    allocated_blocks: RwLock<VecDeque<Arc<AllocatedPortBlock<I>>>>,
}

impl<I: NatIp> AllocatedIp<I> {
    fn new(ip: I) -> Self {
        Self {
            ip,
            block_allocator: port_alloc::BlockAllocator::new(),
            allocated_blocks: RwLock::new(VecDeque::new()),
        }
    }

    fn ip(&self) -> I {
        self.ip
    }

    fn has_free_ports(&self) -> bool {
        todo!()
    }

    fn allocate_block(self: Arc<Self>) -> Result<AllocatedPortBlock<I>, AllocatorError> {
        self.block_allocator.allocate(self.clone())
    }

    fn allocate_port(self: Arc<Self>) -> Result<AllocatedPort<I>, AllocatorError> {
        // TODO: error handling for port
        let allocated_block = self.allocate_block()?;
        Arc::new(allocated_block).allocate_port()
    }
}

impl<I: NatIp> Drop for AllocatedIp<I> {
    fn drop(&mut self) {
        todo!()
    }
}

#[derive(Debug)]
pub struct AllocatedPortBlock<I: NatIp> {
    ip: Arc<AllocatedIp<I>>,
    base_port_idx: u16,
    index: usize,
    usage_bitmap: Mutex<port_alloc::Bitmap256>,
}

impl<I: NatIp> AllocatedPortBlock<I> {
    fn new(ip: Arc<AllocatedIp<I>>, index: usize, base_port_index: u8) -> Self {
        Self {
            ip,
            base_port_idx: u16::from(base_port_index),
            index,
            usage_bitmap: Mutex::new(port_alloc::Bitmap256::new()),
        }
    }

    fn allocate_port(self: Arc<Self>) -> Result<AllocatedPort<I>, AllocatorError> {
        let bitmap_offset = self
            .usage_bitmap
            .lock()
            .unwrap()
            .allocate()
            .map_err(|()| AllocatorError::NoFreePort(self.base_port_idx))?;

        NatPort::new_checked(self.base_port_idx * 256 + bitmap_offset)
            .map_err(AllocatorError::PortAllocationFailed)
            .map(|port| AllocatedPort::new(port, self.clone()))
    }
}

impl<I: NatIp> Drop for AllocatedPortBlock<I> {
    fn drop(&mut self) {
        todo!()
    }
}

#[derive(Debug)]
pub struct AllocatedPort<I: NatIp> {
    port: NatPort,
    block_allocator: Arc<AllocatedPortBlock<I>>,
}

impl<I: NatIp> AllocatedPort<I> {
    pub fn new(port: NatPort, block_allocator: Arc<AllocatedPortBlock<I>>) -> Self {
        Self {
            port,
            block_allocator,
        }
    }

    pub fn port(&self) -> NatPort {
        self.port
    }
}

impl<I: NatIp> Drop for AllocatedPort<I> {
    fn drop(&mut self) {
        todo!()
    }
}
