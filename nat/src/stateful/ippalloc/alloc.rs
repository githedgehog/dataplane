// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::NatIp;
use crate::stateful::allocator::AllocatorError;
use crate::stateful::port::NatPort;
use rand::seq::SliceRandom;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread::ThreadId;

///////////////////////////////////////////////////////////////////////////////
// Allocators
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct IpAllocator<I: NatIpWithBitmap> {
    pool: RwLock<NatPool<I>>,
}

impl<I: NatIpWithBitmap> IpAllocator<I> {
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

impl<I: NatIpWithBitmap> IpAllocator<I> {
    fn reuse_allocated_ip(&self) -> Result<AllocatedPort<I>, AllocatorError> {
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
        allocated_ips.add_in_use(&Arc::new(new_ip));

        allocated_ips
            .get_first()
            .unwrap()
            .upgrade()
            .ok_or(AllocatorError::InternalIssue)
    }

    fn allocate_from_new_ip(&self) -> Result<AllocatedPort<I>, AllocatorError> {
        self.allocate_new_ip_from_pool()
            .and_then(AllocatedIp::allocate_port_for_ip)
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

        self.allocate_from_new_ip()
    }
}

#[derive(Debug)]
struct AllocatorPortBlock {
    base_port_idx: u8,
    free: AtomicBool,
}

impl AllocatorPortBlock {
    fn new(base_port_idx: u8) -> Self {
        Self {
            base_port_idx,
            free: AtomicBool::new(true),
        }
    }
}

#[derive(Debug)]
struct PortAllocator<I: NatIp> {
    // Randomised base port numbers from 1024 to 65535, by increments of 256
    //
    // FIXME: We only randomise port blocks at cration of the NatAllocIp, making it trivial to
    // determine port order if the block is later reused.
    //
    // FIXME: We need fake randomisation for tests
    blocks: [AllocatorPortBlock; 252],
    usable_blocks: AtomicU16,
    current_alloc_index: AtomicUsize,
    thread_blocks: ThreadPortMap,
    allocated_blocks: AllocatedPortBlockMap<I>,
}

impl<I: NatIp> PortAllocator<I> {
    fn new() -> Self {
        let mut rng = rand::rng();
        // Skip ports 0 to 1023
        let mut base_ports = (4..=255).collect::<Vec<_>>();

        base_ports.shuffle(&mut rng);
        let blocks = std::array::from_fn(|i| AllocatorPortBlock::new(base_ports[i]));

        Self {
            blocks,
            usable_blocks: AtomicU16::new(251),
            current_alloc_index: AtomicUsize::new(0),
            thread_blocks: ThreadPortMap::new(),
            allocated_blocks: AllocatedPortBlockMap::new(),
        }
    }

    fn cycle_blocks(&self) -> impl Iterator<Item = (usize, &AllocatorPortBlock)> {
        let offset = self
            .current_alloc_index
            .load(std::sync::atomic::Ordering::SeqCst);
        self.blocks
            .iter()
            .cycle()
            .skip(offset)
            .take(self.blocks.len())
            .scan(offset, |index, block| {
                let res_index = *index;
                *index = (*index + 1) % self.blocks.len();
                Some((res_index, block))
            })
    }

    fn has_free_ports(&self) -> bool {
        self.usable_blocks.load(std::sync::atomic::Ordering::SeqCst) > 0
            || self.has_allocated_blocks_with_free_ports()
    }

    fn has_allocated_blocks_with_free_ports(&self) -> bool {
        self.allocated_blocks.has_entries_with_free_ports()
    }

    fn find_available_block(&self) -> Result<(usize, u8), AllocatorError> {
        let (index, block) = self
            .cycle_blocks()
            .find(|(_, block)| {
                block
                    .free
                    .compare_exchange(
                        true,
                        false,
                        // TODO: Check these
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                    )
                    .is_ok()
            })
            .ok_or(AllocatorError::NoPortBlock)?;
        Ok((index, block.base_port_idx))
    }

    fn allocate_block(
        &self,
        ip: Arc<AllocatedIp<I>>,
    ) -> Result<AllocatedPortBlock<I>, AllocatorError> {
        let (index, base_port_index) = self.find_available_block()?;

        self.thread_blocks.set(Some(index));

        self.current_alloc_index
            .store(index, std::sync::atomic::Ordering::SeqCst);

        self.usable_blocks
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

        Ok(AllocatedPortBlock::new(ip, index, base_port_index))
    }

    fn allocate_port(&self, ip: Arc<AllocatedIp<I>>) -> Result<AllocatedPort<I>, AllocatorError> {
        let thread_block_index = self.thread_blocks.get();

        if let Some(index) = thread_block_index {
            if let Some(current_block) = self.allocated_blocks.get(index)? {
                if !current_block.is_full() {
                    return current_block.allocate_port_from_block();
                }
            }
        }

        let block = Arc::new(self.allocate_block(ip)?);
        self.allocated_blocks
            .insert(block.index, Arc::downgrade(&block));
        block.allocate_port_from_block()
    }
}

///////////////////////////////////////////////////////////////////////////////
// Allocated components
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct AllocatedIp<I: NatIp> {
    ip: I,
    port_allocator: PortAllocator<I>,
}

impl<I: NatIp> AllocatedIp<I> {
    fn new(ip: I) -> Self {
        Self {
            ip,
            port_allocator: PortAllocator::new(),
        }
    }

    fn ip(&self) -> I {
        self.ip
    }

    fn has_free_ports(&self) -> bool {
        self.port_allocator.has_free_ports()
    }

    fn allocate_port_for_ip(self: Arc<Self>) -> Result<AllocatedPort<I>, AllocatorError> {
        self.port_allocator.allocate_port(self.clone())
    }
}

impl<I: NatIp> Drop for AllocatedIp<I> {
    fn drop(&mut self) {
        todo!()
    }
}

#[derive(Debug)]
struct AllocatedPortBlock<I: NatIp> {
    ip: Arc<AllocatedIp<I>>,
    base_port_idx: u16,
    index: usize,
    usage_bitmap: Mutex<Bitmap256>,
}

impl<I: NatIp> AllocatedPortBlock<I> {
    fn new(ip: Arc<AllocatedIp<I>>, index: usize, base_port_index: u8) -> Self {
        Self {
            ip,
            base_port_idx: u16::from(base_port_index),
            index,
            usage_bitmap: Mutex::new(Bitmap256::new()),
        }
    }

    fn ip(&self) -> I {
        self.ip.ip()
    }

    fn is_full(&self) -> bool {
        self.usage_bitmap.lock().unwrap().bitmap_full()
    }

    fn allocate_port_from_block(self: Arc<Self>) -> Result<AllocatedPort<I>, AllocatorError> {
        let bitmap_offset = self
            .usage_bitmap
            .lock()
            .unwrap()
            .allocate_port_from_bitmap()
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
    fn new(port: NatPort, block_allocator: Arc<AllocatedPortBlock<I>>) -> Self {
        Self {
            port,
            block_allocator,
        }
    }

    pub fn port(&self) -> NatPort {
        self.port
    }

    pub fn ip(&self) -> I {
        self.block_allocator.ip()
    }
}

impl<I: NatIp> Drop for AllocatedPort<I> {
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
    in_use: VecDeque<Weak<AllocatedIp<I>>>,
}

impl<I: NatIpWithBitmap> NatPool<I> {
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
struct ThreadPortMap(RwLock<HashMap<ThreadId, Option<usize>>>);

impl ThreadPortMap {
    fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    fn get(&self) -> Option<usize> {
        self.0
            .read()
            .unwrap()
            .get(&std::thread::current().id())
            .copied()
            .unwrap_or(None)
    }

    fn set(&self, index: Option<usize>) {
        self.0
            .write()
            .unwrap()
            .insert(std::thread::current().id(), index);
    }
}

#[derive(Debug)]
struct AllocatedPortBlockMap<I: NatIp>(RwLock<HashMap<usize, Weak<AllocatedPortBlock<I>>>>);

impl<I: NatIp> AllocatedPortBlockMap<I> {
    fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    fn get_weak(&self, index: usize) -> Option<Weak<AllocatedPortBlock<I>>> {
        self.0.read().unwrap().get(&index).cloned()
    }

    fn remove(&self, index: usize) {
        self.0.write().unwrap().remove(&index);
    }

    fn get(&self, index: usize) -> Result<Option<Arc<AllocatedPortBlock<I>>>, AllocatorError> {
        Ok(self
            .get_weak(index)
            .ok_or(AllocatorError::InternalIssue)?
            .upgrade()
            .or_else(|| {
                self.remove(index);
                None
            }))
    }

    fn insert(&self, index: usize, block: Weak<AllocatedPortBlock<I>>) {
        self.0.write().unwrap().insert(index, block);
    }

    fn has_entries_with_free_ports(&self) -> bool {
        self.0
            .read()
            .unwrap()
            .values()
            .any(|block| block.upgrade().is_some_and(|block| !block.is_full()))
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
}

#[derive(Debug, Clone)]
struct Bitmap256 {
    first_half: u128,
    second_half: u128,
}

impl Bitmap256 {
    fn new() -> Self {
        Self {
            first_half: 0,
            second_half: 0,
        }
    }

    fn bitmap_full(&self) -> bool {
        self.first_half == u128::MAX && self.second_half == u128::MAX
    }

    fn allocate_port_from_bitmap(&mut self) -> Result<u16, ()> {
        #[allow(clippy::cast_possible_truncation)] // max value is 128
        let ones = self.first_half.leading_ones() as u16;
        if ones < 128 {
            self.first_half |= 1 << ones;
            return Ok(ones);
        }

        #[allow(clippy::cast_possible_truncation)] // max value is 128
        let ones = self.second_half.leading_ones() as u16;
        if ones < 128 {
            self.second_half |= 1 << ones;
            return Ok(ones + 128);
        }

        // Both halves are full
        Err(())
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
        bitmap_mapping: &BTreeMap<u32, u128>,
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
        _bitmap_mapping: &BTreeMap<u32, u128>,
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
        bitmap_mapping: &BTreeMap<u32, u128>,
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
    bitmap_mapping: &BTreeMap<u32, u128>,
) -> Result<u32, AllocatorError> {
    todo!()
}
