// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIpWithBitmap;
use super::alloc::AllocatedIp;
use crate::stateful::allocator::AllocatorError;
use crate::stateful::port::NatPort;
use concurrency::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize};
use concurrency::sync::{Arc, Mutex, RwLock, Weak};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::thread::ThreadId;

///////////////////////////////////////////////////////////////////////////////
// AllocatorPortBlock
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct AllocatorPortBlock {
    random_index: u8,
    // Candidate for CachePadded
    free: AtomicBool,
}

impl AllocatorPortBlock {
    fn new(index: u8) -> Self {
        Self {
            random_index: index,
            free: AtomicBool::new(true),
        }
    }

    fn to_port_number(&self) -> u16 {
        u16::from(self.random_index) * 256
    }

    fn covers(&self, port: NatPort) -> bool {
        port.as_u16()
            .checked_sub(self.to_port_number())
            .is_some_and(|delta| delta < 256)
    }
}

///////////////////////////////////////////////////////////////////////////////
// PortAllocator
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct PortAllocator<I: NatIpWithBitmap> {
    // Randomised base port numbers from 1024 to 65535, by increments of 256
    //
    // FIXME: We only randomise port blocks at cration of the NatAllocIp, making it trivial to
    // determine port order if the block is later reused.
    //
    // FIXME: We need fake randomisation for tests
    blocks: [AllocatorPortBlock; 252],
    // Candidates for CachePadded? Not sure, given that both atomics should be updated at the same time?
    usable_blocks: AtomicU16,
    current_alloc_index: AtomicUsize,
    thread_blocks: ThreadPortMap,
    allocated_blocks: AllocatedPortBlockMap<I>,
}

impl<I: NatIpWithBitmap> PortAllocator<I> {
    pub fn new() -> Self {
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
            .load(concurrency::sync::atomic::Ordering::Relaxed);
        self.blocks
            .iter()
            .enumerate()
            .cycle()
            .skip(offset)
            .take(self.blocks.len())
    }

    pub fn has_free_ports(&self) -> bool {
        self.usable_blocks
            .load(concurrency::sync::atomic::Ordering::Relaxed)
            > 0
            || self.has_allocated_blocks_with_free_ports()
    }

    pub fn deallocate_block(&self, index: usize) {
        // Do not remove from self.allocated_blocks, as that is managed by the allocator when
        // finding a weak reference that won't upgrade. Removing here would require an additional
        // lookup in the list.
        //
        // TODO: Should we move usable_blocks and blocks into a lock-protected struct? Or adjust the
        // ordering for the atomic operations?
        self.blocks[index]
            .free
            .store(true, concurrency::sync::atomic::Ordering::Relaxed);
        self.usable_blocks
            .fetch_add(1, concurrency::sync::atomic::Ordering::Relaxed);
    }

    fn has_allocated_blocks_with_free_ports(&self) -> bool {
        self.allocated_blocks.has_entries_with_free_ports()
    }

    fn find_available_block(&self) -> Result<(usize, u16), AllocatorError> {
        let (index, block) = self
            .cycle_blocks()
            .find(|(_, block)| {
                block
                    .free
                    .compare_exchange(
                        true,
                        false,
                        concurrency::sync::atomic::Ordering::Relaxed,
                        concurrency::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok()
            })
            .ok_or(AllocatorError::NoPortBlock)?;
        Ok((index, block.to_port_number()))
    }

    fn allocate_block(
        &self,
        ip: Arc<AllocatedIp<I>>,
    ) -> Result<AllocatedPortBlock<I>, AllocatorError> {
        let (index, base_port_index) = self.find_available_block()?;

        self.thread_blocks.set(Some(index));

        self.current_alloc_index
            .store(index, concurrency::sync::atomic::Ordering::Relaxed);

        self.usable_blocks
            .fetch_sub(1, concurrency::sync::atomic::Ordering::Relaxed);

        Ok(AllocatedPortBlock::new(ip, index, base_port_index))
    }

    pub fn allocate_port(
        &self,
        ip: Arc<AllocatedIp<I>>,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
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

    fn try_to_reserve_block(&self, port: NatPort) -> Result<(bool, usize), AllocatorError> {
        let (index, block) = self
            .cycle_blocks()
            .find(|(_, block)| block.covers(port))
            .ok_or(AllocatorError::InternalIssue(
                "Failed to find block for port".to_string(),
            ))?;

        if block
            .free
            .compare_exchange(
                true,
                false,
                concurrency::sync::atomic::Ordering::Relaxed,
                concurrency::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            Ok((true, index))
        } else {
            Ok((false, index))
        }
    }

    fn allocate_block_for_reservation(
        &self,
        ip: Arc<AllocatedIp<I>>,
        index: usize,
        port: NatPort,
    ) -> Arc<AllocatedPortBlock<I>> {
        self.usable_blocks
            .fetch_sub(1, concurrency::sync::atomic::Ordering::Relaxed);
        let block = Arc::new(AllocatedPortBlock::new(
            ip,
            index,
            (port.as_u16() / 256) * 256,
        ));
        self.allocated_blocks
            .insert(block.index, Arc::downgrade(&block));
        block
    }

    fn find_block_for_port(
        &self,
        ip: Arc<AllocatedIp<I>>,
        port: NatPort,
    ) -> Result<Arc<AllocatedPortBlock<I>>, AllocatorError> {
        let (block_was_free, index) = self.try_to_reserve_block(port)?;
        if block_was_free {
            return Ok(self.allocate_block_for_reservation(ip, index, port));
        }
        self.allocated_blocks
            .search_for_block(port)
            // Block was not free but is not in the list of allocated blocks either??
            // FIXME: This can legitimately happen if the block was released just after we checked
            // whether it was free. Do we need an additional lock around the PortAllocator?
            .ok_or(AllocatorError::InternalIssue(
                "Block not free, although absent from list of allocated blocks".to_string(),
            ))
    }

    pub fn reserve_port(
        &self,
        ip: Arc<AllocatedIp<I>>,
        port: NatPort,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        let block = self.find_block_for_port(ip, port)?;
        block.reserve_port_from_block(port)
    }
}

///////////////////////////////////////////////////////////////////////////////
// AllocatedPortBlock
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub(crate) struct AllocatedPortBlock<I: NatIpWithBitmap> {
    ip: Arc<AllocatedIp<I>>,
    base_port_idx: u16,
    index: usize,
    usage_bitmap: Mutex<Bitmap256>,
}

impl<I: NatIpWithBitmap> AllocatedPortBlock<I> {
    fn new(ip: Arc<AllocatedIp<I>>, index: usize, base_port_idx: u16) -> Self {
        Self {
            ip,
            base_port_idx,
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

    fn covers(&self, port: NatPort) -> bool {
        port.as_u16()
            .checked_sub(self.base_port_idx)
            .is_some_and(|delta| delta < 256)
    }

    fn deallocate_port_from_block(self: Arc<Self>, port: NatPort) -> Result<(), AllocatorError> {
        self.usage_bitmap
            .lock()
            .unwrap()
            .deallocate_port_from_bitmap(
                u8::try_from(port.as_u16().checked_sub(self.base_port_idx).ok_or(
                    AllocatorError::InternalIssue(
                        "Subtraction overflow during port deallocation".to_string(),
                    ),
                )?)
                .map_err(|_| {
                    AllocatorError::InternalIssue(
                        "Inconsistent base port index and port value".to_string(),
                    )
                })?,
            )
            .map_err(|()| AllocatorError::InternalIssue("Failed to deallocate port".to_string()))
    }

    fn allocate_port_from_block(self: Arc<Self>) -> Result<AllocatedPort<I>, AllocatorError> {
        let bitmap_offset = self
            .usage_bitmap
            .lock()
            .unwrap()
            .allocate_port_from_bitmap()
            .map_err(|()| AllocatorError::NoFreePort(self.base_port_idx))?;

        NatPort::new_checked(self.base_port_idx + bitmap_offset)
            .map_err(AllocatorError::PortAllocationFailed)
            .map(|port| AllocatedPort::new(port, self.clone()))
    }

    fn reserve_port_from_block(
        self: Arc<Self>,
        port: NatPort,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        self.usage_bitmap
            .lock()
            .unwrap()
            .reserve_port_from_bitmap(
                u8::try_from(port.as_u16().checked_sub(self.base_port_idx).ok_or(
                    AllocatorError::InternalIssue(
                        "Subtraction overflow during port reservation".to_string(),
                    ),
                )?)
                .map_err(|_| {
                    AllocatorError::InternalIssue(
                        "Inconsistent base port index and port value".to_string(),
                    )
                })?,
            )
            .map_err(|()| AllocatorError::NoFreePort(port.as_u16()))?;

        Ok(AllocatedPort::new(port, self.clone()))
    }
}

impl<I: NatIpWithBitmap> Drop for AllocatedPortBlock<I> {
    fn drop(&mut self) {
        self.ip.clone().deallocate_block_for_ip(self.index);
    }
}

///////////////////////////////////////////////////////////////////////////////
// AllocatedPort
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct AllocatedPort<I: NatIpWithBitmap> {
    port: NatPort,
    block_allocator: Arc<AllocatedPortBlock<I>>,
}

impl<I: NatIpWithBitmap> AllocatedPort<I> {
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

impl<I: NatIpWithBitmap> Drop for AllocatedPort<I> {
    fn drop(&mut self) {
        let _ = self
            .block_allocator
            .clone()
            .deallocate_port_from_block(self.port);
    }
}

///////////////////////////////////////////////////////////////////////////////
// ThreadPortMap
///////////////////////////////////////////////////////////////////////////////

// Notes: Daniel reported this struct may not play well with DPDK's thread management.
// Also, other structures than a hashmap + lock may be better suited:
// dashmap, sharded lock, slab.
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

///////////////////////////////////////////////////////////////////////////////
// AllocatedPortBlockMap
///////////////////////////////////////////////////////////////////////////////

// Note: Other structures than a hashmap + lock may be better suited:
// dashmap, sharded lock, slab, const generics?
#[derive(Debug)]
struct AllocatedPortBlockMap<I: NatIpWithBitmap>(
    RwLock<HashMap<usize, Weak<AllocatedPortBlock<I>>>>,
);

impl<I: NatIpWithBitmap> AllocatedPortBlockMap<I> {
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
            .ok_or(AllocatorError::InternalIssue(
                "Weak reference for port block not found".to_string(),
            ))?
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

    fn search_for_block(&self, port: NatPort) -> Option<Arc<AllocatedPortBlock<I>>> {
        let blocks = self.0.read().unwrap();
        blocks
            .values()
            .find(|block| block.upgrade().is_some_and(|block| block.covers(port)))?
            .upgrade()
    }
}

///////////////////////////////////////////////////////////////////////////////
// Bitmap256
///////////////////////////////////////////////////////////////////////////////

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

    fn set_bitmap_value(&mut self, port_in_block: u8, value: u128) -> Result<(), ()> {
        if port_in_block < 128 {
            if self.first_half & (1 << port_in_block) == value {
                return Err(());
            }
            self.first_half |= value << port_in_block;
        } else {
            if self.second_half & (1 << (port_in_block - 128)) == value {
                return Err(());
            }
            self.second_half |= value << (port_in_block - 128);
        }
        Ok(())
    }

    fn deallocate_port_from_bitmap(&mut self, port_in_block: u8) -> Result<(), ()> {
        self.set_bitmap_value(port_in_block, 0)
    }

    fn reserve_port_from_bitmap(&mut self, port_in_block: u8) -> Result<(), ()> {
        self.set_bitmap_value(port_in_block, 1)
    }
}
