// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::alloc::AllocatedIp;
use crate::stateful::NatIp;
use crate::stateful::allocator::AllocatorError;
use crate::stateful::port::NatPort;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread::ThreadId;

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
pub struct PortAllocator<I: NatIp> {
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
            .load(std::sync::atomic::Ordering::Relaxed);
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

    pub fn has_free_ports(&self) -> bool {
        self.usable_blocks
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
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
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
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
            .store(index, std::sync::atomic::Ordering::Relaxed);

        self.usable_blocks
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

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
