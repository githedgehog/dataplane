// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port allocation components for the default allocator for stateful NAT
//!
//! This submodule is the logical continuation of the `alloc` submodule, focusing on allocating
//! ports for a given IP address. The entry point is the [`PortAllocator`] struct.
//!
//! See also the architecture diagram at the top of mod.rs.

use super::NatIpWithBitmap;
use super::alloc::AllocatedIp;
use crate::stateful::allocator::AllocatorError;
use crate::stateful::port::NatPort;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread::ThreadId;

///////////////////////////////////////////////////////////////////////////////
// AllocatorPortBlock
///////////////////////////////////////////////////////////////////////////////

/// [`AllocatorPortBlock`] contains metadata about a block of ports, whether or not it's been
/// allocated. This metadata includes the status (whether or not it's free), and the `random_index`.
/// This index is used to represent the position, initially picked at random, of the block in the
/// list of all blocks. This is used to (somewhat) randomise the order of port allocation for a
/// given IP address.
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

/// [`PortAllocator`] is a port allocator for a given IP address. In fact, it does not allocate
/// ports itself, but handles block of ports ([`AllocatedPortBlock`]s) from which the final ports
/// are effectively allocated.
#[derive(Debug)]
pub(crate) struct PortAllocator<I: NatIpWithBitmap> {
    blocks: [AllocatorPortBlock; 256],
    // TODO: Candidates for CachePadded? Not sure, given that both atomics should be updated at the same time?
    usable_blocks: AtomicU16,
    current_alloc_index: AtomicUsize,
    thread_blocks: ThreadPortMap,
    allocated_blocks: AllocatedPortBlockMap<I>,
}

impl<I: NatIpWithBitmap> PortAllocator<I> {
    pub(crate) fn new() -> Self {
        let mut base_ports = (0..=255).collect::<Vec<_>>();

        // Shuffle the list of port blocks for the port allocator. This way, we can pick blocks in a
        // "random" order when allocating them, and have ports allocated in a "random" order. The
        // quotes denote that this is not completely random: ports are allocated sequentially within
        // a 256-port block.
        Self::shuffle_slice(&mut base_ports);
        let blocks = std::array::from_fn(|i| AllocatorPortBlock::new(base_ports[i]));

        Self {
            blocks,
            usable_blocks: AtomicU16::new(256),
            current_alloc_index: AtomicUsize::new(0),
            thread_blocks: ThreadPortMap::new(),
            allocated_blocks: AllocatedPortBlockMap::new(),
        }
    }

    fn shuffle_slice<T>(slice: &mut [T]) {
        let mut rng = rand::rng();
        slice.shuffle(&mut rng);
    }

    // Iterate over the slice of all blocks, but starting from a given offset (and looping at the
    // end), returning the block and its index from the initial slice.
    //
    // Example: ["a", "b", "c", "d"] with offset 2 yields [(2, "c"), (3, "d"), (0, "a"), (1, "b")]
    fn cycle_blocks(&self) -> impl Iterator<Item = (usize, &AllocatorPortBlock)> {
        let offset = self
            .current_alloc_index
            .load(std::sync::atomic::Ordering::Relaxed);
        self.blocks
            .iter()
            .enumerate()
            .cycle()
            .skip(offset)
            .take(self.blocks.len())
    }

    pub(crate) fn has_free_ports(&self) -> bool {
        self.usable_blocks
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
            || self.has_allocated_blocks_with_free_ports()
    }

    fn has_allocated_blocks_with_free_ports(&self) -> bool {
        self.allocated_blocks.has_entries_with_free_ports()
    }

    // Find an available block to allocate ports from, and mark it as non-free.
    fn pick_available_block(&self) -> Result<(usize, u16), AllocatorError> {
        // Find the first free block in the list, starting from the current self.current_alloc_index
        let (index, block) = self
            .cycle_blocks()
            .find(|(_, block)| {
                // Find the first block for which the atomic compare_exchange succeeds
                block
                    .free
                    .compare_exchange(
                        true,
                        false,
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
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
        // Pick an available block to allocate ports from. This is thread-safe because we atomically
        // compare and exchange the block status. We can then update the other items
        // (current_alloc_index, thread_blocks, usable_blocks) in the rest of the function.
        let (index, base_port_index) = self.pick_available_block()?;

        self.thread_blocks.set(Some(index));

        self.current_alloc_index
            .store(index, std::sync::atomic::Ordering::Relaxed);

        self.usable_blocks
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        AllocatedPortBlock::new(ip, index, base_port_index)
    }

    pub(crate) fn allocate_port(
        &self,
        ip: Arc<AllocatedIp<I>>,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        let thread_block_index = self.thread_blocks.get();

        // Try to allocate a port from the block currently used by this thread
        if let Some(index) = thread_block_index
            && let Some(current_block) = self.allocated_blocks.get(index)
            && !current_block.is_full()
        {
            return current_block.allocate_port_from_block();
        }

        // If we didn't find a port, allocate and use a new block
        let block = Arc::new(self.allocate_block(ip)?);
        self.allocated_blocks
            .insert(block.index, Arc::downgrade(&block));
        block.allocate_port_from_block()
    }
}

///////////////////////////////////////////////////////////////////////////////
// AllocatedPortBlock
///////////////////////////////////////////////////////////////////////////////

/// [`AllocatedPortBlock`] is a block of ports that have been allocated for a specific IP address.
/// It serves as a finer-grained allocator for ports, within the represented port block, and
/// contains a bitmap to that effect.
///
/// Not to be confused with [`AllocatorPortBlock`], which represents the status (free or in use) for
/// a block for a given IP address.
#[derive(Debug)]
pub(crate) struct AllocatedPortBlock<I: NatIpWithBitmap> {
    ip: Arc<AllocatedIp<I>>,
    base_port_idx: u16,
    index: usize,
    usage_bitmap: Mutex<Bitmap256>,
}

impl<I: NatIpWithBitmap> AllocatedPortBlock<I> {
    fn new(
        ip: Arc<AllocatedIp<I>>,
        index: usize,
        base_port_idx: u16,
    ) -> Result<Self, AllocatorError> {
        let block = Self {
            ip,
            base_port_idx,
            index,
            usage_bitmap: Mutex::new(Bitmap256::new()),
        };
        // Port 0 is reserved, we don't want to use it. Mark as not free.
        if block.base_port_idx == 0 {
            block
                .usage_bitmap
                .lock()
                .unwrap()
                .reserve_port_from_bitmap(0)
                .map_err(|()| {
                    AllocatorError::InternalIssue(
                        "Failed to reserve port 0 from new block".to_string(),
                    )
                })?;
        }
        Ok(block)
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
}

///////////////////////////////////////////////////////////////////////////////
// AllocatedPort
///////////////////////////////////////////////////////////////////////////////

/// [`AllocatedPort`] not only represents an allocated port, but also the corresponding IP address,
/// making it the final object resulting from the allocation process, and the one that the allocator
/// returns.
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

///////////////////////////////////////////////////////////////////////////////
// ThreadPortMap
///////////////////////////////////////////////////////////////////////////////

/// [`ThreadPortMap`] is a thread-safe map of thread IDs to port indices. It is used to keep track
/// of the current port block that each thread is using, in order to have each thread work on a
/// separate block and avoid contention.
//
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

/// [`AllocatedPortBlockMap`] is a thread-safe map of [`AllocatedPortBlock`]s. It is used to keep
/// track of allocated port blocks. It contains weak references only, to avoid circular
/// dependencies.
//
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

    fn get(&self, index: usize) -> Option<Arc<AllocatedPortBlock<I>>> {
        self.get_weak(index)?.upgrade().or_else(|| {
            self.remove(index);
            None
        })
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

/// [`Bitmap256`] is a bitmap of 256 bits, stored as two `u128`. It is used to keep track of
/// allocated ports in a [`AllocatedPortBlock`].
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

    // The bitmap is made of two u128, the first one for port values (0)-127, the second one for
    // port values 128-255.
    //
    // For each half, we allocate starting with the rightmost bits (smallest port values). For example:
    //
    //   - 0   is stored as (000...001, 000...000)
    //   - 1   is stored as (000...010, 000...000)
    //   - 128 is stored as (000...000, 000...001)
    //   - 255 is stored as (000...000, 100...000)
    //   - 0, 1, 2, 254 are stored as (000...00111, 010...000)
    //
    // To find the first (lowest) free (at zero) port value, we count the number of trailing ones
    // for the first half, then, if relevant, for the second one.
    //
    // In the last example above, we have three trailing ones in the first half, telling us that
    // port at 1 << 3 (port number 3) is free.
    fn allocate_port_from_bitmap(&mut self) -> Result<u16, ()> {
        #[allow(clippy::cast_possible_truncation)] // max value is 128
        let ones = self.first_half.trailing_ones() as u16;
        if ones < 128 {
            self.first_half |= 1 << ones;
            return Ok(ones);
        }

        #[allow(clippy::cast_possible_truncation)] // max value is 128
        let ones = self.second_half.trailing_ones() as u16;
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

    fn reserve_port_from_bitmap(&mut self, port_in_block: u8) -> Result<(), ()> {
        self.set_bitmap_value(port_in_block, 1)
    }
}
