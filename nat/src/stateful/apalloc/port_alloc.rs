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
use crate::port::NatPort;
use crate::stateful::allocator::AllocatorError;
use concurrency::concurrency_mode;
use concurrency::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize};
use concurrency::sync::{Arc, Mutex, RwLock, Weak};
use lpm::prefix::PortRange;
use std::collections::{BTreeSet, HashMap};
use std::thread::ThreadId;

#[concurrency_mode(std)]
use rand::seq::SliceRandom;
#[concurrency_mode(shuttle)]
use shuttle::rand::{Rng, thread_rng};

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

impl From<&AllocatorPortBlock> for PortRange {
    fn from(value: &AllocatorPortBlock) -> Self {
        let start = value.to_port_number();
        PortRange::new(start, start + 255).unwrap_or_else(|_| unreachable!())
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
    reserved_port_range: Option<PortRange>,
}

impl<I: NatIpWithBitmap> PortAllocator<I> {
    pub(crate) fn new(reserved_port_range: Option<PortRange>, randomize: bool) -> Self {
        let mut base_ports = (0..=255).collect::<Vec<_>>();

        // Shuffle the list of port blocks for the port allocator. This way, we can pick blocks in a
        // "random" order when allocating them, and have ports allocated in a "random" order. The
        // quotes denote that this is not completely random: ports are allocated sequentially within
        // a 256-port block.
        if randomize {
            Self::shuffle_slice(&mut base_ports);
        }
        let blocks = std::array::from_fn(|i| AllocatorPortBlock::new(base_ports[i]));

        Self {
            blocks,
            usable_blocks: AtomicU16::new(256),
            current_alloc_index: AtomicUsize::new(0),
            thread_blocks: ThreadPortMap::new(),
            allocated_blocks: AllocatedPortBlockMap::new(),
            reserved_port_range,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_no_randomness(reserved_port_range: Option<PortRange>) -> Self {
        Self::new(reserved_port_range, false)
    }

    #[concurrency_mode(std)]
    fn shuffle_slice<T>(slice: &mut [T]) {
        let mut rng = rand::rng();
        slice.shuffle(&mut rng);
    }

    #[concurrency_mode(shuttle)]
    fn shuffle_slice<T>(slice: &mut [T]) {
        let mut rng = thread_rng();
        for i in 0..slice.len() {
            let index = rng.r#gen::<usize>() % slice.len();
            slice.swap(i, index);
        }
    }

    // Iterate over the slice of all blocks, but starting from a given offset (and looping at the
    // end), returning the block and its index from the initial slice.
    //
    // Example: ["a", "b", "c", "d"] with offset 2 yields [(2, "c"), (3, "d"), (0, "a"), (1, "b")]
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

    pub(crate) fn has_free_ports(&self) -> bool {
        self.usable_blocks
            .load(concurrency::sync::atomic::Ordering::Relaxed)
            > 0
            || self.has_allocated_blocks_with_free_ports()
    }

    pub(crate) fn deallocate_block(&self, index: usize) {
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

    // Find an available block to allocate ports from, and mark it as non-free.
    fn pick_available_block(&self) -> Result<(usize, u16), AllocatorError> {
        // Find the first free block in the list, starting from the current self.current_alloc_index
        let (index, block) = self
            .cycle_blocks()
            .find(|(_, block)| {
                // Find the first block for which the atomic compare_exchange succeeds
                if block
                    .free
                    .compare_exchange(
                        true,
                        false,
                        concurrency::sync::atomic::Ordering::Relaxed,
                        concurrency::sync::atomic::Ordering::Relaxed,
                    )
                    .is_err()
                {
                    return false;
                }

                // Check if this block is fully contained in the reserved range
                if let Some(reserved_range) = self.reserved_port_range
                    && reserved_range.len() >= 255
                {
                    // Corner case: reserved_range is 1-255+, but 0 cannot be allocated so
                    // reserved_range effectively renders the block unusable (except maybe for ICMP
                    // but never mind)
                    let adjusted_reserved_range = if reserved_range.start() == 1 {
                        PortRange::new(0, reserved_range.end()).unwrap_or_else(|_| unreachable!())
                    } else {
                        reserved_range
                    };

                    let block_range = PortRange::from(*block);
                    if adjusted_reserved_range.covers(block_range) {
                        return false;
                    }
                }
                true
            })
            .ok_or(AllocatorError::NoPortBlock)?;
        Ok((index, block.to_port_number()))
    }

    fn allocate_block(
        &self,
        ip: Arc<AllocatedIp<I>>,
        allow_null: bool,
    ) -> Result<AllocatedPortBlock<I>, AllocatorError> {
        // Pick an available block to allocate ports from. This is thread-safe because we atomically
        // compare and exchange the block status. We can then update the other items
        // (current_alloc_index, thread_blocks, usable_blocks) in the rest of the function.
        let (index, base_port_index) = self.pick_available_block()?;

        self.thread_blocks.set(Some(index));

        self.current_alloc_index
            .store(index, concurrency::sync::atomic::Ordering::Relaxed);

        self.usable_blocks
            .fetch_sub(1, concurrency::sync::atomic::Ordering::Relaxed);

        let reserved_port_range_for_block = self.reserved_port_range.and_then(|range| {
            range.intersection(
                PortRange::new(base_port_index, base_port_index + 255)
                    .unwrap_or_else(|_| unreachable!()),
            )
        });

        AllocatedPortBlock::new(
            ip,
            index,
            base_port_index,
            reserved_port_range_for_block,
            allow_null,
        )
    }

    pub(crate) fn allocate_port(
        &self,
        ip: Arc<AllocatedIp<I>>,
        allow_null: bool,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        let thread_block_index = self.thread_blocks.get();

        // Try to allocate a port from the block currently used by this thread
        if let Some(index) = thread_block_index
            && let Some(current_block) = self.allocated_blocks.get(index)
            && !current_block.is_full()
        {
            return current_block.allocate_port_from_block(allow_null);
        }

        // If we didn't find a port, allocate and use a new block
        let block = Arc::new(self.allocate_block(ip, allow_null)?);
        self.allocated_blocks
            .insert(block.index, Arc::downgrade(&block));
        block.allocate_port_from_block(allow_null)
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
            // "false" means the block was already set to non-free
            Ok((false, index))
        }
    }

    fn allocate_block_for_reservation(
        &self,
        ip: Arc<AllocatedIp<I>>,
        index: usize,
        port: NatPort,
        allow_null: bool,
    ) -> Result<Arc<AllocatedPortBlock<I>>, AllocatorError> {
        self.usable_blocks
            .fetch_sub(1, concurrency::sync::atomic::Ordering::Relaxed);
        let block = Arc::new(AllocatedPortBlock::new(
            ip,
            index,
            (port.as_u16() / 256) * 256, // port block base index, discard offset within block
            None,
            allow_null,
        )?);
        self.allocated_blocks
            .insert(block.index, Arc::downgrade(&block));
        Ok(block)
    }

    fn find_block_for_port(
        &self,
        ip: Arc<AllocatedIp<I>>,
        port: NatPort,
    ) -> Result<Arc<AllocatedPortBlock<I>>, AllocatorError> {
        let (block_was_free, index) = self.try_to_reserve_block(port)?;
        let allow_null = matches!(port, NatPort::Identifier(_));
        if block_was_free {
            return self.allocate_block_for_reservation(ip, index, port, allow_null);
        }
        self.allocated_blocks
            .search_for_block(port)
            // Block was not free but is not in the list of allocated blocks either??
            //
            // FIXME: This can legitimately happen if the block was released just after we checked
            // whether it was free? (Not observed in shuttle tests so far.) Do we need an additional
            // lock around the PortAllocator?
            .ok_or(AllocatorError::InternalIssue(
                "Block not free, although absent from list of allocated blocks".to_string(),
            ))
    }

    pub(crate) fn reserve_port(
        &self,
        ip: Arc<AllocatedIp<I>>,
        port: NatPort,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        let block = self.find_block_for_port(ip, port)?;
        block.reserve_port_from_block(port)
    }

    pub(crate) fn reserved_port_range(&self) -> Option<PortRange> {
        self.reserved_port_range
    }

    // Used for Display
    pub(crate) fn allocated_port_ranges(&self) -> BTreeSet<PortRange> {
        self.allocated_blocks.allocated_port_ranges()
    }
}

///////////////////////////////////////////////////////////////////////////////
// AllocatedPortBlock
///////////////////////////////////////////////////////////////////////////////

/// [`AllocatedPortBlock`] is a block of ports that have been allocated for a specific IP address.
/// It serves as a finer-grained allocator for ports, within the represented port block, and
/// contains a bitmap to that effect.
///
/// It also contains a back reference to its parent [`AllocatedIp`], to deallocate the block when
/// the [`AllocatedPortBlock`] is dropped.
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
        reserved_port_range: Option<PortRange>,
        allow_null: bool,
    ) -> Result<Self, AllocatorError> {
        let block = Self {
            ip,
            base_port_idx,
            index,
            usage_bitmap: Mutex::new(Bitmap256::new()),
        };
        // Port 0 may be reserved, in which case we don't want to use it, so we mark it as not free.
        let reserve_zero = !allow_null && block.base_port_idx == 0;
        let reserve_range = reserved_port_range.is_some();
        if reserve_zero || reserve_range {
            let mut mutex_guard = block.usage_bitmap.lock().unwrap();
            if reserve_zero {
                mutex_guard.reserve_port_from_bitmap(0).map_err(|()| {
                    AllocatorError::InternalIssue(
                        "Failed to reserve port 0 from new block".to_string(),
                    )
                })?;
            }
            if reserve_range {
                mutex_guard
                    .reserve_port_range_from_bitmap(
                        // We just check that reserved_port_range.is_some()
                        reserved_port_range.unwrap_or_else(|| unreachable!()),
                    )
                    .map_err(|()| {
                        AllocatorError::InternalIssue(
                            "Failed to reserve port range from new block".to_string(),
                        )
                    })?;
            }
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

    fn deallocate_port_from_block(&self, port: NatPort) -> Result<(), AllocatorError> {
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

    fn allocate_port_from_block(
        self: Arc<Self>,
        allow_null: bool,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        let bitmap_offset = self
            .usage_bitmap
            .lock()
            .unwrap()
            .allocate_port_from_bitmap()
            .map_err(|()| AllocatorError::NoFreePort(self.base_port_idx))?;

        if allow_null {
            Ok(AllocatedPort::new(
                NatPort::Identifier(self.base_port_idx + bitmap_offset),
                self.clone(),
            ))
        } else {
            // We can't have picked 0 in first port block because we marked port 0 as used in the
            // bitmap at bitmap creation time.
            NatPort::new_port_checked(self.base_port_idx + bitmap_offset)
                .map_err(AllocatorError::PortAllocationFailed)
                .map(|port| AllocatedPort::new(port, self.clone()))
        }
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

    // Used for Display
    fn allocated_port_ranges(&self) -> BTreeSet<PortRange> {
        self.usage_bitmap
            .lock()
            .unwrap()
            .allocated_port_ranges()
            .iter()
            .map(|range| {
                PortRange::new(
                    range.start() + self.base_port_idx,
                    range.end() + self.base_port_idx,
                )
                .unwrap_or_else(|_| unreachable!())
            })
            .collect()
    }
}

impl<I: NatIpWithBitmap> Drop for AllocatedPortBlock<I> {
    fn drop(&mut self) {
        self.ip.deallocate_block_for_ip(self.index);
    }
}

///////////////////////////////////////////////////////////////////////////////
// AllocatedPort
///////////////////////////////////////////////////////////////////////////////

/// [`AllocatedPort`] not only represents an allocated port, but also the corresponding IP address,
/// making it the final object resulting from the allocation process, and the one that the allocator
/// returns.
///
/// It contains a back reference to its parent [`AllocatedPortBlock`], to deallocate the port when
/// the [`AllocatedPort`] is dropped.
#[derive(Debug, Clone)]
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
        let _ = self.block_allocator.deallocate_port_from_block(self.port);
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
/// dependencies. When a block gets dropped, its reference no longer resolves. Strong references to
/// [`AllocatedPortBlock`]s are kept as back references by their children [`AllocatedPort`] objects.
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

    // Used for Display
    fn allocated_port_ranges(&self) -> BTreeSet<PortRange> {
        let blocks = self.0.read().unwrap();
        let mut ranges = BTreeSet::<PortRange>::new();
        for (_, block) in blocks.iter() {
            if let Some(block) = block.upgrade() {
                merge_ranges(&mut ranges, block.allocated_port_ranges());
            }
        }
        ranges
    }
}

// Extend ranges_left with ranges_right, consuming ranges_right, and merging adjacent ranges when
// possible. The function assumes port ranges are all disjoint, and that all ranges in ranges_right
// are contained within an aligned, 256-port block.
fn merge_ranges(ranges_left: &mut BTreeSet<PortRange>, mut ranges_right: BTreeSet<PortRange>) {
    if ranges_right.is_empty() {
        return;
    }
    let single_element = ranges_right.len() == 1;

    let mut new_range = ranges_right.pop_first().unwrap_or_else(|| unreachable!());
    // Try to merge new_range left
    if new_range.start() > 0
        && new_range.start().is_multiple_of(256)
        && let Some(&previous_range) = ranges_left
            .iter()
            .find(|r| r.end() == new_range.start() - 1)
    {
        let merged_range = previous_range
            .merge(new_range)
            .unwrap_or_else(|| unreachable!());
        ranges_left.remove(&previous_range);
        if single_element {
            // If ranges_right contained a single element initially, we'll need to reuse our
            // new_range to compare it for right-side merge: do not insert it.
            new_range = merged_range;
        } else {
            // If ranges_right has remaining elements, we'll pick the last, we're done with the
            // current merged_range and we can merge it.
            ranges_left.insert(merged_range);
        }
    } else if !single_element {
        // If ranges_right has remaining elements, we'll work with a new one. We're done with the
        // current new_range and we can merge it.
        ranges_left.insert(new_range);
    }

    // If ranges_right contained a single element, keep going with new_range, that we may have
    // merged left but not inserted. If ranges_right still contains elements, we'll now work with
    // the last range in the set.
    if !single_element {
        new_range = ranges_right.pop_last().unwrap_or_else(|| unreachable!());
    }
    // Try to merge new_range right
    if new_range.end() < u16::MAX
        && new_range.end() % 256 == 255
        && let Some(&next_range) = ranges_left
            .iter()
            .find(|r| r.start() == new_range.end() + 1)
    {
        let merged_range = next_range
            .merge(new_range)
            .unwrap_or_else(|| unreachable!());
        ranges_left.remove(&next_range);
        ranges_left.insert(merged_range);
    } else {
        ranges_left.insert(new_range);
    }

    // Extend with remaining ranges
    ranges_left.extend(ranges_right);
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

    fn deallocate_port_from_bitmap(&mut self, port_in_block: u8) -> Result<(), ()> {
        self.set_bitmap_value(port_in_block, 0)
    }

    fn reserve_port_from_bitmap(&mut self, port_in_block: u8) -> Result<(), ()> {
        self.set_bitmap_value(port_in_block, 1)
    }

    fn set_half_bitmap_range(
        half: &mut u128,
        start_offset: u8,
        end_offset: u8,
        value: u128,
    ) -> Result<(), ()> {
        if start_offset > 127 || end_offset > 127 || start_offset > end_offset {
            return Err(());
        }
        let mask = if end_offset - start_offset == 127 {
            u128::MAX
        } else {
            ((1u128 << (end_offset - start_offset + 1)) - 1) << start_offset
        };
        match value {
            0 => {
                *half &= !mask;
            }
            1 => {
                *half |= mask;
            }
            _ => return Err(()),
        }
        Ok(())
    }

    fn set_bitmap_range(
        &mut self,
        start_offset: u8,
        end_offset: u8,
        value: u128,
    ) -> Result<(), ()> {
        if start_offset < 128 {
            Self::set_half_bitmap_range(
                &mut self.first_half,
                start_offset,
                end_offset.min(127),
                value,
            )?;
        }
        if end_offset >= 128 {
            Self::set_half_bitmap_range(
                &mut self.second_half,
                start_offset.max(128) - 128,
                end_offset - 128,
                value,
            )?;
        }
        Ok(())
    }

    fn reserve_port_range_from_bitmap(&mut self, range: PortRange) -> Result<(), ()> {
        let start = u8::try_from(range.start() % 256).unwrap_or_else(|_| unreachable!());
        let end = u8::try_from(range.end() % 256).unwrap_or_else(|_| unreachable!());
        self.set_bitmap_range(start, end, 1)?;
        Ok(())
    }

    // Used for Display
    fn allocated_port_ranges(&self) -> BTreeSet<PortRange> {
        let mut ranges_first_half = collect_ranges_from_u128_bitmap(self.first_half, 0);
        let mut ranges_second_half = collect_ranges_from_u128_bitmap(self.second_half, 128);

        // Merge consecutive ranges from both halves if they are adjacent
        let merged_range = if let Some(range_left) = ranges_first_half.last()
            && let Some(range_right) = ranges_second_half.first()
            && range_left.end() + 1 == range_right.start()
        {
            Some(
                PortRange::new(range_left.start(), range_right.end())
                    .unwrap_or_else(|_| unreachable!()),
            )
        } else {
            None
        };
        if let Some(range) = merged_range {
            // Merge the two ranges
            ranges_first_half.pop_last();
            ranges_second_half.pop_first();
            ranges_first_half.insert(range);
        }

        ranges_first_half.extend(ranges_second_half);
        ranges_first_half
    }
}

fn collect_ranges_from_u128_bitmap(bitmap: u128, base: u16) -> BTreeSet<PortRange> {
    let mut ranges = BTreeSet::new();
    let mut start_range: Option<u16> = None;
    let mut last_offset: Option<u16> = None;
    for offset in 0..128 {
        if bitmap & (1 << offset) == 0 {
            // Port not allocated
            continue;
        }
        match (start_range, last_offset) {
            (None, _) => {
                start_range = Some(offset);
                last_offset = Some(offset);
            }
            (Some(start), Some(last)) => {
                if offset == last + 1 {
                    // New offset in the range, just bump last offset
                    last_offset = Some(offset);
                } else {
                    // Insert previous range, and start a new one
                    ranges.insert(
                        PortRange::new(start + base, last + base)
                            .unwrap_or_else(|_| unreachable!()),
                    );
                    start_range = Some(offset);
                    last_offset = Some(offset);
                }
            }
            _ => unreachable!(),
        }
    }
    // Insert last range found, if any range was found
    if let (Some(start), Some(last)) = (start_range, last_offset) {
        ranges.insert(PortRange::new(start + base, last + base).unwrap_or_else(|_| unreachable!()));
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm::prefix::PortRange;
    use std::net::Ipv4Addr;

    // set_half_bitmap_range()

    #[test]
    fn set_half_bitmap_range_single_bit() {
        let mut half = 0u128;
        Bitmap256::set_half_bitmap_range(&mut half, 0, 0, 1).unwrap();
        assert_eq!(half, 1);
    }

    #[test]
    fn set_half_bitmap_range_first_few_bits() {
        let mut half = 0u128;
        Bitmap256::set_half_bitmap_range(&mut half, 0, 3, 1).unwrap();
        assert_eq!(half, 0b1111);
    }

    #[test]
    fn set_half_bitmap_range_middle_bits() {
        let mut half = 0u128;
        Bitmap256::set_half_bitmap_range(&mut half, 4, 7, 1).unwrap();
        assert_eq!(half, 0b1111_0000);
    }

    #[test]
    fn set_half_bitmap_range_full_range() {
        let mut half = 0u128;
        Bitmap256::set_half_bitmap_range(&mut half, 0, 127, 1).unwrap();
        assert_eq!(half, u128::MAX);
    }

    #[test]
    fn set_half_bitmap_range_clear_bits() {
        let mut half = u128::MAX;
        Bitmap256::set_half_bitmap_range(&mut half, 4, 7, 0).unwrap();
        assert_eq!(half, !0b1111_0000);
    }

    #[test]
    fn set_half_bitmap_range_invalid_start_gt_end() {
        let mut half = 0u128;
        assert!(Bitmap256::set_half_bitmap_range(&mut half, 5, 3, 1).is_err());
    }

    #[test]
    fn set_half_bitmap_range_invalid_start_too_large() {
        let mut half = 0u128;
        assert!(Bitmap256::set_half_bitmap_range(&mut half, 128, 128, 1).is_err());
    }

    #[test]
    fn set_half_bitmap_range_invalid_end_too_large() {
        let mut half = 0u128;
        assert!(Bitmap256::set_half_bitmap_range(&mut half, 0, 128, 1).is_err());
    }

    #[test]
    fn set_half_bitmap_range_invalid_value() {
        let mut half = 0u128;
        assert!(Bitmap256::set_half_bitmap_range(&mut half, 0, 3, 2).is_err());
    }

    #[test]
    fn set_half_bitmap_range_high_bits() {
        let mut half = 0u128;
        Bitmap256::set_half_bitmap_range(&mut half, 120, 127, 1).unwrap();
        let expected = ((1u128 << 8) - 1) << 120;
        assert_eq!(half, expected);
    }

    // set_bitmap_range()

    #[test]
    fn set_bitmap_range_first_half_only() {
        let mut bitmap = Bitmap256::new();
        bitmap.set_bitmap_range(10, 20, 1).unwrap();
        let expected = ((1u128 << 11) - 1) << 10;
        assert_eq!(bitmap.first_half, expected);
        assert_eq!(bitmap.second_half, 0);
    }

    #[test]
    fn set_bitmap_range_second_half_only() {
        let mut bitmap = Bitmap256::new();
        bitmap.set_bitmap_range(130, 140, 1).unwrap();
        let expected = ((1u128 << 11) - 1) << 2; // 130-128=2
        assert_eq!(bitmap.first_half, 0);
        assert_eq!(bitmap.second_half, expected);
    }

    #[test]
    fn set_bitmap_range_spans_both_halves() {
        let mut bitmap = Bitmap256::new();
        bitmap.set_bitmap_range(120, 135, 1).unwrap();
        // First half: bits 120..=127
        let first_expected = ((1u128 << 8) - 1) << 120;
        // Second half: bits 0..=7 (135-128=7)
        let second_expected = (1u128 << 8) - 1;
        assert_eq!(bitmap.first_half, first_expected);
        assert_eq!(bitmap.second_half, second_expected);
    }

    #[test]
    fn set_bitmap_range_full_range() {
        let mut bitmap = Bitmap256::new();
        bitmap.set_bitmap_range(0, 255, 1).unwrap();
        assert_eq!(bitmap.first_half, u128::MAX);
        assert_eq!(bitmap.second_half, u128::MAX);
    }

    #[test]
    fn set_bitmap_range_clear_spanning() {
        let mut bitmap = Bitmap256::new();
        bitmap.first_half = u128::MAX;
        bitmap.second_half = u128::MAX;
        bitmap.set_bitmap_range(120, 135, 0).unwrap();
        let first_expected = !(((1u128 << 8) - 1) << 120);
        let second_expected = !((1u128 << 8) - 1);
        assert_eq!(bitmap.first_half, first_expected);
        assert_eq!(bitmap.second_half, second_expected);
    }

    #[test]
    fn set_bitmap_range_at_boundary_128() {
        let mut bitmap = Bitmap256::new();
        bitmap.set_bitmap_range(127, 128, 1).unwrap();
        assert_eq!(bitmap.first_half, 1u128 << 127);
        assert_eq!(bitmap.second_half, 1u128);
    }

    // reserve_port_range_from_bitmap()

    #[test]
    fn reserve_port_range_marks_bits() {
        let mut bitmap = Bitmap256::new();
        let range = PortRange::new(10, 19).unwrap();
        bitmap.reserve_port_range_from_bitmap(range).unwrap();
        let expected = ((1u128 << 10) - 1) << 10;
        assert_eq!(bitmap.first_half, expected);
    }

    #[test]
    fn reserve_port_range_prevents_allocation() {
        let mut bitmap = Bitmap256::new();
        // Reserve ports 0..=9
        let range = PortRange::new(0, 9).unwrap();
        bitmap.reserve_port_range_from_bitmap(range).unwrap();
        // First allocation should skip reserved ports and return 10
        let port = bitmap.allocate_port_from_bitmap().unwrap();
        assert_eq!(port, 10);
    }

    // pick_available_block()

    #[test]
    fn pick_available_block_no_reserved_range() {
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(None);
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 0);
        assert_eq!(base_port, 0);
    }

    #[test]
    fn pick_available_block_reserved_range_covers_first_block() {
        // Reserve 0..=255 (entire first block) → should skip to block 1 (ports 256-511)
        let reserved = PortRange::new(0, 255).unwrap();
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(Some(reserved));
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 1);
        assert_eq!(base_port, 256);
    }

    #[test]
    fn pick_available_block_reserved_range_starting_at_one() {
        // Corner case: reserved 1..=255 does not literally cover 0..=255, but port 0 cannot
        // be allocated anyway, so the block is effectively unusable. The code adjusts the
        // reserved range to start at 0, causing the block to be skipped.
        let reserved = PortRange::new(1, 255).unwrap();
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(Some(reserved));
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 1);
        assert_eq!(base_port, 256);
    }

    #[test]
    fn pick_available_block_reserved_range_covers_multiple_blocks() {
        // Reserve 0..=511 (first two blocks) → should skip to block 2 (ports 512-767)
        let reserved = PortRange::new(0, 511).unwrap();
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(Some(reserved));
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 2);
        assert_eq!(base_port, 512);
    }

    #[test]
    fn pick_available_block_reserved_range_does_not_cover_other_blocks() {
        // Reserve 0..=255 only covers block 0, block 1 is unaffected
        let reserved = PortRange::new(0, 255).unwrap();
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(Some(reserved));
        // First pick skips block 0, gets block 1
        let (_, base_port1) = allocator.pick_available_block().unwrap();
        assert_eq!(base_port1, 256);
        // Second pick gets block 2
        let (_, base_port2) = allocator.pick_available_block().unwrap();
        assert_eq!(base_port2, 512);
    }

    #[test]
    fn pick_available_block_partial_reserved_range_does_not_skip() {
        // Reserve 1..=200 (len 200 < 255) → block is NOT skipped entirely, individual ports
        // are reserved within the block instead
        let reserved = PortRange::new(1, 200).unwrap();
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(Some(reserved));
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 0);
        assert_eq!(base_port, 0);
    }

    #[test]
    fn pick_available_block_reserved_middle_block() {
        // Reserve 256..=511 (block 1 only) → block 0 is fine, block 1 is skipped
        let reserved = PortRange::new(256, 511).unwrap();
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(Some(reserved));
        // First pick: block 0
        let (_, base_port1) = allocator.pick_available_block().unwrap();
        assert_eq!(base_port1, 0);
        // Second pick: block 1 is skipped, picks block 2
        let (_, base_port2) = allocator.pick_available_block().unwrap();
        assert_eq!(base_port2, 512);
    }

    #[test]
    fn pick_available_block_all_blocks_reserved() {
        // Reserve 0..=65535 (all blocks) → NoPortBlock error
        let reserved = PortRange::new(0, 65535).unwrap();
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(Some(reserved));
        assert!(allocator.pick_available_block().is_err());
    }

    fn port_range(start: u16, end: u16) -> PortRange {
        PortRange::new(start, end).unwrap()
    }

    #[test]
    fn merge_ranges_right_is_empty() {
        let mut ranges_left = BTreeSet::from([port_range(1, 255)]);
        let ranges_right = BTreeSet::<PortRange>::new();
        merge_ranges(&mut ranges_left, ranges_right);
        assert_eq!(ranges_left, BTreeSet::from([port_range(1, 255)]));
    }

    #[test]
    fn merge_ranges_right_single_elem_no_adjacent() {
        let mut ranges_left = BTreeSet::from([port_range(1, 255)]);
        let ranges_right = BTreeSet::from([port_range(300, 315)]);
        merge_ranges(&mut ranges_left, ranges_right);
        assert_eq!(
            ranges_left,
            BTreeSet::from([port_range(1, 255), port_range(300, 315)])
        );
    }

    #[test]
    fn merge_ranges_right_single_elem_adjacent_left() {
        let mut ranges_left = BTreeSet::from([port_range(1, 255), port_range(512, 700)]);
        let ranges_right = BTreeSet::from([port_range(256, 300)]);
        merge_ranges(&mut ranges_left, ranges_right);
        assert_eq!(
            ranges_left,
            BTreeSet::from([port_range(1, 300), port_range(512, 700)])
        );
    }

    #[test]
    fn merge_ranges_right_single_elem_adjacent_right() {
        let mut ranges_left = BTreeSet::from([port_range(1, 255), port_range(512, 700)]);
        let ranges_right = BTreeSet::from([port_range(300, 511)]);
        merge_ranges(&mut ranges_left, ranges_right);
        assert_eq!(
            ranges_left,
            BTreeSet::from([port_range(1, 255), port_range(300, 700)])
        );
    }

    #[test]
    fn merge_ranges_right_two_elem_no_adjacent() {
        let mut ranges_left = BTreeSet::from([port_range(1, 255), port_range(512, 700)]);
        let ranges_right = BTreeSet::from([port_range(300, 310), port_range(400, 400)]);
        merge_ranges(&mut ranges_left, ranges_right);
        assert_eq!(
            ranges_left,
            BTreeSet::from([
                port_range(1, 255),
                port_range(300, 310),
                port_range(400, 400),
                port_range(512, 700)
            ])
        );
    }

    #[test]
    fn merge_ranges_right_two_elem_adjacent_left() {
        let mut ranges_left = BTreeSet::from([port_range(1, 255), port_range(512, 700)]);
        let ranges_right = BTreeSet::from([port_range(256, 300), port_range(400, 450)]);
        merge_ranges(&mut ranges_left, ranges_right);
        assert_eq!(
            ranges_left,
            BTreeSet::from([
                port_range(1, 300),
                port_range(400, 450),
                port_range(512, 700)
            ])
        );
    }

    #[test]
    fn merge_ranges_right_two_elem_adjacent_right() {
        let mut ranges_left = BTreeSet::from([port_range(1, 255), port_range(512, 700)]);
        let ranges_right = BTreeSet::from([port_range(300, 310), port_range(400, 511)]);
        merge_ranges(&mut ranges_left, ranges_right);
        assert_eq!(
            ranges_left,
            BTreeSet::from([
                port_range(1, 255),
                port_range(300, 310),
                port_range(400, 700)
            ])
        );
    }

    #[test]
    fn merge_ranges_right_two_elem_adjacent_both() {
        let mut ranges_left = BTreeSet::from([port_range(1, 255), port_range(512, 700)]);
        let ranges_right = BTreeSet::from([port_range(256, 300), port_range(400, 511)]);
        merge_ranges(&mut ranges_left, ranges_right);
        assert_eq!(
            ranges_left,
            BTreeSet::from([port_range(1, 300), port_range(400, 700)])
        );
    }

    #[test]
    fn merge_ranges_right_four_elem_adjacent_both() {
        let mut ranges_left = BTreeSet::from([port_range(1, 255), port_range(512, 700)]);
        let ranges_right = BTreeSet::from([
            port_range(256, 300),
            port_range(350, 360),
            port_range(375, 375),
            port_range(400, 511),
        ]);
        merge_ranges(&mut ranges_left, ranges_right);
        assert_eq!(
            ranges_left,
            BTreeSet::from([
                port_range(1, 300),
                port_range(350, 360),
                port_range(375, 375),
                port_range(400, 700)
            ])
        );
    }
}
