// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port allocation components for the default allocator for masquerade.
//!
//! This submodule is the logical continuation of the `alloc` submodule, focusing on allocating
//! ports for a given IP address. The entry point is the [`PortAllocator`] struct.
//!
//! See also the architecture diagram at the top of mod.rs.

use super::NatIpWithBitmap;
use super::alloc::AllocatedIp;
use super::reserved::ReservedForAddr;
use crate::masquerade::allocation::AllocatorError;
use crate::port::NatPort;
use concurrency::concurrency_mode;
use concurrency::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize};
use concurrency::sync::{Arc, Mutex, RwLock, Weak};
use concurrency::thread::{self, ThreadId};
use lpm::prefix::PortRange;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;

use tracing::{debug, error};

#[concurrency_mode(std)]
use rand::seq::SliceRandom;
#[concurrency_mode(shuttle)]
use shuttle::rand::{Rng, thread_rng};

/// Bounds retries while a port block changes hands.
const BLOCK_LOOKUP_ATTEMPTS: usize = 4;

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
    reserved: ReservedForAddr,
    exclude_wellknown_ports: bool,
}

//= https://www.rfc-editor.org/rfc/rfc4787#section-4.2.1
//= type=exception
//# a) If the host's source port was in the range 0-1023, it is
//# RECOMMENDED the NAT's source port be in the same range.
//
// Declined, deliberately and unconditionally. `setup.rs` sets `exclude_wellknown_ports` for TCP
// and UDP alike, so an internal host sourcing from a well-known port is always translated to a
// port at or above 1024 and this requirement can never be met.
//
// This is the one requirement in RFC 4787 that is marked `exception` rather than `todo`, because
// unlike the timeout and mapping deviations it was actually decided: the range is named, the
// policy is stated on the constant below, a flag carries it, and tests hold it. Handing a tenant
// a public source port below 1024 would let it originate traffic that peers and middleboxes read
// as a privileged service, which is a worse trade than breaking the NFS-style clients RFC 4787
// cites as the beneficiaries.
//
// The second half of REQ-3a -- a source port in 1024-65535 mapping to that same range -- is held,
// and held by the same line.
/// Ports 0..=1023 cover the IANA system/well-known range and should not be
/// allocated by masquerade NAT for TCP or UDP.
pub(super) const IANA_WELLKNOWN_PORT_LIMIT: u16 = 1024;

impl<I: NatIpWithBitmap> PortAllocator<I> {
    pub(crate) fn new(
        reserved: ReservedForAddr,
        randomize: bool,
        exclude_wellknown_ports: bool,
    ) -> Self {
        let mut base_ports = (0..=255).collect::<Vec<_>>();

        // Shuffle the list of port blocks for the port allocator. This way, we can pick blocks in a
        // "random" order when allocating them, and have ports allocated in a "random" order. The
        // quotes denote that this is not completely random: ports are allocated sequentially within
        // a 256-port block.
        if randomize {
            Self::shuffle_slice(&mut base_ports);
        }
        // Count the blocks left usable rather than deriving the count, so a block excluded by both
        // policies below is not subtracted twice.
        let mut usable_blocks = 0u16;
        let blocks = std::array::from_fn(|i| {
            let block = AllocatorPortBlock::new(base_ports[i]);
            let base_port = block.to_port_number();
            // Pre-mark IANA well-known port blocks (0-1023) as permanently non-free so they are
            // never handed out by masquerade NAT for TCP or UDP. A block whose every port is claimed
            // by port forwarding is likewise never handed out; a partially claimed one stays usable
            // and has the claimed ports pre-set when it is allocated.
            let wellknown = exclude_wellknown_ports && base_port < IANA_WELLKNOWN_PORT_LIMIT;
            let claimed_whole_block =
                Bitmap256::for_block(base_port, reserved.ranges(), false).bitmap_full();
            if wellknown || claimed_whole_block {
                block
                    .free
                    .store(false, concurrency::sync::atomic::Ordering::Relaxed);
            } else {
                usable_blocks += 1;
            }
            block
        });
        Self {
            blocks,
            usable_blocks: AtomicU16::new(usable_blocks),
            current_alloc_index: AtomicUsize::new(0),
            thread_blocks: ThreadPortMap::new(),
            allocated_blocks: AllocatedPortBlockMap::new(),
            reserved,
            exclude_wellknown_ports,
        }
    }

    /// The ports of this address that must never be handed out.
    pub(crate) fn reserved_ports(&self) -> &ReservedForAddr {
        &self.reserved
    }

    #[cfg(test)]
    pub(crate) fn new_no_randomness(exclude_wellknown_ports: bool) -> Self {
        Self::new(ReservedForAddr::default(), false, exclude_wellknown_ports)
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

    #[concurrency_mode(loom)]
    fn shuffle_slice<T>(_slice: &mut [T]) {
        // Deterministic replay matters more than allocation-order randomization.
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

        Ok(AllocatedPortBlock::new(
            ip,
            index,
            base_port_index,
            allow_null,
        ))
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
    ) -> Arc<AllocatedPortBlock<I>> {
        self.usable_blocks
            .fetch_sub(1, concurrency::sync::atomic::Ordering::Relaxed);
        let block = Arc::new(AllocatedPortBlock::new(
            ip,
            index,
            (port.as_u16() / 256) * 256, // port block base index, discard offset within block
            allow_null,
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
        let allow_null = matches!(port, NatPort::Identifier(_));
        for _ in 0..BLOCK_LOOKUP_ATTEMPTS {
            let (block_was_free, index) = self.try_to_reserve_block(port)?;
            if block_was_free {
                return Ok(self.allocate_block_for_reservation(ip, index, port, allow_null));
            }
            if let Some(block) = self.allocated_blocks.search_for_block(port) {
                return Ok(block);
            }
            // The free flag and map entry change separately. Retry between those updates.
            debug!("Block holding port {port} changed mid-lookup; retrying");
            thread::yield_now();
        }
        debug!("Block holding port {port} changed {BLOCK_LOOKUP_ATTEMPTS} times");
        Err(AllocatorError::PortReservationFailed(port.as_u16()))
    }

    pub(crate) fn reserve_port(
        &self,
        ip: Arc<AllocatedIp<I>>,
        port: NatPort,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        // Reject explicit reservations into the IANA system/well-known range up front so callers
        // get a policy-oriented error rather than a misleading resource-exhaustion error from the
        // pre-excluded low-port blocks.
        if self.exclude_wellknown_ports && port.as_u16() < IANA_WELLKNOWN_PORT_LIMIT {
            debug!("Explicit reservation for well-known port {port} denied by allocator policy");
            return Err(AllocatorError::Denied);
        }
        // Same reason, for the ports port forwarding claims. Answering here matters beyond the error
        // being clearer: a block claimed in full is never allocated, so `find_block_for_port` would
        // find it neither free nor in the allocated map, and spend every retry before giving up.
        if self.reserved.contains(port.as_u16()) {
            debug!("Explicit reservation for port-forwarding port {port} denied");
            return Err(AllocatorError::Denied);
        }
        let block = self.find_block_for_port(ip, port)?;
        block.reserve_port_from_block(port)
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
    fn new(ip: Arc<AllocatedIp<I>>, index: usize, base_port_idx: u16, allow_null: bool) -> Self {
        // The claims are taken from the address rather than passed in, so that every path creating a
        // block honours the ports port forwarding may use, whether it allocates or reserves.
        let usage_bitmap =
            Bitmap256::for_block(base_port_idx, ip.reserved_ports().ranges(), !allow_null);
        Self {
            ip,
            base_port_idx,
            index,
            usage_bitmap: Mutex::new(usage_bitmap),
        }
    }

    fn ip(&self) -> I {
        self.ip.ip()
    }

    fn is_full(&self) -> bool {
        self.usage_bitmap.lock().bitmap_full()
    }

    fn covers(&self, port: NatPort) -> bool {
        port.as_u16()
            .checked_sub(self.base_port_idx)
            .is_some_and(|delta| delta < 256)
    }

    fn deallocate_port_from_block(&self, port: NatPort) -> Result<(), AllocatorError> {
        self.usage_bitmap
            .lock()
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
            .map_err(|conflict| {
                AllocatorError::InternalIssue(format!("Failed to deallocate port: {conflict}"))
            })
    }

    fn allocate_port_from_block(
        self: Arc<Self>,
        allow_null: bool,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        let bitmap_offset = self
            .usage_bitmap
            .lock()
            .allocate_port_from_bitmap()
            .ok_or(AllocatorError::NoFreePort(self.base_port_idx))?;

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
            .map_err(|_| AllocatorError::PortReservationFailed(port.as_u16()))?;

        Ok(AllocatedPort::new(port, self.clone()))
    }

    // Used for Display
    fn allocated_port_ranges(&self) -> BTreeSet<PortRange> {
        self.usage_bitmap
            .lock()
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
#[derive(Debug)]
pub struct AllocatedPort<I: NatIpWithBitmap> {
    port: NatPort,                               // the actual allocated value
    block_allocator: Arc<AllocatedPortBlock<I>>, // block/IP the allocated value belongs to
}

impl<I: NatIpWithBitmap> AllocatedPort<I> {
    #[must_use]
    fn new(port: NatPort, block_allocator: Arc<AllocatedPortBlock<I>>) -> Self {
        Self {
            port,
            block_allocator,
        }
    }
    #[must_use]
    pub fn port(&self) -> NatPort {
        self.port
    }
    #[must_use]
    pub fn ip(&self) -> I {
        self.block_allocator.ip()
    }
}

impl<I: NatIpWithBitmap> Drop for AllocatedPort<I> {
    fn drop(&mut self) {
        debug!("Dropping allocated port {self}...");
        // Not panicking on a drop path is right; discarding the answer is not. A port that cannot
        // be given back has either been given back already or was never recorded as taken, and
        // both mean the bitmap no longer says what is in use -- the same accounting whose silence
        // let a pair be handed out twice until the error above was made load-bearing. There is
        // nothing to do about it here, but it should not pass unsaid.
        if let Err(e) = self.block_allocator.deallocate_port_from_block(self.port) {
            error!("Failed to give back {self}: {e}");
        }
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
            .get(&concurrency::thread::current().id())
            .copied()
            .unwrap_or(None)
    }

    fn set(&self, index: Option<usize>) {
        self.0
            .write()
            .insert(concurrency::thread::current().id(), index);
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

impl<I: NatIpWithBitmap> Display for AllocatedPort<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip(), self.port())
    }
}

impl<I: NatIpWithBitmap> AllocatedPortBlockMap<I> {
    fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    fn get_weak(&self, index: usize) -> Option<Weak<AllocatedPortBlock<I>>> {
        self.0.read().get(&index).cloned()
    }

    // A live block may replace the expired entry before this lock is acquired.
    fn remove_if_still_dead(&self, index: usize) {
        let mut blocks = self.0.write();
        if let Some(stored) = blocks.get(&index)
            && stored.upgrade().is_none()
        {
            blocks.remove(&index);
        }
    }

    fn get(&self, index: usize) -> Option<Arc<AllocatedPortBlock<I>>> {
        self.get_weak(index)?.upgrade().or_else(|| {
            self.remove_if_still_dead(index);
            None
        })
    }

    fn insert(&self, index: usize, block: Weak<AllocatedPortBlock<I>>) {
        self.0.write().insert(index, block);
    }

    fn has_entries_with_free_ports(&self) -> bool {
        self.0
            .read()
            .values()
            .any(|block| block.upgrade().is_some_and(|block| !block.is_full()))
    }

    fn search_for_block(&self, port: NatPort) -> Option<Arc<AllocatedPortBlock<I>>> {
        self.0
            .read()
            .values()
            .find_map(|block| block.upgrade().filter(|block| block.covers(port)))
    }

    // Used for Display
    fn allocated_port_ranges(&self) -> BTreeSet<PortRange> {
        let blocks = self.0.read();
        let mut ranges = BTreeSet::<PortRange>::new();
        for block in blocks.values() {
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

/// Why a bit could not be flipped: it already held the value asked for.
///
/// The two directions are different facts, and the callers report them differently -- one is a
/// refusal to hand the same port out twice, the other is a bookkeeping mistake -- so the type
/// says which rather than leaving each caller to infer it from the direction it asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum BitmapConflict {
    #[error("port is already allocated")]
    AlreadyAllocated,
    #[error("port was not allocated")]
    NotAllocated,
}
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

    /// The starting state of the block based at `base_port`: every port `claimed` covers is marked
    /// used before the block is handed out, so it can never be allocated. Port 0 is treated the same
    /// way when it may not be given out.
    ///
    /// A claim is clipped to this block, so one spanning several blocks marks the right ports in each
    /// of them. [`Self::bitmap_full`] then says whether the block has anything left to allocate.
    fn for_block(base_port: u16, claimed: &[PortRange], reserve_null: bool) -> Self {
        debug_assert_eq!(base_port % 256, 0, "not a port block base: {base_port}");
        let mut bitmap = Self::new();
        if reserve_null && base_port == 0 {
            bitmap.first_half |= 1;
        }
        for range in claimed {
            let start = range.start().max(base_port);
            let end = range.end().min(base_port | 0xff);
            if start > end {
                continue;
            }
            // Both offsets fall inside the block, so they fit in a u8.
            let offset = |port: u16| {
                u8::try_from(port - base_port).unwrap_or_else(|_| unreachable!("{port}"))
            };
            bitmap.reserve_offset_range(offset(start), offset(end));
        }
        bitmap
    }

    /// Mark the inclusive offset range `start..=end` of the block used.
    fn reserve_offset_range(&mut self, start: u8, end: u8) {
        debug_assert!(start <= end, "start: {start}, end: {end}");
        if start < 128 {
            self.first_half |= Self::contiguous_bits(start, end.min(127));
        }
        if end >= 128 {
            self.second_half |= Self::contiguous_bits(start.max(128) - 128, end - 128);
        }
    }

    /// Ones in `start..=end`, both offsets within one half.
    fn contiguous_bits(start: u8, end: u8) -> u128 {
        debug_assert!(start <= end && end < 128, "start: {start}, end: {end}");
        let width = u32::from(end - start) + 1;
        // A full half cannot be built by shifting: `1 << 128` overflows.
        let ones = if width >= 128 {
            u128::MAX
        } else {
            (1u128 << width) - 1
        };
        ones << start
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
    //= https://www.rfc-editor.org/rfc/rfc5382#section-8
    //# REQ-7:  A NAT MUST NOT have a "Port assignment" behavior of "Port
    //# overloading" for TCP.
    //
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.2.1
    //# REQ-3:  A NAT MUST NOT have a "Port assignment" behavior of "Port
    //# overloading".
    //
    // Port overloading is handing the same public port to two live flows, and this is the
    // function that would have to do it: every port the allocator returns is claimed by the bit
    // set below, and nothing else marks one used. The citation belongs here rather than on a
    // caller because a caller cannot violate the requirement without going through this.
    //
    // The allocator is protocol-agnostic, so the UDP and TCP requirements are one
    // implementation, and one test discharges both.
    fn allocate_port_from_bitmap(&mut self) -> Option<u16> {
        #[allow(clippy::cast_possible_truncation)] // max value is 128
        let ones = self.first_half.trailing_ones() as u16;
        if ones < 128 {
            self.first_half |= 1 << ones;
            return Some(ones);
        }

        #[allow(clippy::cast_possible_truncation)] // max value is 128
        let ones = self.second_half.trailing_ones() as u16;
        if ones < 128 {
            self.second_half |= 1 << ones;
            return Some(ones + 128);
        }

        // Both halves are full
        None
    }

    /// Mark a port used or free, failing if it is already in that state.
    ///
    /// The error is load-bearing in both directions: it is how reserving a port that has already
    /// been handed out is refused, rather than the pair going to two flows at once, and how giving
    /// back a port that was never taken is reported as the bookkeeping mistake it is. Those are
    /// different things, so [`BitmapConflict`] says which, rather than each caller re-deriving it
    /// from the direction it asked for.
    fn set_bitmap_value(&mut self, port_in_block: u8, used: bool) -> Result<(), BitmapConflict> {
        let (half, bit) = if port_in_block < 128 {
            (&mut self.first_half, port_in_block)
        } else {
            (&mut self.second_half, port_in_block - 128)
        };
        let mask = 1u128 << bit;

        if (*half & mask != 0) == used {
            return Err(if used {
                BitmapConflict::AlreadyAllocated
            } else {
                BitmapConflict::NotAllocated
            });
        }
        if used {
            *half |= mask;
        } else {
            *half &= !mask;
        }
        Ok(())
    }

    fn deallocate_port_from_bitmap(&mut self, port_in_block: u8) -> Result<(), BitmapConflict> {
        self.set_bitmap_value(port_in_block, false)
    }

    fn reserve_port_from_bitmap(&mut self, port_in_block: u8) -> Result<(), BitmapConflict> {
        self.set_bitmap_value(port_in_block, true)
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
    use bolero::{Driver, TypeGenerator};
    use lpm::prefix::PortRange;
    use std::net::Ipv4Addr;

    // set_bitmap_value(), through the two operations built on it

    fn port_is_used(bitmap: &Bitmap256, port: u8) -> bool {
        if port < 128 {
            bitmap.first_half & (1u128 << port) != 0
        } else {
            bitmap.second_half & (1u128 << (port - 128)) != 0
        }
    }

    // A port given back is free again. Blocks outlive the ports drawn from them, so a port that
    // stays marked used is one the block can never hand out again.
    #[test]
    fn a_deallocated_port_becomes_free_again() {
        let mut bitmap = Bitmap256::new();
        for port in [5u8, 200] {
            bitmap.reserve_port_from_bitmap(port).unwrap();
            assert!(
                port_is_used(&bitmap, port),
                "port {port} was not marked used"
            );

            bitmap.deallocate_port_from_bitmap(port).unwrap();
            assert!(
                !port_is_used(&bitmap, port),
                "port {port} is still marked used after being given back"
            );
        }
    }

    // Allocation hands out the lowest free port, so a freed port is the next one out.
    #[test]
    fn a_deallocated_port_is_handed_out_again() {
        let mut bitmap = Bitmap256::new();
        let first = bitmap.allocate_port_from_bitmap().unwrap();
        let second = bitmap.allocate_port_from_bitmap().unwrap();
        assert_eq!((first, second), (0, 1));

        bitmap
            .deallocate_port_from_bitmap(u8::try_from(first).unwrap())
            .unwrap();
        assert_eq!(
            bitmap.allocate_port_from_bitmap().unwrap(),
            first,
            "a freed port was not handed out again"
        );
    }

    // Reserving a port already in use has to fail: that is what tells a flow being carried across
    // a config change that its address and port have been taken, rather than handing the same pair
    // to two flows.
    #[test]
    fn reserving_a_used_port_fails() {
        for port in [0u8, 7, 128, 201] {
            let mut bitmap = Bitmap256::new();
            bitmap.reserve_port_from_bitmap(port).unwrap();
            assert!(
                bitmap.reserve_port_from_bitmap(port).is_err(),
                "reserving port {port} twice was allowed"
            );
        }
    }

    // An allocated nonzero port must also be unavailable for reservation.
    #[test]
    fn reserving_an_allocated_port_fails() {
        let mut bitmap = Bitmap256::new();
        let mut allocated = 0;
        for _ in 0..4 {
            allocated = u8::try_from(bitmap.allocate_port_from_bitmap().unwrap()).unwrap();
        }
        assert_ne!(allocated, 0);
        assert!(
            bitmap.reserve_port_from_bitmap(allocated).is_err(),
            "reserving port {allocated}, which is allocated, was allowed"
        );
    }

    // Giving back a port that is already free is a bookkeeping error, and says so.
    #[test]
    fn deallocating_a_free_port_fails() {
        let mut bitmap = Bitmap256::new();
        assert!(bitmap.deallocate_port_from_bitmap(9).is_err());
    }

    #[test]
    fn pick_available_block_starts_at_zero() {
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(false);
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 0);
        assert_eq!(base_port, 0);
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

    #[test]
    fn exclude_wellknown_ports_first_available_block_is_1024() {
        // With no randomness and IANA exclusion, blocks 0-3 (ports 0-1023) are pre-marked
        // non-free, so the first block handed out should start at port 1024.
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(true);
        let (_, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(base_port, 1024);
    }

    #[test]
    fn exclude_wellknown_ports_all_252_blocks_are_above_1023() {
        // Exactly 252 blocks (256 - 4 IANA blocks) should be allocatable; every one should
        // start at port >= 1024. The 253rd attempt should fail with NoPortBlock.
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(true);
        for _ in 0..252 {
            let (_, base_port) = allocator.pick_available_block().unwrap();
            assert!(
                base_port >= 1024,
                "expected base_port >= 1024, got {base_port}"
            );
        }
        assert!(allocator.pick_available_block().is_err());
    }

    #[test]
    fn exclude_wellknown_ports_disabled_starts_at_port_zero() {
        // Sanity check: without the flag, block 0 (port 0) is returned first.
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(false);
        let (_, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(base_port, 0);
    }

    ///////////////////////////////////////////////////////////////////////////
    // for_block(): ports claimed by port forwarding
    ///////////////////////////////////////////////////////////////////////////

    fn claimed(pairs: &[(u16, u16)]) -> Vec<PortRange> {
        pairs
            .iter()
            .map(|&(start, end)| PortRange::new(start, end).unwrap())
            .collect()
    }

    #[test]
    fn a_claim_outside_the_block_marks_nothing() {
        let bitmap = Bitmap256::for_block(1024, &claimed(&[(300, 400)]), false);
        assert!((0..=255u8).all(|port| !port_is_used(&bitmap, port)));
    }

    #[test]
    fn a_claim_is_clipped_to_the_block() {
        let bitmap = Bitmap256::for_block(1024, &claimed(&[(1000, 1100)]), false);
        assert!(!bitmap.bitmap_full());
        assert!(port_is_used(&bitmap, 0), "port 1024 must be reserved");
        assert!(port_is_used(&bitmap, 76), "port 1100 must be reserved");
        assert!(!port_is_used(&bitmap, 77), "port 1101 must be free");
    }

    #[test]
    fn a_claim_spanning_both_halves_marks_both() {
        // Ports 1100-1200 are offsets 76-176 of the block based at 1024, crossing the boundary
        // between the two halves the bitmap is stored in.
        let bitmap = Bitmap256::for_block(1024, &claimed(&[(1100, 1200)]), false);
        assert!(port_is_used(&bitmap, 127), "port 1151 must be reserved");
        assert!(port_is_used(&bitmap, 128), "port 1152 must be reserved");
        assert!(!port_is_used(&bitmap, 177), "port 1201 must be free");
        assert!(!port_is_used(&bitmap, 255), "port 1279 must be free");
    }

    #[test]
    fn a_claim_running_past_the_block_marks_its_tail() {
        let bitmap = Bitmap256::for_block(1024, &claimed(&[(1100, 1300)]), false);
        assert!(port_is_used(&bitmap, 76), "port 1100 must be reserved");
        assert!(port_is_used(&bitmap, 255), "port 1279 must be reserved");
        assert!(!port_is_used(&bitmap, 75), "port 1099 must be free");
    }

    // A block with nothing left to allocate, which is how `PortAllocator::new` recognises the blocks
    // it must never hand out.
    #[test]
    fn a_claim_over_a_whole_block_fills_it() {
        assert!(
            Bitmap256::for_block(1024, &claimed(&[(1024, 1279)]), false).bitmap_full(),
            "an exact claim must fill the block"
        );
        // And so must a claim spanning it, without leaking into its neighbours.
        let wide = claimed(&[(1000, 2000)]);
        assert!(Bitmap256::for_block(1024, &wide, false).bitmap_full());
        assert!(Bitmap256::for_block(1280, &wide, false).bitmap_full());
        assert!(!Bitmap256::for_block(2048, &wide, false).bitmap_full());
    }

    #[test]
    fn disjoint_claims_accumulate_in_one_block() {
        let bitmap = Bitmap256::for_block(1024, &claimed(&[(1024, 1024), (1279, 1279)]), false);
        assert!(port_is_used(&bitmap, 0));
        assert!(port_is_used(&bitmap, 255));
        assert!(!port_is_used(&bitmap, 128));
    }

    #[test]
    fn port_zero_is_reserved_in_the_first_block_alone() {
        assert!(port_is_used(&Bitmap256::for_block(0, &[], true), 0));
        assert!(!port_is_used(&Bitmap256::for_block(0, &[], false), 0));
        // Offset 0 of any other block is a legitimate port.
        assert!(!port_is_used(&Bitmap256::for_block(256, &[], true), 0));
    }

    /// A block base and a handful of claims around it.
    #[derive(Debug, Clone)]
    struct Claims {
        base_port: u16,
        ranges: Vec<(u16, u16)>,
    }

    impl TypeGenerator for Claims {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let base_port = u16::from(driver.produce::<u8>()?) * 256;
            let count = usize::from(driver.produce::<u8>()? % 4);
            let mut ranges = Vec::with_capacity(count);
            for _ in 0..count {
                // Draw around the block so claims land inside it, across its edges, and outside.
                let start = base_port.saturating_sub(300).saturating_add(
                    u16::from(driver.produce::<u8>()?) * 4 + u16::from(driver.produce::<u8>()? % 4),
                );
                let end = start.saturating_add(u16::from(driver.produce::<u8>()?) * 3);
                ranges.push((start, end));
            }
            Some(Self { base_port, ranges })
        }
    }

    #[test]
    fn a_block_holds_exactly_the_claimed_ports_of_its_block() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|claims: Claims| {
                let ranges = claimed(&claims.ranges);
                let bitmap = Bitmap256::for_block(claims.base_port, &ranges, false);
                // The claimed set, restricted to this block, port by port.
                let is_claimed = |port: u16| {
                    ranges
                        .iter()
                        .any(|range| range.start() <= port && port <= range.end())
                };

                for offset in 0..=255u8 {
                    let port = claims.base_port + u16::from(offset);
                    assert_eq!(
                        port_is_used(&bitmap, offset),
                        is_claimed(port),
                        "port {port} (offset {offset} of block {})",
                        claims.base_port
                    );
                }
                assert_eq!(
                    bitmap.bitmap_full(),
                    (0..=255u8).all(|offset| is_claimed(claims.base_port + u16::from(offset)))
                );
            });
    }
}
