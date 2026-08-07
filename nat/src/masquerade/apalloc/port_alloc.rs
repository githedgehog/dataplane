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
use super::reserved::{IANA_WELLKNOWN_PORT_LIMIT, PortClaims};
use crate::masquerade::allocation::AllocatorError;
use crate::port::NatPort;
use concurrency::concurrency_mode;
use concurrency::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize};
use concurrency::sync::{Arc, Mutex, RwLock, Weak};
use concurrency::thread::ThreadId;
use config::GenId;
use lpm::prefix::PortRange;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;

use tracing::{debug, error};

#[concurrency_mode(std)]
use rand::seq::SliceRandom;
#[concurrency_mode(shuttle)]
use shuttle::rand::{Rng, thread_rng};

/// How many times a reservation will look a port's block up before giving up on it.
///
/// A block's flag and its entry in the map of allocated blocks are set apart from one another at
/// both ends of its life, so a lookup landing between them finds it neither free nor allocated and
/// has to start over. Releasing stores the flag `true` and lets the weak entry expire with the
/// `Arc`; claiming takes the flag first and inserts the entry after building the block. Either gap
/// is enough, and the second needs no release at all -- a thread descheduled between the two holds
/// it open for as long as it is parked. This is a bound on livelock, not a number of expected
/// attempts.
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
    reserved_ports: PortClaims,
    exclude_wellknown_ports: bool,
}

impl<I: NatIpWithBitmap> PortAllocator<I> {
    pub(crate) fn new(
        reserved_ports: PortClaims,
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
        let blocks: [AllocatorPortBlock; 256] = std::array::from_fn(|i| {
            let block = AllocatorPortBlock::new(base_ports[i]);
            let base = block.to_port_number();
            // Mark the blocks masquerade can never draw from as permanently non-free: the IANA
            // well-known range (0-1023) for TCP and UDP, and any block port forwarding has claimed
            // in full. Deciding this once, here, is what keeps the count of usable blocks honest:
            // a block ruled out later would be marked non-free without ever being counted out.
            if reserved_ports.block_is_unusable(base, exclude_wellknown_ports) {
                block
                    .free
                    .store(false, concurrency::sync::atomic::Ordering::Relaxed);
            }
            block
        });
        // Counted from the blocks themselves rather than assumed, so the two cannot disagree.
        let usable_blocks = u16::try_from(
            blocks
                .iter()
                .filter(|block| {
                    block
                        .free
                        .load(concurrency::sync::atomic::Ordering::Relaxed)
                })
                .count(),
        )
        .unwrap_or(u16::MAX);
        Self {
            blocks,
            usable_blocks: AtomicU16::new(usable_blocks),
            current_alloc_index: AtomicUsize::new(0),
            thread_blocks: ThreadPortMap::new(),
            allocated_blocks: AllocatedPortBlockMap::new(),
            reserved_ports,
            exclude_wellknown_ports,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_no_randomness(
        reserved_ports: PortClaims,
        exclude_wellknown_ports: bool,
    ) -> Self {
        Self::new(reserved_ports, false, exclude_wellknown_ports)
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
        // TODO: Should we move usable_blocks and blocks into a lock-protected struct?
        //
        // The count is given back before the flag, and the order matters. A claimant subtracts
        // from the count only after winning the flag, so raising the flag first leaves a window in
        // which the count is still short by this block and someone else's subtraction takes it
        // below zero -- on a `u16`, to 65535, which says the address has room it does not have.
        // This way round the count is briefly one too high instead, which only says an address has
        // room a moment before it truly does.
        self.usable_blocks
            .fetch_add(1, concurrency::sync::atomic::Ordering::Relaxed);
        self.blocks[index]
            .free
            .store(true, concurrency::sync::atomic::Ordering::Relaxed);
    }

    fn has_allocated_blocks_with_free_ports(&self) -> bool {
        self.allocated_blocks.has_entries_with_free_ports()
    }

    // Find an available block to allocate ports from, and mark it as non-free.
    //
    // The blocks masquerade may never draw from, the well-known range and those port forwarding
    // has claimed in full, were marked non-free when the allocator was built, so taking the first
    // block whose flag can be claimed is the whole of the decision.
    fn pick_available_block(&self) -> Result<(usize, u16), AllocatorError> {
        // Starting from the current self.current_alloc_index, take the first block for which the
        // atomic compare_exchange succeeds.
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

        // Clip the claims to this block before they reach its bitmap, which indexes ports modulo
        // 256 and cannot represent a range reaching past the block's end.
        let reserved_for_block: Vec<PortRange> =
            self.reserved_ports.within_block(base_port_index).collect();

        // Building the block is the last thing that can fail, and by here its flag is taken and
        // the count is down. Nothing would give either back: no `Arc` exists yet, so no `Drop` is
        // coming, and the block would sit claimed by nobody for the life of the allocator. Only
        // reachable through an `InternalIssue` that should not happen, which is exactly the sort
        // of thing that turns one bad block into a slow leak.
        AllocatedPortBlock::new(ip, index, base_port_index, &reserved_for_block, allow_null)
            .inspect_err(|_| self.deallocate_block(index))
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
        let base_port_index = (port.as_u16() / 256) * 256; // discard the offset within the block
        // A block entering the allocator through a reservation serves later allocations like any
        // other, so it carries the same claims, clipped to it.
        let reserved_for_block: Vec<PortRange> =
            self.reserved_ports.within_block(base_port_index).collect();
        // As in `allocate_block`: the flag is already taken and the count already down, and only
        // a `Drop` gives them back. There is no `Arc` to drop if this fails.
        let block = Arc::new(
            AllocatedPortBlock::new(ip, index, base_port_index, &reserved_for_block, allow_null)
                .inspect_err(|_| self.deallocate_block(index))?,
        );
        self.allocated_blocks
            .insert(block.index, Arc::downgrade(&block));
        Ok(block)
    }

    // Whether the block holding this port is one masquerade may never draw from, and so was marked
    // non-free when the allocator was built without ever having been allocated.
    //
    // Mirrors the condition in `new`, and has to keep mirroring it: a block ruled out there but not
    // recognized here is taken for a live allocation that has gone missing.
    fn block_is_excluded(&self, port: NatPort) -> bool {
        let base = (port.as_u16() / 256) * 256;
        self.reserved_ports
            .block_is_unusable(base, self.exclude_wellknown_ports)
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
                return self.allocate_block_for_reservation(ip, index, port, allow_null);
            }
            if let Some(block) = self.allocated_blocks.search_for_block(port) {
                return Ok(block);
            }
            // A block masquerade may never draw from never joins the list of allocated blocks, so
            // its absence from that list says nothing about the bookkeeping. Port forwarding
            // claiming a block in full is the way to reach this from a configuration: a flow
            // carried across a config change may hold a port in a block the new configuration has
            // claimed.
            //
            // Answer as a claim on part of the same block does, where the block is allocatable and
            // its own bitmap refuses the port. How much of a block an operator happened to claim is
            // not something the caller should be able to tell apart, and it is certainly not the
            // difference between a policy conflict and a broken allocator.
            if self.block_is_excluded(port) {
                debug!("Port {port} lies in a block that port forwarding has claimed in full");
                return Err(AllocatorError::PortReservationFailed(port.as_u16()));
            }
            // Not free, not allocated, not excluded: the block is mid-handover. Either its last
            // holder released it between the flag being read and the map being searched, or
            // another thread has claimed it and not yet published it. Nothing is wrong either
            // way, and starting over is the answer to both -- the next attempt finds the block
            // free if it was released, and in the map once the claimant gets there.
            debug!("Block holding port {port} was released mid-lookup, retrying");
        }
        // Every attempt landed in that window: either this block kept changing hands, or a thread
        // claiming it stayed parked between taking its flag and publishing it. Say the reservation
        // failed rather than claim the bookkeeping is broken -- the caller drops one flow, where
        // `InternalIssue` is read as the allocator being unfit and costs the packet its whole
        // batch.
        debug!("Block holding port {port} was released mid-lookup {BLOCK_LOOKUP_ATTEMPTS} times");
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
        //
        // The range is a port-number convention, so it says nothing about an ICMP identifier,
        // which is drawn from the whole 16 bits. Identifiers cannot meet this today -- ICMP pools
        // are built with the exclusion off -- but that is decided in `setup.rs`, and a reader here
        // would have to go and find it to know a low identifier is not silently denied.
        if self.exclude_wellknown_ports
            && !matches!(port, NatPort::Identifier(_))
            && port.as_u16() < IANA_WELLKNOWN_PORT_LIMIT
        {
            debug!("Explicit reservation for well-known port {port} denied by allocator policy");
            return Err(AllocatorError::Denied);
        }
        let block = self.find_block_for_port(ip, port)?;
        block.reserve_port_from_block(port)
    }

    pub(crate) fn reserved_ports(&self) -> &PortClaims {
        &self.reserved_ports
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
        reserved_ports: &[PortRange],
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
        if reserve_zero || !reserved_ports.is_empty() {
            let mut mutex_guard = block.usage_bitmap.lock();
            if reserve_zero {
                mutex_guard.reserve_port_from_bitmap(0).map_err(|()| {
                    AllocatorError::InternalIssue(
                        "Failed to reserve port 0 from new block".to_string(),
                    )
                })?;
            }
            // Reserving in the bitmap is an OR, so claims that overlap each other, or that
            // overlap port 0 reserved just above, are harmless in any order.
            for claim in reserved_ports {
                mutex_guard
                    .reserve_port_range_from_bitmap(*claim)
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
            .map_err(|()| AllocatorError::InternalIssue("Failed to deallocate port".to_string()))
    }

    fn allocate_port_from_block(
        self: Arc<Self>,
        allow_null: bool,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        let bitmap_offset = self
            .usage_bitmap
            .lock()
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
            .map_err(|()| AllocatorError::PortReservationFailed(port.as_u16()))?;

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
    genid: GenId,                                // the generation id of the allocator (late set)
}

impl<I: NatIpWithBitmap> AllocatedPort<I> {
    #[must_use]
    fn new(port: NatPort, block_allocator: Arc<AllocatedPortBlock<I>>) -> Self {
        Self {
            port,
            block_allocator,
            genid: 0, // initially zero
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
    #[must_use]
    pub fn genid(&self) -> GenId {
        self.genid
    }
    pub fn set_genid(&mut self, genid: GenId) {
        self.genid = genid;
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
        write!(f, "{}:{} (genid: {})", self.ip(), self.port(), self.genid())
    }
}

impl<I: NatIpWithBitmap> AllocatedPortBlockMap<I> {
    fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    fn get_weak(&self, index: usize) -> Option<Weak<AllocatedPortBlock<I>>> {
        self.0.read().get(&index).cloned()
    }

    // Drop the entry at this index, but only if what is there now is still dead.
    //
    // The caller found its own copy of the weak reference expired, under no lock. By the time it
    // gets here another thread may have claimed the freed block and inserted a live reference at
    // the same index, and removing that would orphan a block that is in use: reservations into it
    // would find it neither free nor listed, and its free ports would be invisible to
    // `has_entries_with_free_ports`. Re-checking under the write lock is what makes the removal
    // apply to the entry the caller actually saw. A different *dead* entry is fine to drop; that
    // is the same tidying, one turn later.
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
        // One upgrade, kept. Upgrading to test the block and again to return it let the block die
        // in between, so a block that was there a moment ago read as absent -- which the caller
        // cannot tell from a block that was never listed.
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

    /// Mark a port used or free, failing if it is already in that state.
    ///
    /// The error is load-bearing in both directions: it is how reserving a port that has already
    /// been handed out is refused, rather than the pair going to two flows at once, and how giving
    /// back a port that was never taken is reported as the bookkeeping mistake it is.
    fn set_bitmap_value(&mut self, port_in_block: u8, used: bool) -> Result<(), ()> {
        let (half, bit) = if port_in_block < 128 {
            (&mut self.first_half, port_in_block)
        } else {
            (&mut self.second_half, port_in_block - 128)
        };
        let mask = 1u128 << bit;

        if (*half & mask != 0) == used {
            return Err(());
        }
        if used {
            *half |= mask;
        } else {
            *half &= !mask;
        }
        Ok(())
    }

    fn deallocate_port_from_bitmap(&mut self, port_in_block: u8) -> Result<(), ()> {
        self.set_bitmap_value(port_in_block, false)
    }

    fn reserve_port_from_bitmap(&mut self, port_in_block: u8) -> Result<(), ()> {
        self.set_bitmap_value(port_in_block, true)
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

    // The same, for a port taken by allocation rather than by an earlier reservation. Port 0 is
    // skipped deliberately: it is the one bit position a broken guard still gets right, so testing
    // only the first allocation would pass either way.
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
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(PortClaims::default(), false);
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 0);
        assert_eq!(base_port, 0);
    }

    #[test]
    fn pick_available_block_reserved_range_covers_first_block() {
        // Reserve 0..=255 (entire first block) → should skip to block 1 (ports 256-511)
        let reserved = PortRange::new(0, 255).unwrap();
        let allocator =
            PortAllocator::<Ipv4Addr>::new_no_randomness([reserved].into_iter().collect(), false);
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
        let allocator =
            PortAllocator::<Ipv4Addr>::new_no_randomness([reserved].into_iter().collect(), false);
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 1);
        assert_eq!(base_port, 256);
    }

    #[test]
    fn pick_available_block_reserved_range_covers_multiple_blocks() {
        // Reserve 0..=511 (first two blocks) → should skip to block 2 (ports 512-767)
        let reserved = PortRange::new(0, 511).unwrap();
        let allocator =
            PortAllocator::<Ipv4Addr>::new_no_randomness([reserved].into_iter().collect(), false);
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 2);
        assert_eq!(base_port, 512);
    }

    #[test]
    fn pick_available_block_reserved_range_does_not_cover_other_blocks() {
        // Reserve 0..=255 only covers block 0, block 1 is unaffected
        let reserved = PortRange::new(0, 255).unwrap();
        let allocator =
            PortAllocator::<Ipv4Addr>::new_no_randomness([reserved].into_iter().collect(), false);
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
        let allocator =
            PortAllocator::<Ipv4Addr>::new_no_randomness([reserved].into_iter().collect(), false);
        let (index, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(index, 0);
        assert_eq!(base_port, 0);
    }

    #[test]
    fn pick_available_block_reserved_middle_block() {
        // Reserve 256..=511 (block 1 only) → block 0 is fine, block 1 is skipped
        let reserved = PortRange::new(256, 511).unwrap();
        let allocator =
            PortAllocator::<Ipv4Addr>::new_no_randomness([reserved].into_iter().collect(), false);
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
        let allocator =
            PortAllocator::<Ipv4Addr>::new_no_randomness([reserved].into_iter().collect(), false);
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

    #[test]
    fn exclude_wellknown_ports_first_available_block_is_1024() {
        // With no randomness and IANA exclusion, blocks 0-3 (ports 0-1023) are pre-marked
        // non-free, so the first block handed out should start at port 1024.
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(PortClaims::default(), true);
        let (_, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(base_port, 1024);
    }

    #[test]
    fn exclude_wellknown_ports_all_252_blocks_are_above_1023() {
        // Exactly 252 blocks (256 - 4 IANA blocks) should be allocatable; every one should
        // start at port >= 1024. The 253rd attempt should fail with NoPortBlock.
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(PortClaims::default(), true);
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
        let allocator = PortAllocator::<Ipv4Addr>::new_no_randomness(PortClaims::default(), false);
        let (_, base_port) = allocator.pick_available_block().unwrap();
        assert_eq!(base_port, 0);
    }

    #[test]
    fn exclude_wellknown_ports_combined_with_reserved_range() {
        let reserved = PortRange::new(2048, 2303).unwrap(); // entire block 8
        let allocator =
            PortAllocator::<Ipv4Addr>::new_no_randomness([reserved].into_iter().collect(), true);

        let (_, b0) = allocator.pick_available_block().unwrap();
        assert_eq!(b0, 1024); // block 4

        let (_, b1) = allocator.pick_available_block().unwrap();
        assert_eq!(b1, 1280); // block 5

        let (_, b2) = allocator.pick_available_block().unwrap();
        assert_eq!(b2, 1536); // block 6

        let (_, b3) = allocator.pick_available_block().unwrap();
        assert_eq!(b3, 1792); // block 7

        let (_, b4) = allocator.pick_available_block().unwrap();
        assert_eq!(b4, 2304); // block 9 — block 8 (2048-2303) was skipped
    }
}
