// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Masquerade IP allocation. See the architecture diagram in `mod.rs`.

use super::region::AddrInterval;
use super::reserved::{ReservedForAddr, ReservedPorts};
use super::{NatIpWithBitmap, port_alloc};
use crate::masquerade::allocation::AllocatorError;
use crate::masquerade::natip::NatIp;
use crate::port::NatPort;
use crate::ranges::IpRange;
use concurrency::sync::{Arc, RwLock, RwLockReadGuard, Weak};
use concurrency::thread;
use port_alloc::PortAllocator;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use tracing::{debug, error};

///////////////////////////////////////////////////////////////////////////////
// Tenancy
///////////////////////////////////////////////////////////////////////////////

/// Identifies one lease of one public address, so that a lease which has ended cannot be confused
/// with the lease that replaced it.
///
/// A [`NatPool`] hands an address out at most once per tenancy. The address returns to the pool
/// when its tenancy ends, and ending a tenancy that is no longer the current one does nothing. That
/// is what makes the hand-back safe to perform from either side: an [`AllocatedIp`] releasing
/// itself, or an allocation reclaiming an address whose owner has already gone away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Tenancy(u64);

impl Tenancy {
    /// The tenancy handed to the first lease of any address in a pool.
    const FIRST: Tenancy = Tenancy(0);

    /// The tenancy that follows this one.
    ///
    /// Wrapping is not a correctness concern: distinguishing a lease from its successor only
    /// requires that a `u64` counter not wrap while a single `AllocatedIp` is being dropped.
    fn next(self) -> Tenancy {
        Tenancy(self.0.wrapping_add(1))
    }
}

/// Bounds retries while an address changes hands.
///
/// Mirrors `BLOCK_LOOKUP_ATTEMPTS` in the port allocator, for the same reason: two steps that each
/// read a consistent pool can still straddle a change made between them.
const ADDRESS_LOOKUP_ATTEMPTS: usize = 4;

///////////////////////////////////////////////////////////////////////////////
// IpAllocator
///////////////////////////////////////////////////////////////////////////////

/// Thread-safe allocation of addresses and their ports from a [`NatPool`].
#[derive(Debug, Clone)]
pub(crate) struct IpAllocator<I: NatIpWithBitmap> {
    pool: Arc<RwLock<NatPool<I>>>,
    randomize: bool,
}

impl<I: NatIpWithBitmap> IpAllocator<I> {
    pub(crate) fn new(pool: NatPool<I>, randomize: bool) -> Self {
        Self {
            pool: Arc::new(RwLock::new(pool)),
            randomize,
        }
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, NatPool<I>> {
        self.pool.read()
    }

    fn deallocate_ip(&self, ip: I, tenancy: Tenancy) {
        self.pool.write().deallocate_from_pool(ip, tenancy);
    }

    fn reuse_allocated_ip(
        &self,
        allow_null: bool,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        // Keep upgraded addresses alive until the read guard is gone. Their drop path takes this
        // pool's write lock.
        let mut examined: Vec<Arc<AllocatedIp<I>>> = Vec::new();
        let outcome = {
            let allocated_ips = self.pool.read();
            let mut outcome = Err(AllocatorError::NoFreeIp);
            for ip_weak in allocated_ips.ips_in_use() {
                let Some(ip) = ip_weak.upgrade() else {
                    continue;
                };
                examined.push(ip.clone());
                if !ip.has_free_ports() {
                    continue;
                }
                let addr = ip.ip();
                match ip.allocate_port_for_ip(allow_null) {
                    Ok(port) => {
                        debug!("Allocated port {port}");
                        outcome = Ok(port);
                        break;
                    }
                    // This address is out of space, but another may still have room: keep
                    // scanning. Running out of port blocks is exhaustion just as much as running
                    // out of ports within a block, and ending the scan there would strand every
                    // address behind this one in the list.
                    //
                    // Matching the whole exhaustion class rather than naming the port errors keeps
                    // this honest if that class grows. It cannot swallow `NoFreeIp`, which is also
                    // in the class: allocating a port for an address the caller already holds has
                    // no address to run out of, so the port allocator never returns it.
                    Err(e) if e.is_exhaustion() => {
                        debug!("Address {addr} is out of space: {e}");
                        outcome = Err(e);
                    }
                    // Anything else describes allocator failure, not exhaustion. Report it.
                    Err(e) => {
                        outcome = Err(e);
                        break;
                    }
                }
            }
            outcome
        };
        drop(examined);
        outcome
    }

    fn allocate_new_ip_from_pool(&self) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        let mut allocated_ips = self.pool.write();
        let (offset, new_ip) = allocated_ips.use_new_ip(self.clone(), self.randomize)?;
        let arc_ip = Arc::new(new_ip);
        allocated_ips.add_in_use(offset, &arc_ip);
        debug!("Allocated new ip {}", arc_ip.ip());
        Ok(arc_ip)
    }

    fn allocate_from_new_ip(
        &self,
        allow_null: bool,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        self.allocate_new_ip_from_pool()
            .and_then(|ip| ip.allocate_port_for_ip(allow_null))
    }

    fn cleanup_used_ips(&self) {
        // Release upgraded entries after the pool's write guard. See `reuse_allocated_ip`.
        let mut released = Vec::new();
        {
            let mut allocated_ips = self.pool.write();
            allocated_ips.cleanup(&mut released);
        }
        drop(released);
    }

    pub(crate) fn allocate(
        &self,
        allow_null: bool,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        // Reusing an address and drawing a fresh one each read a pool that is internally
        // consistent, but the decision to move from the first to the second is taken between them,
        // and the pool can change in the gap. Two flows starting at once on a pool whose address
        // does not yet exist is enough: the loser's scan finds nothing, and by the time it draws,
        // the winner holds the only address, so it reports exhaustion for a pool that could serve
        // it. Releases move the state the other way just as easily. Neither step is wrong on its
        // own; the pair just needs to be retried when it straddles a change.
        //
        // Bounded, and never reports success it did not achieve -- if the pool really is empty,
        // every attempt fails the same way and the last reason is returned.
        let mut exhausted = None;
        for _ in 0..ADDRESS_LOOKUP_ATTEMPTS {
            // FIXME: Should we clean up every time??
            self.cleanup_used_ips();

            // Draw a fresh address only when the addresses already in use are exhausted. Other
            // errors describe allocator failure and must be preserved.
            let reuse = match self.reuse_allocated_ip(allow_null) {
                Ok(port) => return Ok(port),
                Err(reuse) if reuse.is_exhaustion() => reuse,
                Err(e) => return Err(e),
            };

            match self.allocate_from_new_ip(allow_null) {
                Ok(port) => return Ok(port),
                Err(drawn) if drawn.is_exhaustion() => {
                    // Drawing reports `NoFreeIp` whenever the bitmap is empty, which for a
                    // single-address pool is always. That answer hides why the addresses already
                    // in use could not serve the request, and the two are not the same operational
                    // problem: an empty bitmap wants more addresses, whereas exhausted port blocks
                    // want the block allocator looked at. So the draw only gets the last word when
                    // it has something to say beyond an empty bitmap.
                    exhausted = Some(if matches!(drawn, AllocatorError::NoFreeIp) {
                        reuse
                    } else {
                        drawn
                    });
                    thread::yield_now();
                }
                Err(drawn) => return Err(drawn),
            }
        }

        debug!("Address lookup changed {ADDRESS_LOOKUP_ATTEMPTS} times");
        Err(exhausted.unwrap_or(AllocatorError::NoFreeIp))
    }

    fn get_allocated_ip(&self, ip: I) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        // Keep upgrades alive past the pool guard. See `cleanup_used_ips`.
        let mut examined = Vec::new();
        let outcome =
            self.pool
                .write()
                .reserve_from_pool(ip, self.clone(), self.randomize, &mut examined);
        drop(examined);
        outcome
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
        let pool = self.pool.read();
        (
            pool.bitmap.0.clone(),
            pool.in_use.iter().map(|entry| entry.ip.clone()).collect(),
        )
    }
}

///////////////////////////////////////////////////////////////////////////////
// PoolSet
///////////////////////////////////////////////////////////////////////////////

/// One region of the public address space, and the allocator that owns it.
#[derive(Debug, Clone)]
pub(crate) struct PoolRegion<I: NatIpWithBitmap> {
    range: AddrInterval,
    allocator: IpAllocator<I>,
}

impl<I: NatIpWithBitmap> PoolRegion<I> {
    pub(crate) fn range(&self) -> AddrInterval {
        self.range
    }

    pub(crate) fn allocator(&self) -> &IpAllocator<I> {
        &self.allocator
    }
}

/// The ordered regions and settings belonging to one expose.
///
/// Shared regions share an allocator, keeping public tuples unique across exposes.
#[derive(Debug, Clone)]
pub(crate) struct PoolSet<I: NatIpWithBitmap> {
    regions: Vec<PoolRegion<I>>,
    idle_timeout: Duration,
}

impl<I: NatIpWithBitmap> PoolSet<I> {
    pub(crate) fn new(idle_timeout: Duration) -> Self {
        Self {
            regions: Vec::new(),
            idle_timeout,
        }
    }

    pub(crate) fn push_region(&mut self, range: AddrInterval, allocator: IpAllocator<I>) {
        self.regions.push(PoolRegion { range, allocator });
    }

    pub(crate) fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub(crate) fn regions(&self) -> impl Iterator<Item = &PoolRegion<I>> {
        self.regions.iter()
    }

    /// Allocate from the first region with room, preserving non-exhaustion errors.
    pub(crate) fn allocate(
        &self,
        allow_null: bool,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        let mut exhausted = None;
        for region in &self.regions {
            match region.allocator.allocate(allow_null) {
                Ok(port) => return Ok(port),
                Err(e) if e.is_exhaustion() => {
                    debug!("Region {:?} is out of space: {e}", region.range);
                    exhausted = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(exhausted.unwrap_or(AllocatorError::NoFreeIp))
    }

    /// Reserve a specific address and port, which has to come from the region owning that address.
    pub(crate) fn reserve(
        &self,
        ip: I,
        port: NatPort,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        let bits = ip.to_addr_bits();
        let region = self
            .regions
            .iter()
            .find(|region| region.range.contains(bits))
            .ok_or(AllocatorError::NoPoolFound)?;
        region.allocator.reserve(ip, port)
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
    /// The lease this address was handed out under. Returned to the pool on drop so the pool can
    /// tell a stale hand-back from a live one.
    tenancy: Tenancy,
    port_allocator: port_alloc::PortAllocator<I>,
    ip_allocator: IpAllocator<I>,
}

impl<I: NatIpWithBitmap> AllocatedIp<I> {
    fn new(
        ip: I,
        ip_allocator: IpAllocator<I>,
        reserved: ReservedForAddr,
        randomize: bool,
        exclude_wellknown_ports: bool,
        tenancy: Tenancy,
    ) -> Self {
        let port_allocator = PortAllocator::new(reserved, randomize, exclude_wellknown_ports);
        Self {
            ip,
            tenancy,
            port_allocator,
            ip_allocator,
        }
    }

    pub(crate) fn ip(&self) -> I {
        self.ip
    }

    /// The ports of this address that masquerade may not hand out.
    ///
    /// A port block reads this off the address it belongs to when it is created, so every path that
    /// creates one honours the reservations without having to be told about them.
    pub(crate) fn reserved_ports(&self) -> &ReservedForAddr {
        self.port_allocator.reserved_ports()
    }

    fn tenancy(&self) -> Tenancy {
        self.tenancy
    }

    // Used for Display; should probably not be accessed directly anywhere else
    pub(crate) fn port_allocator(&self) -> &port_alloc::PortAllocator<I> {
        &self.port_allocator
    }

    fn has_free_ports(&self) -> bool {
        self.port_allocator.has_free_ports()
    }

    pub(crate) fn deallocate_block_for_ip(&self, index: usize) {
        self.port_allocator.deallocate_block(index);
    }

    fn allocate_port_for_ip(
        self: Arc<Self>,
        allow_null: bool,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        let alloc_port = self
            .port_allocator
            .allocate_port(self.clone(), allow_null)?;

        debug!(
            "Allocated port {} for ip {}",
            alloc_port.port().as_u16(),
            alloc_port.ip()
        );
        Ok(alloc_port)
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
        self.ip_allocator.deallocate_ip(self.ip, self.tenancy);
    }
}

///////////////////////////////////////////////////////////////////////////////
// NatPool
///////////////////////////////////////////////////////////////////////////////

/// One address this pool has handed out, and the lease it was handed out under.
///
/// The weak reference alone cannot answer "is this address available?". It stops resolving the
/// moment the last [`AllocatedPort`](port_alloc::AllocatedPort) goes away, which is *before*
/// `AllocatedIp::drop` runs and returns the address to the bitmap. Recording the offset and the
/// tenancy next to the weak reference lets whoever notices first finish the hand-back, so the
/// address is never absent from both the bitmap and this list.
#[derive(Debug)]
struct InUseEntry<I: NatIpWithBitmap> {
    offset: u32,
    tenancy: Tenancy,
    ip: Weak<AllocatedIp<I>>,
}

/// A [`NatPool`] is a pool of IP addresses that can be allocated from. It contains a bitmap of
/// available IP addresses, and a list of weak references to [`AllocatedIp`] objects representing
/// the allocated IPs potentially available for use (if they still have free ports)
///
/// # Invariant
///
/// Every address of the pool is either free in `bitmap` or has a current tenancy in `tenancies`,
/// never both and never neither. `tenancies` is what makes that invariant maintainable: it is
/// updated in the same critical section as `bitmap`, whereas the liveness of an `AllocatedIp`
/// changes on whatever thread happens to drop the last reference to it.
#[derive(Debug)]
pub(crate) struct NatPool<I: NatIpWithBitmap> {
    bitmap: PoolBitmap,
    bitmap_mapping: BTreeMap<u32, u128>,
    reverse_bitmap_mapping: BTreeMap<u128, u32>,
    in_use: VecDeque<InUseEntry<I>>,
    /// The public tuples of this region that port forwarding may claim. Applied to every address as
    /// it is put to use, so masquerade never hands one of them out.
    reserved: ReservedPorts,
    /// The current tenancy of every address not free in `bitmap`. An address is removed from here
    /// exactly when it returns to the bitmap.
    tenancies: BTreeMap<u32, Tenancy>,
    /// The tenancy the next lease of any address in this pool will be handed.
    next_tenancy: Tenancy,
    exclude_wellknown_ports: bool,
}

impl<I: NatIpWithBitmap> NatPool<I> {
    /// Build a pool over one disjoint public region.
    pub(crate) fn for_range(
        range: AddrInterval,
        reserved: ReservedPorts,
        exclude_wellknown_ports: bool,
    ) -> Self {
        // IPv6 uses offsets from the region start because its addresses do not fit in the bitmap.
        let bitmap_mapping = BTreeMap::from([(0u32, range.start)]);
        let reverse_bitmap_mapping = BTreeMap::from([(range.start, 0u32)]);

        // A region holding more addresses than the u32 bitmap can index is truncated. We would run
        // out of memory long before allocating four billion addresses.
        let span = range.len().saturating_sub(1).min(u128::from(u32::MAX));
        let to_offset = |bits: u128| {
            let address = I::try_from_bits(bits).unwrap_or_else(|()| unreachable!());
            I::try_to_offset(address, &reverse_bitmap_mapping).unwrap_or_else(|_| unreachable!())
        };

        Self {
            bitmap: PoolBitmap::with_offset_range(
                to_offset(range.start),
                to_offset(range.start + span),
            ),
            bitmap_mapping,
            reverse_bitmap_mapping,
            in_use: VecDeque::new(),
            reserved,
            tenancies: BTreeMap::new(),
            next_tenancy: Tenancy::FIRST,
            exclude_wellknown_ports,
        }
    }

    /// Take the address at `offset` out of the bitmap and record the lease it is handed out under.
    ///
    /// Overwriting an existing tenancy is deliberate: it retires the previous lease, so that
    /// lease's eventual hand-back becomes a no-op rather than freeing an address this pool has
    /// already re-issued.
    fn begin_tenancy(&mut self, offset: u32) -> Tenancy {
        let tenancy = self.next_tenancy;
        self.next_tenancy = tenancy.next();
        self.bitmap.set_ip_allocated(offset);
        self.tenancies.insert(offset, tenancy);
        tenancy
    }

    /// Return the address at `offset` to the bitmap, but only if `tenancy` is still its current
    /// lease.
    ///
    /// Returns whether the hand-back happened. A `false` answer means some other caller already
    /// completed it, or the pool has since re-issued the address; neither is an error, and both
    /// must leave the bitmap alone.
    fn end_tenancy(&mut self, offset: u32, tenancy: Tenancy) -> bool {
        if self.tenancies.get(&offset) != Some(&tenancy) {
            return false;
        }
        self.tenancies.remove(&offset);
        self.bitmap.set_ip_free(offset);
        true
    }

    // Reach the tenancy bookkeeping directly from tests. The states worth asserting on -- a lease
    // retired while its owner's `Drop` is still in flight -- need two threads to reach for real,
    // so the invariant is pinned on the pool instead of raced for.
    #[cfg(test)]
    pub(crate) fn begin_tenancy_for_tests(&mut self, offset: u32) -> Tenancy {
        self.begin_tenancy(offset)
    }

    #[cfg(test)]
    pub(crate) fn end_tenancy_for_tests(&mut self, offset: u32, tenancy: Tenancy) -> bool {
        self.end_tenancy(offset, tenancy)
    }

    #[cfg(test)]
    pub(crate) fn bitmap_contains_for_tests(&self, offset: u32) -> bool {
        self.bitmap.0.contains(offset)
    }

    /// Plant an entry whose address is already gone, so the reclaim path can be driven without a
    /// second thread. `Weak::new()` never upgrades and reports a strong count of zero, which is
    /// exactly the state a released address is in before its `Drop` reaches this pool.
    #[cfg(test)]
    pub(crate) fn plant_dead_entry_for_tests(&mut self, offset: u32, tenancy: Tenancy) {
        self.in_use.push_back(InUseEntry {
            offset,
            tenancy,
            ip: Weak::new(),
        });
    }

    #[cfg(test)]
    pub(crate) fn reclaim_ended_tenancies_for_tests(&mut self) {
        self.reclaim_ended_tenancies();
    }

    #[cfg(test)]
    pub(crate) fn in_use_len_for_tests(&self) -> usize {
        self.in_use.len()
    }

    /// The lease currently held on the address at `offset`, if any.
    ///
    /// Together with the bitmap this is the whole of the pool's opinion about an address, which is
    /// what lets a test assert the partition the allocator is supposed to maintain.
    #[cfg(test)]
    pub(crate) fn current_tenancy_for_tests(&self, offset: u32) -> Option<Tenancy> {
        self.tenancies.get(&offset).copied()
    }

    /// Finish the hand-back of every address whose `AllocatedIp` is gone, dropping their entries.
    ///
    /// This is the other half of the [`InUseEntry`] contract: the thread that dropped the last
    /// reference may still be waiting for this pool's lock, so any caller that holds the lock and
    /// sees a dead weak reference completes the hand-back on its behalf.
    ///
    /// Deliberately not shared with [`NatPool::cleanup`], which it otherwise resembles. `cleanup`
    /// upgrades each entry and hands the resulting `Arc`s to its caller to drop after the guard is
    /// released; this runs with the write lock held and must never mint an `Arc` at all, because
    /// the one it minted could be the last and `AllocatedIp::drop` takes that same lock. Reading
    /// `strong_count` answers the liveness question without that hazard.
    fn reclaim_ended_tenancies(&mut self) {
        let mut ended = Vec::new();
        self.in_use.retain(|entry| {
            if entry.ip.strong_count() > 0 {
                return true;
            }
            ended.push((entry.offset, entry.tenancy));
            false
        });
        for (offset, tenancy) in ended {
            if self.end_tenancy(offset, tenancy) {
                debug!("Reclaimed address at offset {offset} from an ended tenancy");
            }
        }
    }

    fn add_in_use(&mut self, offset: u32, ip: &Arc<AllocatedIp<I>>) {
        self.in_use.push_back(InUseEntry {
            offset,
            tenancy: ip.tenancy(),
            ip: Arc::downgrade(ip),
        });
    }

    /// Drop the entries whose addresses are gone, handing the caller every address that is still
    /// alive so it can release them once the pool lock is no longer held. See `cleanup_used_ips`.
    ///
    /// Dropping an entry also completes that address's hand-back, so pruning the list can never
    /// lose track of an address.
    fn cleanup(&mut self, keep_alive: &mut Vec<Arc<AllocatedIp<I>>>) {
        let mut ended = Vec::new();
        self.in_use.retain(|entry| {
            if let Some(alive) = entry.ip.upgrade() {
                keep_alive.push(alive);
                return true;
            }
            ended.push((entry.offset, entry.tenancy));
            false
        });
        for (offset, tenancy) in ended {
            self.end_tenancy(offset, tenancy);
        }
    }

    pub(crate) fn ips_in_use(&self) -> impl Iterator<Item = &Weak<AllocatedIp<I>>> {
        self.in_use.iter().map(|entry| &entry.ip)
    }

    fn use_new_ip(
        &mut self,
        ip_allocator: IpAllocator<I>,
        randomize: bool,
    ) -> Result<(u32, AllocatedIp<I>), AllocatorError> {
        // Retrieve the first available offset
        let offset = match self.bitmap.pop_ip() {
            Ok(offset) => offset,
            Err(empty) => {
                // The bitmap being empty is not proof the pool is: an address whose last lease
                // ended a moment ago is not in the bitmap yet, and no longer reachable through
                // `in_use` either. Finish those hand-backs -- under the same lock as the retry, so
                // the answer cannot go stale between the two -- before reporting exhaustion.
                self.reclaim_ended_tenancies();
                self.bitmap.pop_ip().map_err(|_| empty)?
            }
        };

        // the ip being allocated
        let ip = I::try_from_offset(offset, &self.bitmap_mapping)?;
        let tenancy = self.begin_tenancy(offset);

        // determine the set of reserved ports that cannot be allocated for this ip
        let reserved = self.reserved.for_addr(ip.to_ip_addr());

        Ok((
            offset,
            AllocatedIp::new(
                ip,
                ip_allocator,
                reserved,
                randomize,
                self.exclude_wellknown_ports,
                tenancy,
            ),
        ))
    }

    fn deallocate_from_pool(&mut self, ip: I, tenancy: Tenancy) {
        debug!("Address {ip} was deallocated");
        // The address was handed out by this pool, so it maps back into it. This runs while an
        // allocation is being dropped and has nowhere to report a failure, so say so and leave the
        // address marked in use rather than panicking on the drop path.
        match I::try_to_offset(ip, &self.reverse_bitmap_mapping) {
            Ok(offset) => {
                if !self.end_tenancy(offset, tenancy) {
                    // An allocation noticed this lease had ended and completed the hand-back
                    // already, possibly re-issuing the address in the process. Freeing it here
                    // would hand the same address to a second `AllocatedIp`.
                    debug!("Address {ip} was already handed back before its lease was dropped");
                }
            }
            Err(e) => error!("Address {ip} does not map back into the pool it came from: {e}"),
        }
    }

    /// `keep_alive` collects every address upgraded here, for the caller to release once the pool
    /// lock is gone. See `cleanup_used_ips`.
    fn reserve_from_pool(
        &mut self,
        ip: I,
        ip_allocator: IpAllocator<I>,
        randomize: bool,
        keep_alive: &mut Vec<Arc<AllocatedIp<I>>>,
    ) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        let offset = I::try_to_offset(ip, &self.reverse_bitmap_mapping)?;

        for ip_weak in self.ips_in_use() {
            let Some(ip_arc) = ip_weak.upgrade() else {
                continue;
            };
            keep_alive.push(ip_arc.clone());
            if ip_arc.ip() == ip {
                // We found the allocated IP in the list of IPs in use, return it
                debug!("Reserved ip {ip_arc}");
                return Ok(ip_arc);
            }
        }

        // Allocate the IP now.
        //
        // The address may still be marked allocated in the bitmap: it was handed out in the past
        // and is no longer in use (it is not in the list of in-use IPs), but the thread dropping
        // the previous `AllocatedIp` has not reached this pool's lock yet. Opening a new tenancy
        // retires that previous lease, so when its drop does arrive it will not free an address
        // this reservation now owns. `begin_tenancy` takes the address out of the bitmap itself.
        let tenancy = self.begin_tenancy(offset);

        // Reservations apply here as well: an address put to use by carrying a live masquerade flow
        // over to a new allocator must not be able to re-take a port that port forwarding claims.
        let arc_ip = Arc::new(AllocatedIp::new(
            ip,
            ip_allocator,
            self.reserved.for_addr(ip.to_ip_addr()),
            randomize,
            self.exclude_wellknown_ports,
            tenancy,
        ));
        self.add_in_use(offset, &arc_ip);
        Ok(arc_ip)
    }

    // Returns a set of IP ranges present in the pool (available for new IP address allocation),
    // based on `self.bitmap`
    //
    // Used for Display
    pub(crate) fn ips_in_bitmap(&self) -> Result<BTreeSet<IpRange>, ()> {
        fn ip_to_bits(ip: IpAddr) -> u128 {
            match ip {
                IpAddr::V4(ip) => u128::from(u32::from(ip)),
                IpAddr::V6(ip) => u128::from(ip),
            }
        }
        let to_addr = |offset: u32| {
            I::try_from_offset(offset, &self.bitmap_mapping)
                .map(|ip| ip.to_ip_addr())
                .map_err(|_| ())
        };

        let mut offset_ranges = BTreeSet::new();
        let mut start_offset: Option<IpAddr> = None;
        let mut last_addr: Option<IpAddr> = None;
        for offset in &self.bitmap.0 {
            match (start_offset, last_addr) {
                (None, _) => {
                    // First bitmap entry, start a new range
                    last_addr = Some(to_addr(offset)?);
                    start_offset = last_addr;
                }
                (Some(start), Some(last)) => {
                    let addr = to_addr(offset)?;
                    if ip_to_bits(addr) == ip_to_bits(last) + 1 {
                        // New offset in the range, just bump last offset
                        last_addr = Some(addr);
                    } else {
                        // Insert previous range, and start a new one
                        offset_ranges.insert(IpRange::new(start, last));
                        last_addr = Some(addr);
                        start_offset = last_addr;
                    }
                }
                _ => unreachable!(),
            }
        }
        if let (Some(start), Some(last)) = (start_offset, last_addr) {
            // Insert last range found
            offset_ranges.insert(IpRange::new(start, last));
        }

        Ok(offset_ranges)
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
    /// Mark every index in the inclusive range as free.
    pub(crate) fn with_offset_range(start: u32, end: u32) -> Self {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert_range(start..=end);
        Self(bitmap)
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
}

///////////////////////////////////////////////////////////////////////////////
// IPv6 <-> u32-offset mapping functions
///////////////////////////////////////////////////////////////////////////////

pub(crate) fn map_offset(
    offset: u32,
    bitmap_mapping: &BTreeMap<u32, u128>,
) -> Result<Ipv6Addr, AllocatorError> {
    // Find the closest mapped prefix and apply the remaining offset.
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
//
// Not every address of a region has an offset. A region may hold more addresses than a u32 can
// index, in which case the bitmap covers only the first 2^32 of them (see `NatPool::for_range`),
// and an address beyond that is simply not one this pool can serve. That is reachable from
// configuration rather than a bug: a flow carried across a config change presents the address it
// already holds, and the region it falls in may have grown downwards underneath it. Report it as
// the pool not serving the address, so the flow is dropped like any other that cannot be carried
// over, rather than panicking in the middle of applying a config.
pub(crate) fn map_address(
    address: Ipv6Addr,
    bitmap_mapping: &BTreeMap<u128, u32>,
) -> Result<u32, AllocatorError> {
    let (prefix_start_bits, prefix_offset) = bitmap_mapping
        .range(..=address.to_bits())
        .next_back()
        .ok_or(AllocatorError::NoPoolFound)?;

    u32::try_from(address.to_bits() - prefix_start_bits)
        .ok()
        .and_then(|offset| prefix_offset.checked_add(offset))
        .ok_or(AllocatorError::NoPoolFound)
}
