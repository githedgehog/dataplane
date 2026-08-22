// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Masquerade IP allocation. See the architecture diagram in `mod.rs`.

use super::region::AddrInterval;
use super::reserved::{ReservedForAddr, ReservedPorts};
use super::{NatIpWithBitmap, port_alloc};
use crate::masquerade::allocation::AllocatorError;
use crate::port::NatPort;
use crate::ranges::IpRange;
use concurrency::sync::{Arc, RwLock, RwLockReadGuard, Weak};
use net::ip::IpAddress;
use port_alloc::PortAllocator;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv6Addr;
use std::time::Duration;
use tracing::{debug, error};

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

    fn deallocate_ip(&self, ip: I) {
        self.pool.write().deallocate_from_pool(ip);
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
                match ip.allocate_port_for_ip(allow_null) {
                    Ok(port) => {
                        debug!("Allocated port {port}");
                        outcome = Ok(port);
                        break;
                    }
                    // If there is no free port left, loop again to try another IP address
                    Err(AllocatorError::NoFreePort(_)) => {}
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
        let new_ip = allocated_ips.use_new_ip(self.clone(), self.randomize)?;
        let arc_ip = Arc::new(new_ip);
        allocated_ips.add_in_use(&arc_ip);
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
        // FIXME: Should we clean up every time??
        self.cleanup_used_ips();

        //= https://www.rfc-editor.org/rfc/rfc4787#section-4.1
        //= reason=held: reuse before draw is what makes the pooling behaviour "Paired"
        //# REQ-2:  It is RECOMMENDED that a NAT have an "IP address pooling"
        //# behavior of "Paired".
        //
        // These two lines are the whole of REQ-2. Reusing an address already in use before drawing
        // a new one is what makes one internal address keep one public address across all its
        // sessions; drawing first would give the same host a different public address per flow and
        // break peers that negotiate media addresses once.
        //
        // Draw a fresh address only when the addresses already in use are exhausted. Other errors
        // describe allocator failure and must be preserved.
        match self.reuse_allocated_ip(allow_null) {
            Ok(port) => Ok(port),
            Err(e) if e.is_exhaustion() => self.allocate_from_new_ip(allow_null),
            Err(e) => Err(e),
        }
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
        (pool.bitmap.0.clone(), pool.in_use.clone())
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
    ) -> Self {
        let port_allocator = PortAllocator::new(reserved, randomize, exclude_wellknown_ports);
        Self {
            ip,
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
        self.ip_allocator.deallocate_ip(self.ip);
    }
}

///////////////////////////////////////////////////////////////////////////////
// NatPool
///////////////////////////////////////////////////////////////////////////////

/// A [`NatPool`] is a pool of IP addresses that can be allocated from. It contains a bitmap of
/// available IP addresses, and a list of weak references to [`AllocatedIp`] objects representing
/// the allocated IPs potentially available for use (if they still have free ports)
#[derive(Debug)]
pub(crate) struct NatPool<I: NatIpWithBitmap> {
    bitmap: PoolBitmap,
    bitmap_mapping: BTreeMap<u32, u128>,
    reverse_bitmap_mapping: BTreeMap<u128, u32>,
    in_use: VecDeque<Weak<AllocatedIp<I>>>,
    /// The public tuples of this region that port forwarding may claim. Applied to every address as
    /// it is put to use, so masquerade never hands one of them out.
    reserved: ReservedPorts,
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
            let address = I::try_from_bits(bits).unwrap_or_else(|_| unreachable!());
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
            exclude_wellknown_ports,
        }
    }

    fn add_in_use(&mut self, ip: &Arc<AllocatedIp<I>>) {
        self.in_use.push_back(Arc::downgrade(ip));
    }

    /// Drop the entries whose addresses are gone, handing the caller every address that is still
    /// alive so it can release them once the pool lock is no longer held. See `cleanup_used_ips`.
    fn cleanup(&mut self, keep_alive: &mut Vec<Arc<AllocatedIp<I>>>) {
        self.in_use.retain(|ip| match ip.upgrade() {
            Some(alive) => {
                keep_alive.push(alive);
                true
            }
            None => false,
        });
    }

    pub(crate) fn ips_in_use(&self) -> impl Iterator<Item = &Weak<AllocatedIp<I>>> {
        self.in_use.iter()
    }

    fn use_new_ip(
        &mut self,
        ip_allocator: IpAllocator<I>,
        randomize: bool,
    ) -> Result<AllocatedIp<I>, AllocatorError> {
        // Retrieve the first available offset
        let offset = self.bitmap.pop_ip()?;

        // the ip being allocated
        let ip = I::try_from_offset(offset, &self.bitmap_mapping)?;

        // determine the set of reserved ports that cannot be allocated for this ip
        let reserved = self.reserved.for_addr(ip.to_ip_addr());

        Ok(AllocatedIp::new(
            ip,
            ip_allocator,
            reserved,
            randomize,
            self.exclude_wellknown_ports,
        ))
    }

    fn deallocate_from_pool(&mut self, ip: I) {
        debug!("Address {ip} was deallocated");
        // The address was handed out by this pool, so it maps back into it. This runs while an
        // allocation is being dropped and has nowhere to report a failure, so say so and leave the
        // address marked in use rather than panicking on the drop path.
        match I::try_to_offset(ip, &self.reverse_bitmap_mapping) {
            Ok(offset) => {
                self.bitmap.set_ip_free(offset);
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
        // If the IP was already allocated in the bitmap, this is OK: it means that the IP was
        // allocated in the past, it is no longer in used (because it is not in the list of in-use
        // IPs), but we haven't deallocated from the bitmap yet (this happens when another thread
        // drops an AllocatedIp and its reference count goes to 0, but it hasn't called the drop()
        // function to remove the IP from the bitmap in that other thread yet).
        let _ = self.bitmap.set_ip_allocated(offset);

        // Reservations apply here as well: an address put to use by carrying a live masquerade flow
        // over to a new allocator must not be able to re-take a port that port forwarding claims.
        let arc_ip = Arc::new(AllocatedIp::new(
            ip,
            ip_allocator,
            self.reserved.for_addr(ip.to_ip_addr()),
            randomize,
            self.exclude_wellknown_ports,
        ));
        self.add_in_use(&arc_ip);
        Ok(arc_ip)
    }

    /// The IP ranges still available for allocation, coalesced.
    ///
    /// # Walk the runs, not the bits
    ///
    /// This asks the bitmap for its *runs* rather than its set bits, and the difference is not a
    /// micro-optimisation. `for_range` seeds the bitmap with every offset in the region, capped at
    /// `u32::MAX` -- so any public range of `/96` or shorter saturates at 2^32 entries, and a v6
    /// `/64`, which is the ordinary thing an operator writes, is exactly that case.
    ///
    /// Per set bit the old walk did a `BTreeMap` lookup to convert the offset to an address, then
    /// coalesced the results back into ranges: four billion lookups to print, for a freshly built
    /// pool, one line. Measured over both address families it did not complete once in two hundred
    /// seconds -- and `Display` held the pool's read lock throughout, while `allocate_ip` and
    /// `deallocate_ip` want it for writing. Printing a v6 pool stalled every new masqueraded flow
    /// in it for as long as the print took.
    ///
    /// `Iter::next_range` yields each run of consecutive offsets in one step, so the cost is one
    /// iteration per run and runs are bounded by the number of allocated addresses. A fresh pool is
    /// a single run whatever its size.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if an offset in the bitmap has no address, which would be a bug in the
    /// mapping rather than anything about the pool's contents.
    pub(crate) fn ips_in_bitmap(&self) -> Result<BTreeSet<IpRange>, ()> {
        // A run of offsets is a run of addresses only because the mapping is a single linear
        // translation. `for_range` is the only constructor and it installs exactly one entry; a
        // pool built from several disjoint prefixes would need each run split where it crosses a
        // mapping boundary, and would otherwise print ranges that span the gap between them.
        debug_assert_eq!(
            self.bitmap_mapping.len(),
            1,
            "ips_in_bitmap treats an offset run as an address run, which holds only for a \
             single-prefix mapping"
        );

        let to_addr = |offset: u32| {
            I::try_from_offset(offset, &self.bitmap_mapping)
                .map(IpAddress::to_ip_addr)
                .map_err(|_| ())
        };

        let mut ranges = BTreeSet::new();
        let mut runs = self.bitmap.0.iter();
        while let Some(run) = runs.next_range() {
            ranges.insert(IpRange::new(to_addr(*run.start())?, to_addr(*run.end())?));
        }
        Ok(ranges)
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
    IpAddress::try_from_bits(prefix_start_bits + u128::from(offset - prefix_offset))
        .map_err(|_| AllocatorError::InternalIssue("Failed to convert offset to IPv6".to_string()))
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
