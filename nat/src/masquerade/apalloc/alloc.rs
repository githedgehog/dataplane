// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP allocation components for the default allocator for masquerade.
//!
//! This submodule focuses on allocating IP addresses, and it gets an address, calls the methods
//! from its port allocator to allocate ports for this IP address. The [`IpAllocator`] is the main
//! entry point.
//!
//! See also the architecture diagram at the top of mod.rs.

use super::region::AddrInterval;
use super::reserved::{PortClaims, ReservedPorts};
use super::{NatIpWithBitmap, port_alloc};
use crate::masquerade::allocation::AllocatorError;
use crate::masquerade::natip::NatIp;
use crate::port::NatPort;
use crate::ranges::IpRange;
use concurrency::sync::{Arc, RwLock, RwLockReadGuard, Weak};
use lpm::prefix::PortRange;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use tracing::{debug, error};

/// How many addresses one allocation may draw before giving up.
///
/// A data plane cannot search without a bound on the packet path. The bound costs nothing in the
/// ordinary case, where the first address serves, and an address that cannot serve is taken out of
/// the pool as it is found, so a run of them is worked through over successive packets rather than
/// being walked again each time.
pub(super) const MAX_ADDRESSES_PER_ALLOCATION: usize = 8;

///////////////////////////////////////////////////////////////////////////////
// IpAllocator
///////////////////////////////////////////////////////////////////////////////

/// [`IpAllocator`] is a thread-safe allocator for IP addresses. It wraps around a [`NatPool`]
/// object that contains IP availables for a given
/// [`VpcExpose`](config::external::overlay::vpcpeering::VpcExpose). It can allocate an IP and
/// (using this IP) a port.
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
        // An address upgraded out of the in-use list has to outlive the guard below.
        //
        // The list holds weak references; the strong ones belong to the blocks handed out from
        // each address. Another thread ending the last flow on an address drops the last of those
        // at any moment, which leaves the reference upgraded here as the only one. Letting it go
        // while the guard is held runs `AllocatedIp::drop` on this thread, and that takes the same
        // lock for writing: a self-deadlock that wedges the core for good, on the path every new
        // flow takes.
        //
        // Every upgrade is therefore kept until the guard is gone, and released after it.
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
                    // This address has nothing left, whether it ran out of ports in a block or of
                    // blocks altogether. Either way the next address in hand may still have room,
                    // and giving up here would draw a fresh address while those sat with ports to
                    // spare.
                    Err(e) if e.is_exhaustion() => {}
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

    /// Take an address out of the pool for good.
    ///
    /// Only for an address that can never serve, not one that is merely busy.
    fn retire_ip(&self, ip: I) {
        self.pool.write().retire_from_pool(ip);
    }

    fn allocate_from_new_ip(
        &self,
        allow_null: bool,
    ) -> Result<port_alloc::AllocatedPort<I>, AllocatorError> {
        let mut exhausted = None;
        for _ in 0..MAX_ADDRESSES_PER_ALLOCATION {
            let ip = self.allocate_new_ip_from_pool()?;
            let address = ip.ip();
            match ip.allocate_port_for_ip(allow_null) {
                Ok(port) => return Ok(port),
                Err(e) if e.is_exhaustion() => {
                    // The address came fresh out of the pool, so what leaves it with no port is
                    // almost always fixed for the life of the pool: every port it has is spoken
                    // for by port forwarding, or by the well-known range. Take it out instead of
                    // handing it back, or the next allocation stops on it again and the pool
                    // serves nothing for as long as the address is the lowest one free.
                    //
                    // Almost always, because the address joins the in-use list before this runs,
                    // so another thread could in principle take its every port in between. Losing
                    // an address that way costs capacity rather than correctness, and needs 64k
                    // allocations to land in the window.
                    //
                    // The allocation attempt consumed the only strong reference we held, so the
                    // address is already back in the pool by now and taking it out is what sticks.
                    debug!("Address {address} has no port to give and is taken out of the pool");
                    self.retire_ip(address);
                    exhausted = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        // Addresses are only ever tried once, since a useless one is taken out as it is found, so
        // stopping here spreads the discovery of a large claimed range over several packets rather
        // than doing all of it on one.
        Err(exhausted.unwrap_or(AllocatorError::NoFreeIp))
    }

    fn cleanup_used_ips(&self) {
        // Same trap as in `reuse_allocated_ip`, and worse: `cleanup` upgrades each weak reference
        // to see whether it still resolves, and does it holding the pool's *write* lock. An
        // upgrade that turns out to be the last strong reference runs `AllocatedIp::drop` on this
        // thread, which asks for that same lock again.
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

        // Drawing a fresh address is what to do when the addresses already in hand have no room,
        // and only then. `reuse_allocated_ip` distinguishes the two: it walks past an address that
        // has run out and reports anything else as it found it. Taking only `Ok` here would put
        // that back, burying an error about the allocator under whatever the fresh address
        // returns -- the same mistake `PoolSet::allocate` avoids one level up, where trying the
        // next region on any error would bury it under a success.
        match self.reuse_allocated_ip(allow_null) {
            Ok(port) => Ok(port),
            Err(e) if e.is_exhaustion() => self.allocate_from_new_ip(allow_null),
            Err(e) => Err(e),
        }
    }

    fn get_allocated_ip(&self, ip: I) -> Result<Arc<AllocatedIp<I>>, AllocatorError> {
        // The third place that upgrades an in-use entry under the pool lock, and so the third that
        // must not let the upgrade go while holding it. See `cleanup_used_ips`.
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

/// What a single expose may allocate from: the regions its public range covers, in the order to
/// try them, plus the settings that belong to the expose rather than to the address space.
///
/// An expose's range is exactly the union of its regions, so allocating from any of them yields an
/// address the expose is configured for, and regions shared with another expose are backed by one
/// allocator, so no address is handed out twice.
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

    /// Allocate from the first region with room. Regions are ordered so that those the expose has
    /// to itself are tried first, leaving shared space for exposes that have nowhere else to go.
    ///
    /// Only a region being full moves on to the next one. Any other error is about the allocator
    /// rather than about how full that region is, and trying the next region would either bury it
    /// under a success or replace it with a later region's `NoFreeIp`.
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
        reserved_ports: PortClaims,
        randomize: bool,
        exclude_wellknown_ports: bool,
    ) -> Self {
        Self {
            ip,
            port_allocator: port_alloc::PortAllocator::new(
                reserved_ports,
                randomize,
                exclude_wellknown_ports,
            ),
            ip_allocator,
        }
    }

    pub(crate) fn ip(&self) -> I {
        self.ip
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
    /// Offsets that may never be handed out, however often they are given back.
    ///
    /// Distinct from being absent from `bitmap`, which only says an address is in use at the
    /// moment. An address lands here either because port forwarding has claimed every port
    /// masquerade could draw on it, which is known when the pool is built, or because it was found
    /// to have nothing to give while serving. Either way it must not come back:
    /// `deallocate_from_pool` runs on the drop path and would otherwise return it to the pool the
    /// first time a flow holding it ends, which for a carried-over flow is moments after the pool
    /// was built.
    unusable: RoaringBitmap,
    bitmap_mapping: BTreeMap<u32, u128>,
    reverse_bitmap_mapping: BTreeMap<u128, u32>,
    in_use: VecDeque<Weak<AllocatedIp<I>>>,
    reserved_ports: ReservedPorts,
    exclude_wellknown_ports: bool,
}

impl<I: NatIpWithBitmap> NatPool<I> {
    /// Build the pool covering one contiguous region of the public address space.
    ///
    /// Pools own a region rather than an expose's range, because ranges from different exposes
    /// overlap and a public address may only be handed out by one pool.
    pub(crate) fn for_range(
        range: AddrInterval,
        reserved_ports: ReservedPorts,
        exclude_wellknown_ports: bool,
    ) -> Self {
        // Index the region from its own start. IPv4 indexes its bitmap by the address bits and
        // ignores the mapping; IPv6 cannot fit its space in a u32, so indices count from the start
        // of the region and the mapping carries them back to real addresses. Going through
        // try_to_offset gets both right without naming either version here.
        let bitmap_mapping = BTreeMap::from([(0u32, range.start)]);
        let reverse_bitmap_mapping = BTreeMap::from([(range.start, 0u32)]);

        // A region holding more addresses than the u32 bitmap can index is truncated. We would run
        // out of memory long before allocating four billion addresses.
        let span = range.len().saturating_sub(1).min(u128::from(u32::MAX));
        let indexable = AddrInterval::new(range.start, range.start + span);
        let to_offset = |bits: u128| {
            let address = I::try_from_bits(bits).unwrap_or_else(|()| unreachable!());
            I::try_to_offset(address, &reverse_bitmap_mapping).unwrap_or_else(|_| unreachable!())
        };

        let mut bitmap =
            PoolBitmap::with_offset_range(to_offset(indexable.start), to_offset(indexable.end));

        // An address port forwarding has taken every usable port on can serve masquerade nothing,
        // and which addresses those are is known now rather than discovered a packet at a time.
        // Left in the pool, such an address is drawn because it is the lowest one free, found
        // useless, and taken out -- but only eight of them may be worked through before the
        // allocation gives up, so a run of them costs a dropped packet for every eight, on flows
        // the region had ample room for. And it costs them again after every config change, since
        // a new allocator starts with a fresh pool. Keeping them out from the start costs one
        // sweep over the claims when the pool is built.
        let mut unusable = RoaringBitmap::new();
        for interval in reserved_ports.unusable_within::<I>(indexable, exclude_wellknown_ports) {
            let (first, last) = (to_offset(interval.start), to_offset(interval.end));
            unusable.insert_range(first..=last);
            bitmap.remove_offset_range(first, last);
        }
        if !unusable.is_empty() {
            debug!(
                "Pool over {} address(es) keeps {} of them out: port forwarding has claimed every \
                 port masquerade could use there",
                indexable.len(),
                unusable.len()
            );
        }

        Self {
            bitmap,
            unusable,
            bitmap_mapping,
            reverse_bitmap_mapping,
            in_use: VecDeque::new(),
            reserved_ports,
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

    // Used for Display
    pub(crate) fn reserved_ports(&self) -> Option<impl Iterator<Item = (IpRange, PortRange)>> {
        if self.reserved_ports.is_empty() {
            return None;
        }
        Some(self.reserved_ports.iter())
    }

    fn use_new_ip(
        &mut self,
        ip_allocator: IpAllocator<I>,
        randomize: bool,
    ) -> Result<AllocatedIp<I>, AllocatorError> {
        // Retrieve the first available offset
        let offset = self.bitmap.pop_ip()?;

        let ip = I::try_from_offset(offset, &self.bitmap_mapping)?;

        // Every port range port forwarding has claimed on this address, not just one of them.
        let claims = self.reserved_ports.for_address(ip.to_ip_addr());

        Ok(AllocatedIp::new(
            ip,
            ip_allocator,
            claims,
            randomize,
            self.exclude_wellknown_ports,
        ))
    }

    // Mark an address used and never give it back, for an address that can never serve.
    fn retire_from_pool(&mut self, ip: I) {
        match I::try_to_offset(ip, &self.reverse_bitmap_mapping) {
            Ok(offset) => {
                self.unusable.insert(offset);
                self.bitmap.set_ip_allocated(offset);
            }
            Err(e) => error!("Address {ip} cannot be retired from its pool: {e}"),
        }
    }

    fn deallocate_from_pool(&mut self, ip: I) {
        debug!("Address {ip} was deallocated");
        // The address was handed out by this pool, so it maps back into it. This runs while an
        // allocation is being dropped and has nowhere to report a failure, so say so and leave the
        // address marked in use rather than panicking on the drop path.
        match I::try_to_offset(ip, &self.reverse_bitmap_mapping) {
            Ok(offset) => {
                // An address that can never serve does not come back, whoever is giving it up.
                // Reserving reaches addresses the pool never draws, so a flow carried across a
                // config change onto an address the new configuration has claimed would otherwise
                // put it into the pool on its way out.
                if self.unusable.contains(offset) {
                    debug!("Address {ip} stays out of its pool: it can serve nothing");
                } else {
                    self.bitmap.set_ip_free(offset);
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
        // If the IP was already allocated in the bitmap, this is OK: it means that the IP was
        // allocated in the past, it is no longer in used (because it is not in the list of in-use
        // IPs), but we haven't deallocated from the bitmap yet (this happens when another thread
        // drops an AllocatedIp and its reference count goes to 0, but it hasn't called the drop()
        // function to remove the IP from the bitmap in that other thread yet).
        let _ = self.bitmap.set_ip_allocated(offset);
        let arc_ip = Arc::new(AllocatedIp::new(
            ip,
            ip_allocator,
            // An address entering the pool this way serves later allocations exactly as one that
            // arrived through allocate(), so it has to carry the same claims. Passing none here
            // let a flow carried across a config change bring an address in unencumbered, after
            // which masquerade could hand out the ports port forwarding had taken on it.
            self.reserved_ports.for_address(ip.to_ip_addr()),
            randomize,
            // Keep the low-port exclusion policy for explicitly reserved IPs as well, so
            // reserve() follows the same TCP/UDP allocation rules as allocate().
            self.exclude_wellknown_ports,
        ));
        self.add_in_use(&arc_ip);
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

    /// Take an inclusive range of indices out of the pool.
    fn remove_offset_range(&mut self, start: u32, end: u32) {
        self.0.remove_range(start..=end);
    }
}

///////////////////////////////////////////////////////////////////////////////
// IPv6 <-> u32-offset mapping functions
///////////////////////////////////////////////////////////////////////////////

pub(crate) fn map_offset(
    offset: u32,
    bitmap_mapping: &BTreeMap<u32, u128>,
) -> Result<Ipv6Addr, AllocatorError> {
    // Field bitmap_mapping is a BTreeMap that associates, to each given u32 offset, an IPv6
    // address, as a u128, corresponding to the network address of the corresponding prefix in
    // the list.
    // Here we lookup for the closest lower offset in the tree, which returns the network
    // address for the prefix start address and its offset, and we deduce the IPv6 address we're
    // looking for.
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
