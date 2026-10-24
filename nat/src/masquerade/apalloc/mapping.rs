// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Mapping table for masquerade. This is a side table that lets a public tuple be shared by several
//! flows, based on the selected mapping behavior.
//!
//! A [`Mapping`] independently owns its [`AllocatedPort`], with its own expiry (RFC 4787 REQ-5).
//! Flows share a mapping via `Arc`.
//!
//! [`Subscriber`] is the per-private-address record. It holds the pinned public addresses usable
//! for NAT for that private address, as required by RFC 4787's "Paired" IP pooling behavior; and
//! the map of mappings currently in use for that private address.

use super::NatIpWithBitmap;
use super::alloc::{AllocatedIp, PoolSet};
use super::port_alloc::AllocatedPort;
use crate::masquerade::allocation::AllocatorError;
use crate::port::NatPort;
use concurrency::sync::atomic::{AtomicBool, Ordering};
use concurrency::sync::{Arc, Mutex, RwLock};
use config::external::overlay::vpcpeering::MappingPolicy;
use flow_entry::flow_table::{Schedule, SideTimer, TimerRef};
use net::flows::nat_state::MappingDeadline;
#[cfg(not(miri))]
use shuttle_dashmap::DashMap;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::time::{Duration, Instant};

///////////////////////////////////////////////////////////////////////////////
// MappingScope / MappingKey
///////////////////////////////////////////////////////////////////////////////

/// The destination context for a mapping, based on the configured [`MappingPolicy`]. Two packets
/// from the same private `(ip, port)` share a mapping exactly when they have equal scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MappingScope<I: NatIpWithBitmap> {
    /// EIM, Endpoint-Independent Mapping: destination never matters
    Independent,
    /// ADM, Address-Dependent Mapping: same mapping if and only if same destination address
    Address(I),
    /// APDM, Address-and-Port-Dependent Mapping: same mapping if and only if same destination
    /// address and port (or ICMP identifier)
    AddressPort(I, NatPort),
}

impl<I: NatIpWithBitmap> MappingScope<I> {
    pub(crate) fn new(policy: MappingPolicy, dst_ip: I, dst_port: Option<NatPort>) -> Self {
        match (policy, dst_port) {
            //= https://www.rfc-editor.org/rfc/rfc4787#section-4.1
            //= type=implementation
            //# REQ-1:  A NAT MUST have an "Endpoint-Independent Mapping" behavior.
            (MappingPolicy::EndpointIndependent, _) => Self::Independent,
            //= https://www.rfc-editor.org/rfc/rfc4787#section-4.1
            //= type=exception
            //= reason=an operator may opt a peering into Address-Dependent or Address-and-Port-Dependent Mapping, which folds the destination into the mapping key and so is deliberately not Endpoint-Independent for that peering; the default stays EndpointIndependent
            //# REQ-1:  A NAT MUST have an "Endpoint-Independent Mapping" behavior.
            //= https://www.rfc-editor.org/rfc/rfc5382#section-4.1
            //= type=exception
            //= reason=the same operator opt-in applies to TCP: a peering configured for Address-Dependent or Address-and-Port-Dependent Mapping is deliberately not Endpoint-Independent for TCP either
            //# REQ-1:  A NAT MUST have an "Endpoint-Independent Mapping" behavior
            //# for TCP.
            (MappingPolicy::AddressAndPortDependent, Some(port)) => Self::AddressPort(dst_ip, port),
            // dst_port is None for traffic with no representable destination port/identifier (for
            // example, an ICMP error message, or an unsupported ICMP category). Under APDM, this
            // degrades to address-only scope rather than failing.
            (MappingPolicy::AddressDependent, _)
            | (MappingPolicy::AddressAndPortDependent, None) => Self::Address(dst_ip),
        }
    }
}

// The private side of a flow, as the allocator sees it: what private endpoing is talking, to whom
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrivateTuple<I: NatIpWithBitmap> {
    pub(crate) src_ip: I,
    pub(crate) src_port: NatPort,
    pub(crate) dst_ip: I,
    pub(crate) dst_port: Option<NatPort>,
}

impl<I: NatIpWithBitmap> PrivateTuple<I> {
    pub(crate) fn new(src_ip: I, src_port: NatPort, dst_ip: I, dst_port: Option<NatPort>) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }
}

// The key to identify one mapping within a Subscriber
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MappingKey<I: NatIpWithBitmap> {
    port: NatPort,
    scope: MappingScope<I>,
}

impl<I: NatIpWithBitmap> MappingKey<I> {
    pub(crate) fn new(port: NatPort, scope: MappingScope<I>) -> Self {
        Self { port, scope }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Mapping
///////////////////////////////////////////////////////////////////////////////

/// One public tuple (IP and port). Flows share a `Mapping` through `Arc`; dropping the last
/// reference to it (the owning [`Subscriber`]'s table entry, plus every flow's reference) releases
/// the tuple through the `AllocatedPort` -> `AllocatedPortBlock` -> `AllocatedIp` chain of `Drop`
/// implementations.
#[derive(Debug)]
pub struct Mapping<I: NatIpWithBitmap> {
    allocation: AllocatedPort<I>,
    /// Shared with the flows holding this mapping, which refresh it on outbound traffic without
    /// reaching the mapping itself.
    deadline: MappingDeadline,
    /// The reaper's timer, once it is on a worker's wheel.
    timer: Mutex<Option<TimerRef>>,
}

impl<I: NatIpWithBitmap> Mapping<I> {
    fn new(allocation: AllocatedPort<I>, idle_timeout: Duration) -> Self {
        Self {
            allocation,
            deadline: MappingDeadline::new(idle_timeout),
            timer: Mutex::new(None),
        }
    }

    fn bind_timer(&self, timer: TimerRef) {
        if let Some(previous) = self.timer.lock().replace(timer) {
            // A reaper put back on its wheel: the previous timer already fired.
            previous.cancel();
        }
    }

    fn cancel_timer(&self) {
        if let Some(timer) = self.timer.lock().as_ref() {
            timer.cancel();
        }
    }

    #[must_use]
    pub(crate) fn allocation(&self) -> &AllocatedPort<I> {
        &self.allocation
    }

    #[must_use]
    pub fn ip(&self) -> I {
        self.allocation.ip()
    }

    #[must_use]
    pub fn port(&self) -> NatPort {
        self.allocation.port()
    }

    pub(crate) fn expires_at(&self) -> Instant {
        self.deadline.expires_at()
    }

    /// The deadline, for a flow holding this mapping.
    pub(crate) fn deadline(&self) -> MappingDeadline {
        self.deadline.clone()
    }

    fn is_expired(&self) -> bool {
        self.expires_at() <= clock::now()
    }

    // From RFC 4787 REQ-6, any outbound packet on any flow sharing a mapping refreshes it,
    // independent of that flow's own idle timer. The clock is monotonic, given that several flows
    // on different cores may refresh concurrently, and we must never make it go backwards.
    pub(crate) fn refresh(&self) {
        self.deadline.refresh();
    }
}

///////////////////////////////////////////////////////////////////////////////
// Subscriber
///////////////////////////////////////////////////////////////////////////////

// One private address, that "subscribes" to mappings (public IP/port tuples). This is used to
// implement RFC 4787's "Paired" IP pooling, holding every Mapping currently in use for the private
// address.
//
// The Subscriber is reaped from its parent PoolSet's table once its mapping table goes empty.
#[derive(Debug)]
pub(crate) struct Subscriber<I: NatIpWithBitmap> {
    /// Associated public addresses, ordered (first-used first).
    addresses: RwLock<SmallVec<[Arc<AllocatedIp<I>>; 1]>>,
    mappings: RwLock<HashMap<MappingKey<I>, Arc<Mapping<I>>>>,
}

impl<I: NatIpWithBitmap> Default for Subscriber<I> {
    fn default() -> Self {
        Self {
            addresses: RwLock::new(SmallVec::new()),
            mappings: RwLock::new(HashMap::new()),
        }
    }
}

impl<I: NatIpWithBitmap> Subscriber<I> {
    fn pin_if_absent(addresses: &mut SmallVec<[Arc<AllocatedIp<I>>; 1]>, ip: &Arc<AllocatedIp<I>>) {
        if !addresses.iter().any(|pinned| pinned.ip() == ip.ip()) {
            addresses.push(ip.clone());
        }
    }

    // Draw a port for a new mapping, preferring this subscriber's already-in-use addresses (Paired
    // pooling behavior) and only falling through to the parent pool's reuse-then-new-address path
    // once every associated address is exhausted (or if none exists yet).
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.1
    //= type=implementation
    //# REQ-2:  It is RECOMMENDED that a NAT have an "IP address pooling"
    //# behavior of "Paired".
    //
    // This is what closes the gap IpAllocator::allocate documents as its REQ-2 exception: the
    // choice is keyed on the internal IP for the lifetime of its mappings.
    fn allocate_paired(
        &self,
        pool: &PoolSet<I>,
        allow_null: bool,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        {
            let pinned = self.addresses.read();
            for ip in pinned.iter() {
                match ip.clone().allocate_port_for_ip(allow_null) {
                    Ok(port) => return Ok(port),
                    Err(e) if e.is_exhaustion() => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let port = pool.allocate(allow_null)?;
        Self::pin_if_absent(&mut self.addresses.write(), port.allocated_ip());
        Ok(port)
    }

    fn live_mapping(&self, key: &MappingKey<I>) -> Option<Arc<Mapping<I>>> {
        self.mappings
            .read()
            .get(key)
            .filter(|m| !m.is_expired())
            .cloned()
    }

    fn get_or_insert_with(
        self: &Arc<Self>,
        src_ip: I,
        key: MappingKey<I>,
        pool: &PoolSet<I>,
        // "draw" produces the AllocatedPort, and is responsible for having whatever address it
        // picks associated to a subscriber (so this differs between drawing a fresh port and
        // re-reserving a known one)
        //
        // Note that "draw" runs with this subscriber's "mappings" write lock held, so it must no
        // reach the pool's subscriber table: reaping takes that table's lock and then a
        // subscriber's mappings, so we'd risk a deadlock.
        draw: impl FnOnce() -> Result<AllocatedPort<I>, AllocatorError>,
        timers: &dyn Schedule,
    ) -> Result<Arc<Mapping<I>>, AllocatorError> {
        // Lazy staleness check (common path)
        if let Some(existing) = self.live_mapping(&key) {
            existing.refresh();
            return Ok(existing);
        }
        let mut guard = self.mappings.write();
        // Now that we grabbed the write lock, check again in case a racing thread created an entry
        // in the meantime
        if let Some(existing) = guard.get(&key).filter(|m| !m.is_expired()) {
            existing.refresh();
            return Ok(existing.clone());
        }
        let mapping = Arc::new(Mapping::new(draw()?, pool.idle_timeout()));
        guard.insert(key, mapping.clone());
        drop(guard);
        timers.schedule(Box::new(MappingReaper {
            subscriber: self.clone(),
            subscriber_ip: src_ip,
            key,
            mapping: mapping.clone(),
            subscribers: pool.subscribers().clone(),
            retired: pool.reapers_retired(),
        }));
        Ok(mapping)
    }

    // Get mapping for the given key, or create one allocating a fresh port if none exists (or if
    // the existing one has expired)
    pub(crate) fn get_or_create(
        self: &Arc<Self>,
        src_ip: I,
        key: MappingKey<I>,
        pool: &PoolSet<I>,
        allow_null: bool,
        timers: &dyn Schedule,
    ) -> Result<Arc<Mapping<I>>, AllocatorError> {
        self.get_or_insert_with(
            src_ip,
            key,
            pool,
            || self.allocate_paired(pool, allow_null),
            timers,
        )
    }

    // Same as get_or_create(), but for re-reserving a known (ip, port) tuple during config
    // migration, rather than selecting a new one one.
    pub(crate) fn get_or_reserve(
        self: &Arc<Self>,
        src_ip: I,
        key: MappingKey<I>,
        pool: &PoolSet<I>,
        ip: I,
        port: NatPort,
        timers: &dyn Schedule,
    ) -> Result<Arc<Mapping<I>>, AllocatorError> {
        let mapping = self.get_or_insert_with(
            src_ip,
            key,
            pool,
            || {
                let allocated = pool.reserve(ip, port)?;
                Self::pin_if_absent(&mut self.addresses.write(), allocated.allocated_ip());
                Ok(allocated)
            },
            timers,
        )?;
        // If a mapping is already associated to this key, attach to it, we attach to it, rather
        // than reserving the mapping again. This is what lets two flows sharing one mapping both
        // survive a config change. But we can only do that when the new and old mappings' tuple is
        // exactly the same. Otherwise, we'd have an issue when a policy change merges two
        // previously distinct keys into one (if moving from ADM to EIM behaviors, for example), and
        // then the second flow would keep rewriting to a tuple that nothing reserved in the new
        // allocator. So if the old and new tuples are not the same, we refuse to reserve, so the
        // caller invalidates the flow rather than carrying a tuple it no longer owns.
        if mapping.ip() != ip || mapping.port() != port {
            return Err(AllocatorError::MappingTupleMismatch {
                found: mapping.to_string(),
                requested: format!("{ip}:{port}"),
            });
        }
        Ok(mapping)
    }

    // Whether this subscriber holds no mappings; returns `None` when its map is locked by some
    // other entity.
    //
    // Reaping calls this from inside the subscriber table's shard lock, where blocking on a second
    // lock would pin the whole shard behind an unrelated subscriber's port draw (which holds
    // "mappings" for its duration). A subscriber whose lock is held is in use by definition, so we
    // just decline to reap it.
    fn try_is_empty(&self) -> Option<bool> {
        self.mappings.try_read().map(|m| m.is_empty())
    }
}

///////////////////////////////////////////////////////////////////////////////
// Reaping
///////////////////////////////////////////////////////////////////////////////

// Must be a power of two.
// Under the model backends the backing map is a single lock and this is ignored.
const SUBSCRIBER_SHARDS: usize = 1024;

// The per-pool table of Subscribers, keyed by private address
//
// The backing map is shuttle-dashmap, which is the real sharded DashMap in production and a
// façade-routed RwLock<HashMap> under the model backends. That matters because DashMap::remove_if()
// runs its closure while holding a shard lock: with the real map that lock is dashmap's own
// RawRwLock, which a model checker cannot see, so touching a façade lock from the closure would
// suspend the task mid-closure with an unmodelled lock held and wedge shuttle's single-threaded
// executor. The model build has no unmodelled lock to hold.
#[derive(Debug, Clone)]
pub(crate) struct SubscribersTable<I: NatIpWithBitmap>(Arc<Backing<I>>);

// Under miri the map goes through the façade as well, for a reason of the same shape: dashmap's
// shard locks are parking_lot_core's, and parking_lot_core parks on a futex through a c-variadic
// syscall whose argument types miri rejects as UB. The façade already refuses to use parking_lot
// under miri (see concurrency::sync), but it cannot refuse on dashmap's behalf, so a contended
// shard takes the slow path straight into that syscall.
#[cfg(not(miri))]
type Backing<I> = DashMap<I, Arc<Subscriber<I>>>;
#[cfg(miri)]
type Backing<I> = RwLock<HashMap<I, Arc<Subscriber<I>>>>;

#[cfg(not(miri))]
impl<I: NatIpWithBitmap> SubscribersTable<I> {
    pub(crate) fn new() -> Self {
        Self(Arc::new(DashMap::with_shard_amount(SUBSCRIBER_SHARDS)))
    }

    // Get the subscriber for the provided IP, or create an empty one if this is the first mapping
    pub(crate) fn get_or_default(&self, ip: I) -> Arc<Subscriber<I>> {
        // Common case: probe read-only first
        if let Some(existing) = self.0.get(&ip) {
            return existing.clone();
        }
        // Else, take the shard's write lock
        self.0
            .entry(ip)
            .or_insert_with(|| Arc::new(Subscriber::default()))
            .clone()
    }

    // Drop subscriber's row if it is still that exact subscriber and still holds no mappings
    pub(crate) fn remove_if_empty(&self, ip: I, subscriber: &Arc<Subscriber<I>>) {
        self.0.remove_if(&ip, |_, v| {
            Arc::ptr_eq(v, subscriber) && v.try_is_empty().unwrap_or(false)
        });
    }

    // Call `f` on every mapping of every subscriber.
    pub(crate) fn for_each_mapping(&self, mut f: impl FnMut(&Mapping<I>)) {
        for entry in self.0.iter() {
            entry.value().mappings.read().values().for_each(|m| f(m));
        }
    }

    #[cfg(test)]
    pub(crate) fn get(&self, ip: I) -> Option<Arc<Subscriber<I>>> {
        self.0.get(&ip).map(|entry| entry.value().clone())
    }
}

#[cfg(miri)]
impl<I: NatIpWithBitmap> SubscribersTable<I> {
    pub(crate) fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }

    pub(crate) fn get_or_default(&self, ip: I) -> Arc<Subscriber<I>> {
        if let Some(existing) = self.0.read().get(&ip) {
            return existing.clone();
        }
        self.0
            .write()
            .entry(ip)
            .or_insert_with(|| Arc::new(Subscriber::default()))
            .clone()
    }

    pub(crate) fn remove_if_empty(&self, ip: I, subscriber: &Arc<Subscriber<I>>) {
        let mut guard = self.0.write();
        if guard
            .get(&ip)
            .is_some_and(|v| Arc::ptr_eq(v, subscriber) && v.try_is_empty().unwrap_or(false))
        {
            guard.remove(&ip);
        }
    }

    pub(crate) fn for_each_mapping(&self, mut f: impl FnMut(&Mapping<I>)) {
        for subscriber in self.0.read().values() {
            subscriber.mappings.read().values().for_each(|m| f(m));
        }
    }

    #[cfg(test)]
    pub(crate) fn get(&self, ip: I) -> Option<Arc<Subscriber<I>>> {
        self.0.read().get(&ip).cloned()
    }
}

// Retires every reaper a pool started, once the last copy of the pool is gone.
//
// A reaper holds its Subscriber, its Mapping and the subscriber table until it fires, which is the
// mapping's deadline: possibly far away, since idle timeouts are configurable. When a config change
// replaces the allocator, this cancels them all at once, so the old pool is not kept alive.
#[derive(Debug)]
pub(crate) struct PoolReapers<I: NatIpWithBitmap> {
    retired: Arc<AtomicBool>,
    subscribers: SubscribersTable<I>,
}

impl<I: NatIpWithBitmap> PoolReapers<I> {
    pub(crate) fn new(subscribers: SubscribersTable<I>) -> Self {
        Self {
            retired: Arc::new(AtomicBool::new(false)),
            subscribers,
        }
    }

    pub(crate) fn retired(&self) -> Arc<AtomicBool> {
        self.retired.clone()
    }
}

impl<I: NatIpWithBitmap> Drop for PoolReapers<I> {
    fn drop(&mut self) {
        // Set first: a reaper that fires before its cancellation arrives sees the flag and is done.
        self.retired.store(true, Ordering::Relaxed);
        self.subscribers.for_each_mapping(Mapping::cancel_timer);
    }
}

// A mapping's reaper, on the wheel of the worker that created the mapping (or of the worker a
// configuration change handed it to). When the mapping's deadline passes, it re-checks for a
// concurrent refresh and expires the mapping otherwise, then reaps the owning Subscriber too if
// it is now empty, so a Paired-pooled address is not pinned forever once nothing uses it any more.
struct MappingReaper<I: NatIpWithBitmap> {
    subscriber: Arc<Subscriber<I>>,
    subscriber_ip: I,
    key: MappingKey<I>,
    mapping: Arc<Mapping<I>>,
    subscribers: SubscribersTable<I>,
    retired: Arc<AtomicBool>,
}

impl<I: NatIpWithBitmap> SideTimer for MappingReaper<I> {
    fn deadline(&self) -> Instant {
        self.mapping.expires_at()
    }

    fn bind(&self, timer: TimerRef) {
        self.mapping.bind_timer(timer);
    }

    fn fire(&mut self, now: Instant) -> bool {
        // The pool this mapping belongs to is gone: there is nothing left to reap it out of.
        if self.retired.load(Ordering::Relaxed) {
            return false;
        }
        if self.mapping.expires_at() > now {
            return true;
        }
        // A refresh can land between that check and the write lock; then the mapping keeps its
        // entry, and has to keep this reaper too: no other path starts one for an entry already in
        // the table.
        !reap_expired_mapping(
            &self.subscriber,
            self.subscriber_ip,
            self.key,
            &self.mapping,
            &self.subscribers,
        )
    }
}

// Drop the mapping from the subscriber's table (verifying identity so a concurrently-inserted
// replacement under the same key survives), then reap the subscriber itself if it is now empty
//
// Return whether this reaper is finished with the mapping: true if the entry is gone (removed here
// or already replaced elsewhere), false if a refresh landed between the caller's deadline check and
// the write lock, meaning the entry is still live and the caller has to keep watching it.
pub(crate) fn reap_expired_mapping<I: NatIpWithBitmap>(
    subscriber: &Arc<Subscriber<I>>,
    subscriber_ip: I,
    key: MappingKey<I>,
    mapping: &Arc<Mapping<I>>,
    subscribers: &SubscribersTable<I>,
) -> bool {
    // Remove the mapping, verifying identity so a concurrently-inserted replacement under the same
    // key survives, and re-checking expiry so a refresh that landed after the reaper last looked is
    // not thrown away. The caller already checked expirty, but we need to double-check now we hold
    // the lock, to avoid a race.
    let done = {
        let mut guard = subscriber.mappings.write();
        match guard.get(&key) {
            Some(current) if Arc::ptr_eq(current, mapping) => {
                if mapping.is_expired() {
                    guard.remove(&key);
                    true
                } else {
                    false
                }
            }
            // Gone, or replaced by a fresh mapping that brought its own reaper
            _ => true,
        }
    };

    // If that was the last mapping, reap the subscriber too, so its pinned public IP(s) are
    // not held forever.
    //
    // Note: There is a potential, acceptable race where a concurrent get_or_create() or
    // get_or_reserve() call for a new key on the same subscriber may have fetched the
    // Arc<Subscriber>, but not yet inserted its new mapping when this check runs. In that case,
    // we'd go on and insert the mapping into the now-orphaned subscriber. This mapping's port still
    // expires correctly; only pinning consistency for that one flow degrades temporarily, and
    // returns to normal once the orphan subscriber's mappings expire. We accept a similar race
    // AllocatedPortBlockMap::remove_if_still_dead, for the same reason.
    subscribers.remove_if_empty(subscriber_ip, subscriber);
    done
}

#[cfg(test)]
mod tests {
    use super::super::region::AddrInterval;
    use super::super::setup::{PoolSpec, narrow_budget_specs, pool_sets_for_specs};
    use super::super::test_alloc::context::port;
    use super::*;
    use crate::masquerade::apalloc::test_alloc::context::TIMERS;
    use net::ip::NextHeader;
    use std::net::Ipv4Addr;

    fn dst() -> Ipv4Addr {
        "9.9.9.9".parse().unwrap()
    }

    fn other_dst() -> Ipv4Addr {
        "8.8.8.8".parse().unwrap()
    }

    // RFC 4787 Endpoint-Independent Mapping: the destination never enters the scope, so every
    // combination of destination address/port collapses to "Independent"
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.1
    //= type=test
    //# REQ-1:  A NAT MUST have an "Endpoint-Independent Mapping" behavior.
    #[test]
    fn endpoint_independent_ignores_the_destination() {
        for dst_port in [None, Some(port(80)), Some(port(443))] {
            assert_eq!(
                MappingScope::new(MappingPolicy::EndpointIndependent, dst(), dst_port),
                MappingScope::Independent
            );
        }
    }

    // RFC 4787 Address-Dependent Mapping: only the destination address enters the scope, so a
    // different destination port with the same address does not change it
    #[test]
    fn address_dependent_ignores_the_destination_port() {
        assert_eq!(
            MappingScope::new(MappingPolicy::AddressDependent, dst(), Some(port(80))),
            MappingScope::new(MappingPolicy::AddressDependent, dst(), Some(port(443))),
        );
        assert_eq!(
            MappingScope::new(MappingPolicy::AddressDependent, dst(), None),
            MappingScope::Address(dst())
        );
    }

    // RFC 4787 Address-and-Port-Dependent Mapping: a different destination address, or a
    // different destination port on the same address, both must change the scope
    #[test]
    fn address_and_port_dependent_distinguishes_both() {
        let a = MappingScope::new(
            MappingPolicy::AddressAndPortDependent,
            dst(),
            Some(port(80)),
        );
        let b = MappingScope::new(
            MappingPolicy::AddressAndPortDependent,
            dst(),
            Some(port(443)),
        );
        let c = MappingScope::new(
            MappingPolicy::AddressAndPortDependent,
            other_dst(),
            Some(port(80)),
        );
        assert_ne!(a, b, "a different destination port must change the scope");
        assert_ne!(
            a, c,
            "a different destination address must change the scope"
        );
    }

    // Traffic with no representable destination port/identifier (for example, ICMP error message)
    // degrades to address-only scope under AddressAndPortDependent, rather than being unscopable
    #[test]
    fn address_and_port_dependent_falls_back_to_address_only_without_a_dst_port() {
        assert_eq!(
            MappingScope::new(MappingPolicy::AddressAndPortDependent, dst(), None),
            MappingScope::Address(dst())
        );
    }

    const BASE: u128 = 0x0A02_0000; // 10.2.0.0, distinct from other apalloc test fixtures' ranges.
    const BUDGET: u16 = 3;

    // Two addresses, each with a per-address port budget small enough that exhaustion is reachable
    // in a handful of draws, via the same claiming mechanism port forwarding uses to reserve space
    fn narrow_budget_pool() -> PoolSet<Ipv4Addr> {
        pool_sets_for_specs::<Ipv4Addr>(&narrow_budget_specs(BASE, BUDGET), NextHeader::TCP, false)
            .into_iter()
            .next()
            .unwrap_or_else(|| unreachable!())
    }

    // A reaper waits for its mapping's deadline, holding the subscriber, the mapping and the
    // subscriber table alive. Replacing the allocator on a config change drops the pool those
    // belong to, and the reapers have to go with it: otherwise every live mapping keeps a timer, and
    // the old allocator's tables reachable, until its deadline passes, which may be never.
    #[tokio::test(start_paused = true)]
    async fn dropping_a_pool_retires_the_reapers_it_started() {
        use flow_entry::flow_table::{FlowTable, WorkerFlowTable};

        let worker = WorkerFlowTable::new(Arc::new(FlowTable::default()));
        let pool = narrow_budget_pool();
        let subscriber_ip = Ipv4Addr::from(u32::try_from(BASE).unwrap_or_else(|_| unreachable!()));
        let mapping = pool
            .get_or_create_mapping(
                subscriber_ip,
                MappingKey::new(port(1), MappingScope::Independent),
                false,
                &worker,
            )
            .expect("the pool has room");
        assert_eq!(
            worker.timers(),
            1,
            "sanity: creating a mapping should have put a reaper on the worker's wheel"
        );

        // The mapping outlives the pool here, as a flow's own reference would
        drop(pool);

        // Nowhere near the mapping's deadline: the reaper goes because its pool did.
        worker.expire_all(clock::now());
        assert_eq!(
            worker.timers(),
            0,
            "a reaper stayed on the wheel after its pool was dropped"
        );
        drop(mapping);
    }

    // A configured idle timeout has no upper bound (see GH 1854), and deadlines are computed as
    // "now + timeout". We use a saturating helper to avoid overflow; make sure it doesn't regress.
    #[test]
    fn an_absurd_idle_timeout_never_overflows_a_deadline() {
        let specs = vec![PoolSpec::new(
            vec![AddrInterval::new(BASE, BASE)],
            Duration::MAX, // that's long!
        )];
        let pool = pool_sets_for_specs::<Ipv4Addr>(&specs, NextHeader::TCP, false)
            .into_iter()
            .next()
            .unwrap_or_else(|| unreachable!());
        let subscriber_ip = Ipv4Addr::from(u32::try_from(BASE).unwrap_or_else(|_| unreachable!()));

        // Both deadline computations: one at creation, one on every refresh.
        let mapping = pool
            .get_or_create_mapping(
                subscriber_ip,
                MappingKey::new(port(1), MappingScope::Independent),
                false,
                &TIMERS,
            )
            .expect("the pool has room");
        mapping.refresh();

        assert!(
            !mapping.is_expired(),
            "a mapping with the largest configured timeout should be live, not expired"
        );
    }

    // A pool whose mappings are expired the moment they are handed out
    fn pool_with_zero_timeout() -> PoolSet<Ipv4Addr> {
        let specs = vec![PoolSpec::new(
            vec![AddrInterval::new(BASE, BASE)],
            Duration::ZERO,
        )];
        pool_sets_for_specs::<Ipv4Addr>(&specs, NextHeader::TCP, false)
            .into_iter()
            .next()
            .unwrap_or_else(|| unreachable!())
    }

    // The reaper re-reads the deadline before it decides to expire a mapping, but an outbound
    // packet's refresh can still land between that read and the write lock. Reaping then would
    // strand the flow holding this Arc on a tuple the next flow for the same private tuple no
    // longer draws, so the removal has to re-check expiry under the lock, which means a mapping
    // that is live by the time the reaper gets there survives.
    #[test]
    fn a_mapping_that_is_live_again_survives_its_reaper() {
        let pool = narrow_budget_pool();
        let subscriber_ip = Ipv4Addr::from(u32::try_from(BASE).unwrap_or_else(|_| unreachable!()));
        let key = MappingKey::new(port(1), MappingScope::Independent);

        let mapping = pool
            .get_or_create_mapping(subscriber_ip, key, false, &TIMERS)
            .expect("the pool has room");
        let subscriber = pool
            .subscribers()
            .get(subscriber_ip)
            .expect("a subscriber row exists after the first mapping");

        // The pool's idle timeout is minutes, so this stands in for a refresh that landed while
        // the reaper was on its way to the lock
        assert!(!mapping.is_expired(), "sanity: the mapping is still live");
        let done = reap_expired_mapping(
            &subscriber,
            subscriber_ip,
            key,
            &mapping,
            pool.subscribers(),
        );

        assert!(
            subscriber.live_mapping(&key).is_some(),
            "the reaper removed a mapping that was live again by the time it took the lock"
        );
        assert!(
            pool.subscribers().get(subscriber_ip).is_some(),
            "the subscriber was reaped although it still holds a live mapping"
        );
        // We checked survival, but we're not done yet. Nothing else spawns a reaper for an
        // entry already in the table, so the entry would be left with no timer at all if its reaper
        // were told it was finished here.
        assert!(
            !done,
            "the reaper was told it was finished with a mapping it did not reap,
             so the entry keeps its port and its pinned address with nothing left to expire it"
        );

        // When the mapping really has expired, the reaper is finished
        let expired = pool_with_zero_timeout();
        let key2 = MappingKey::new(port(2), MappingScope::Independent);
        let doomed = expired
            .get_or_create_mapping(subscriber_ip, key2, false, &TIMERS)
            .expect("the pool has room");
        let owner = expired
            .subscribers()
            .get(subscriber_ip)
            .expect("a subscriber row exists after the first mapping");
        assert!(
            reap_expired_mapping(&owner, subscriber_ip, key2, &doomed, expired.subscribers()),
            "an expired mapping should be reaped, and its reaper told it is done"
        );
        assert!(owner.live_mapping(&key2).is_none());
    }

    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.1
    //= type=test
    //# REQ-2:  It is RECOMMENDED that a NAT have an "IP address pooling"
    //# behavior of "Paired".
    #[test]
    fn a_subscriber_prefers_its_own_still_open_address_over_a_reopened_earlier_one() {
        let pool = narrow_budget_pool();
        let address_a = Ipv4Addr::from(u32::try_from(BASE).unwrap_or_else(|_| unreachable!()));
        let address_b = Ipv4Addr::from(u32::try_from(BASE + 1).unwrap_or_else(|_| unreachable!()));

        // Exhaust address_a directly through the pool, simulating other subscribers' demand.
        // We have bare AllocatedPort objects, so dropping one later in the test releases it.
        let mut other_held = Vec::new();
        for _ in 0..BUDGET {
            let allocation = pool.allocate(false).expect("room for the other demand");
            assert_eq!(
                allocation.ip(),
                address_a,
                "sanity: exhausting address_a first"
            );
            other_held.push(allocation);
        }

        // The subscriber under test draws for the first time only after address_a is exhausted,
        // so it is pushed to address_b and has never touched address_a
        let subscriber = Subscriber::default();
        let first = subscriber
            .allocate_paired(&pool, false)
            .expect("room on address_b");
        assert_eq!(
            first.ip(),
            address_b,
            "sanity: the subscriber under test should have spilled straight to address_b"
        );

        // Someone else's allocation on address_a ends, reopening capacity there
        drop(other_held.remove(0));

        // A new draw for the subscriber under test must stay on its own address_b, which still has
        // room, rather than drifting onto the just-reopened address_a
        let second = subscriber
            .allocate_paired(&pool, false)
            .expect("room on address_b");
        assert_eq!(
            second.ip(),
            address_b,
            "the subscriber drifted onto a reopened address it had never used instead of staying on its own still-open one: \
             Paired pooling has regressed to plain pool-wide reuse"
        );
    }
}
