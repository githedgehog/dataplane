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
use concurrency::sync::atomic::Ordering;
use concurrency::sync::{Arc, RwLock};
use config::external::overlay::vpcpeering::MappingPolicy;
use dashmap::DashMap;
use net::flows::atomic_instant::AtomicInstant;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::time::{Duration, Instant};
#[cfg(not(any(feature = "shuttle", feature = "loom")))]
use tracing::debug;

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
    expires_at: AtomicInstant,
    idle_timeout: Duration,
}

impl<I: NatIpWithBitmap> Mapping<I> {
    fn new(allocation: AllocatedPort<I>, idle_timeout: Duration) -> Self {
        Self {
            allocation,
            expires_at: AtomicInstant::new(clock::now() + idle_timeout),
            idle_timeout,
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
        self.expires_at.load(Ordering::Relaxed)
    }

    fn is_expired(&self) -> bool {
        self.expires_at() <= clock::now()
    }

    // From RFC 4787 REQ-6, any outbound packet on any flow sharing a mapping refreshes it,
    // independent of that flow's own idle timer. The clock is monotonic, given that several flows
    // on different cores may refresh concurrently, and we must never make it go backwards.
    pub(crate) fn refresh(&self) {
        let new = clock::now() + self.idle_timeout;
        self.expires_at.fetch_max(new, Ordering::Relaxed);
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
        // `draw` produces the `AllocatedPort`, and is responsible for having whatever address it
        // picks associated to a subscriber (so this differs between drawing a fresh port and
        // re-reserving a known one)
        draw: impl FnOnce() -> Result<AllocatedPort<I>, AllocatorError>,
    ) -> Result<Arc<Mapping<I>>, AllocatorError> {
        // Lazy staleness check (common path)
        if let Some(existing) = self.live_mapping(&key) {
            return Ok(existing);
        }
        let mut guard = self.mappings.write();
        // Now that we grabbed the write lock, check again in case a racing thread created an entry
        // in the meantime
        if let Some(existing) = guard.get(&key).filter(|m| !m.is_expired()) {
            return Ok(existing.clone());
        }
        let mapping = Arc::new(Mapping::new(draw()?, pool.idle_timeout()));
        guard.insert(key, mapping.clone());
        drop(guard);
        spawn_mapping_reaper(
            self.clone(),
            src_ip,
            key,
            mapping.clone(),
            pool.subscribers().clone(),
        );
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
    ) -> Result<Arc<Mapping<I>>, AllocatorError> {
        self.get_or_insert_with(src_ip, key, pool, || self.allocate_paired(pool, allow_null))
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
    ) -> Result<Arc<Mapping<I>>, AllocatorError> {
        self.get_or_insert_with(src_ip, key, pool, || {
            let allocated = pool.reserve(ip, port)?;
            Self::pin_if_absent(&mut self.addresses.write(), allocated.allocated_ip());
            Ok(allocated)
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.mappings.read().is_empty()
    }
}

///////////////////////////////////////////////////////////////////////////////
// Reaping
///////////////////////////////////////////////////////////////////////////////

// The per-pool table of Subscribers, keyed by private address
#[derive(Debug, Clone)]
pub(crate) struct SubscribersTable<I: NatIpWithBitmap>(Arc<DashMap<I, Arc<Subscriber<I>>>>);

impl<I: NatIpWithBitmap> SubscribersTable<I> {
    pub(crate) fn new() -> Self {
        Self(Arc::new(DashMap::new()))
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
        self.0
            .remove_if(&ip, |_, v| Arc::ptr_eq(v, subscriber) && v.is_empty());
    }

    #[cfg(test)]
    pub(crate) fn get(&self, ip: I) -> Option<Arc<Subscriber<I>>> {
        self.0.get(&ip).map(|entry| entry.value().clone())
    }
}

// This method mirrors the shape of flow_entry::flow_table::table::FlowTable::start_timer. It is a
// per-mapping tokio task that:
//
// - sleeps to the current deadline
// - re-checks for a concurrent deadline extension, and expires the mapping otherwise
// - then reaps the owning Subscriber too if it is now empty, so a Paired-pooled address is not
//   pinned forever once nothing uses it any more
#[cfg(not(any(feature = "shuttle", feature = "loom")))]
fn spawn_mapping_reaper<I: NatIpWithBitmap>(
    subscriber: Arc<Subscriber<I>>,
    subscriber_ip: I,
    key: MappingKey<I>,
    mapping: Arc<Mapping<I>>,
    subscribers: SubscribersTable<I>,
) {
    if tokio::runtime::Handle::try_current().is_err() {
        debug!(
            // See simple staleness checks in Subscriber::get_or_insert_with()
            "No Tokio runtime on this thread; mapping for {subscriber_ip} will not be actively reaped, relying on lazy staleness checks"
        );
        return;
    }
    tokio::task::spawn(async move {
        let mut deadline = mapping.expires_at();
        loop {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            let new_deadline = mapping.expires_at();
            if new_deadline > deadline {
                deadline = new_deadline;
                continue;
            }
            break;
        }
        reap_expired_mapping(&subscriber, subscriber_ip, key, &mapping, &subscribers);
    });
}

// Drop the mapping from the subscriber's table (verifying identity so a concurrently-inserted
// replacement under the same key survives), then reap the subscriber itself if it is now empty
#[cfg_attr(feature = "loom", allow(dead_code))]
pub(crate) fn reap_expired_mapping<I: NatIpWithBitmap>(
    subscriber: &Arc<Subscriber<I>>,
    subscriber_ip: I,
    key: MappingKey<I>,
    mapping: &Arc<Mapping<I>>,
    subscribers: &SubscribersTable<I>,
) {
    // Remove the mapping, verifying identity so a concurrently-inserted replacement under the same
    // key survives.
    {
        let mut guard = subscriber.mappings.write();
        if guard
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, mapping))
        {
            guard.remove(&key);
        }
    }

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
}

#[cfg(any(feature = "shuttle", feature = "loom"))]
fn spawn_mapping_reaper<I: NatIpWithBitmap>(
    _subscriber: Arc<Subscriber<I>>,
    _subscriber_ip: I,
    _key: MappingKey<I>,
    _mapping: Arc<Mapping<I>>,
    _subscribers: SubscribersTable<I>,
) {
    // No task backend under shuttle/loom. Correctness under these modes relies entirely on the lazy
    // staleness check in Subscriber::{get_or_create,get_or_reserve} (via get_or_insert_with), which
    // never hands back a Mapping whose expiry time has already passed.
}

#[cfg(test)]
mod tests {
    use super::super::setup::{narrow_budget_specs, pool_sets_for_specs};
    use super::super::test_alloc::context::port;
    use super::*;
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
