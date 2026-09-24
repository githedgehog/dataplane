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
use net::flows::atomic_instant::AtomicInstant;
use shuttle_dashmap::DashMap;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
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
        // "draw" produces the AllocatedPort, and is responsible for having whatever address it
        // picks associated to a subscriber (so this differs between drawing a fresh port and
        // re-reserving a known one)
        //
        // Note that "draw" runs with this subscriber's "mappings" write lock held, so it must no
        // reach the pool's subscriber table: reaping takes that table's lock and then a
        // subscriber's mappings, so we'd risk a deadlock.
        draw: impl FnOnce() -> Result<AllocatedPort<I>, AllocatorError>,
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
        spawn_mapping_reaper(
            self.clone(),
            src_ip,
            key,
            mapping.clone(),
            pool.subscribers().clone(),
            pool.reaper_token(),
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
        let mapping = self.get_or_insert_with(src_ip, key, pool, || {
            let allocated = pool.reserve(ip, port)?;
            Self::pin_if_absent(&mut self.addresses.write(), allocated.allocated_ip());
            Ok(allocated)
        })?;
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
pub(crate) struct SubscribersTable<I: NatIpWithBitmap>(Arc<DashMap<I, Arc<Subscriber<I>>>>);

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

    #[cfg(test)]
    pub(crate) fn get(&self, ip: I) -> Option<Arc<Subscriber<I>>> {
        self.0.get(&ip).map(|entry| entry.value().clone())
    }
}

// Cancels every reaper a pool started, once the pool itself is gone.
//
// A reaper sleeps until its mapping's deadline, and it holds the Subscriber, the Mapping and the
// subscriber table alive while it does. Without a way to wake it, replacing the allocator on a
// config change leaves one parked task per live mapping until every one of those deadlines passes.
#[derive(Debug)]
pub(crate) struct ReaperShutdown(CancellationToken);

impl ReaperShutdown {
    pub(crate) fn new() -> Self {
        Self(CancellationToken::new())
    }

    pub(crate) fn token(&self) -> CancellationToken {
        self.0.clone()
    }
}

impl Drop for ReaperShutdown {
    fn drop(&mut self) {
        self.0.cancel();
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
    cancel: CancellationToken,
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
            tokio::select! {
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
                // The pool this mapping belongs to is gone, so there is nothing left to reap it
                // out of. Unwind now rather than holding the table alive until the deadline.
                () = cancel.cancelled() => return,
            }

            let new_deadline = mapping.expires_at();
            if new_deadline > deadline {
                deadline = new_deadline;
                continue;
            }
            if reap_expired_mapping(&subscriber, subscriber_ip, key, &mapping, &subscribers) {
                return;
            }
            // A refresh landed between that deadline check and the write lock, so the mapping kept
            // its entry. It has to keep this reaper too: no other path spawns one for an entry
            // already in the table.
            deadline = mapping.expires_at();
        }
    });
}

// Drop the mapping from the subscriber's table (verifying identity so a concurrently-inserted
// replacement under the same key survives), then reap the subscriber itself if it is now empty
//
// Return whether this reaper is finished with the mapping: true if the entry is gone (removed here
// or already replaced elsewhere), false if a refresh landed between the caller's deadline check and
// the write lock, meaning the entry is still live and the caller has to keep watching it.
#[cfg_attr(feature = "loom", allow(dead_code))]
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

#[cfg(any(feature = "shuttle", feature = "loom"))]
fn spawn_mapping_reaper<I: NatIpWithBitmap>(
    _subscriber: Arc<Subscriber<I>>,
    _subscriber_ip: I,
    _key: MappingKey<I>,
    _mapping: Arc<Mapping<I>>,
    _subscribers: SubscribersTable<I>,
    _cancel: CancellationToken,
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

    // A reaper sleeps until its mapping's deadline, holding the subscriber, the mapping and the
    // subscriber table alive. Replacing the allocator on a config change drops the pool those
    // belong to, and the reaper has to notice: otherwise every live mapping leaves a parked task
    // behind, and the old allocator's tables stay reachable, until its deadline passes.
    #[tokio::test]
    async fn dropping_a_pool_retires_the_reapers_it_started() {
        let metrics = tokio::runtime::Handle::current().metrics();
        let pool = narrow_budget_pool();
        let subscriber_ip = Ipv4Addr::from(u32::try_from(BASE).unwrap_or_else(|_| unreachable!()));
        let mapping = pool
            .get_or_create_mapping(
                subscriber_ip,
                MappingKey::new(port(1), MappingScope::Independent),
                false,
            )
            .expect("the pool has room");
        assert!(
            metrics.num_alive_tasks() > 0,
            "sanity: creating a mapping should have started a reaper"
        );

        // The mapping outlives the pool here, as a flow's own reference would
        drop(pool);

        for _ in 0..1024 {
            if metrics.num_alive_tasks() == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        drop(mapping);
        panic!(
            "{} reaper task(s) still parked after their pool was dropped",
            metrics.num_alive_tasks()
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

    // The reaper task re-reads the deadline before it decides to expire a mapping, but an outbound
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
            .get_or_create_mapping(subscriber_ip, key, false)
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
            .get_or_create_mapping(subscriber_ip, key2, false)
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
