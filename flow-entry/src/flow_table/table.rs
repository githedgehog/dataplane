// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ahash::RandomState;
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use concurrency::sync::{Arc, RwLock, RwLockReadGuard, Weak};
use dashmap::DashMap;
use net::FlowKey;
use net::flows::{FlowInfo, FlowStatus};
use std::borrow::Borrow;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::time::Duration;
use tracing::debug;

#[derive(Debug, thiserror::Error)]
pub enum FlowTableError {
    #[error("Flow table capacity exceeded")]
    CapacityExceeded,
}

#[derive(Debug)]
pub enum Insertion {
    Installed,
    Occupied(Arc<FlowInfo>),
}

/// Outcome of admitting a forward/reverse flow pair.
#[derive(Debug)]
pub enum PairInsertion {
    Installed,
    ForwardOccupied(Arc<FlowInfo>),
    ReverseOccupied,
}

enum Found {
    Inserted(Option<Arc<FlowInfo>>),
    Held(Arc<FlowInfo>),
    Refused(FlowTableError),
}

type Table = DashMap<FlowKey, Arc<FlowInfo>, RandomState>;

/// Counts an insertion before its entry can be removed. An unused reservation is returned.
struct SlotReservation<'a> {
    live: Option<&'a AtomicUsize>,
}

impl SlotReservation<'_> {
    /// Transfer the count to a newly published entry; its remover will decrement it.
    fn commit(mut self) {
        self.live = None;
    }
}

impl Drop for SlotReservation<'_> {
    fn drop(&mut self) {
        if let Some(live) = self.live {
            live.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
pub struct FlowTable {
    // TODO(mvachhar) move this to a cross beam sharded lock
    pub(crate) table: Arc<RwLock<Table>>,
    capacity: AtomicUsize,
    live: Arc<AtomicUsize>,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new(1024)
    }
}

fn hasher_state() -> &'static RandomState {
    use concurrency::sync::OnceLock;
    static HASHER_STATE: OnceLock<RandomState> = OnceLock::new();
    HASHER_STATE.get_or_init(|| RandomState::with_seeds(0, 0, 0, 0))
}

/// A read guard to the `FlowTable`, returned by the methods that iterate over it so a caller can
/// keep holding what the iteration held, without exposing the internal types.
///
/// It excludes resharding and pair admission. Single-entry insertion and removal take the same
/// read lock and can proceed alongside this guard. A caller that must not miss an insertion needs
/// the inserting side to re-check its work, as masquerade does after installing a flow pair.
pub struct FlowTableReadGuard<'a>(
    #[allow(unused)] RwLockReadGuard<'a, DashMap<FlowKey, Arc<FlowInfo>, RandomState>>,
);
impl Drop for FlowTableReadGuard<'_> {
    fn drop(&mut self) {
        debug!("Dropping flow-table read lock");
    }
}

impl FlowTable {
    /// Default capacity for the flow table: 10M.
    ///
    /// Use [`FlowTable::set_capacity`] to enforce a hard limit.
    pub const DEFAULT_CAPACITY: usize = 10_000_000;

    #[must_use]
    pub fn new(num_shards: usize) -> Self {
        Self {
            table: Arc::new(RwLock::new(Table::with_hasher_and_shard_amount(
                hasher_state().clone(),
                num_shards,
            ))),
            capacity: AtomicUsize::new(Self::DEFAULT_CAPACITY),
            live: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Set the hard capacity limit for the flow table.
    ///
    /// When entries and pending insertions reach this limit, new flow insertions will fail with
    /// [`FlowTableError::CapacityExceeded`]. A flow related to an active entry may exceed the limit
    /// so a forward/reverse pair can be completed.
    pub fn set_capacity(&self, capacity: usize) {
        self.capacity.store(capacity, Ordering::Relaxed);
    }

    /// Reshard the flow table into the given number of shards.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of shards is not a power of two.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table,
    /// or if the new number of shards is not a power of 2.
    pub fn reshard(&self, num_shards: usize) {
        assert!(
            num_shards.is_power_of_two(),
            "Shard number must be a power of 2!"
        );
        debug!(
            "reshard: Resharding flow table from {} shards into {} shards",
            self.table.read().shards().len(),
            num_shards
        );
        let mut locked_table = self.table.write();
        let new_table =
            DashMap::with_hasher_and_shard_amount(locked_table.hasher().clone(), num_shards);
        let old_table = std::mem::replace(&mut *locked_table, new_table);

        // Move all entries from the old table to the new table using raw_api
        for shard_lock in old_table.into_shards() {
            let mut shard = shard_lock.write();
            let drain_iter = shard.drain();
            for (k, v) in drain_iter {
                locked_table.insert(k, v.into_inner());
            }
        }
    }

    /// Add a flow to the table.
    ///
    /// # Returns
    ///
    /// Returns the old `Arc<FlowInfo>` associated with the flow key, if any.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table.
    ///
    /// # Errors
    ///
    /// Returns [`FlowTableError::CapacityExceeded`] when the table has reached its hard limit.
    pub fn insert(&self, flow_info: FlowInfo) -> Result<Option<Arc<FlowInfo>>, FlowTableError> {
        let val = Arc::new(flow_info);
        self.insert_common(&val)
    }

    /// Add a flow entry to the table from a `&Arc<FlowInfo>`
    ///
    /// # Returns
    ///
    /// Returns the old `Arc<FlowInfo>` associated with the flow key, if any.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table.
    ///
    /// # Errors
    ///
    /// Returns [`FlowTableError::CapacityExceeded`] when the table has reached its hard limit.
    pub fn insert_from_arc(
        &self,
        flow_info: &Arc<FlowInfo>,
    ) -> Result<Option<Arc<FlowInfo>>, FlowTableError> {
        self.insert_common(flow_info)
    }

    /// Start a timer task for a flow
    #[allow(unused)]
    fn start_timer(table: Arc<RwLock<Table>>, live: Arc<AtomicUsize>, flow_info: Arc<FlowInfo>) {
        tokio::task::spawn(async move {
            let table = table;
            let flow_key = flow_info.flowkey();
            let mut deadline = flow_info.expires_at();
            loop {
                tokio::select! {
                    () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        let status = flow_info.status();
                        if status != FlowStatus::Active {
                            debug!("Flow-timer[EXPIRED]: Flow {flow_key} is in status {status}");
                            break;
                        }
                        let new_deadline = flow_info.expires_at();
                        if new_deadline > deadline {
                            debug!("Flow-timer[EXTENDED] for Flow {flow_key}");
                            deadline = new_deadline;
                            continue;
                        }
                        debug!("Flow-timer[EXPIRED] for flow {flow_key}");
                        flow_info.update_status(FlowStatus::Expired);
                        break;
                    },
                    () = flow_info.token.cancelled() =>  {
                        debug!("Flow-timer[CANCELLED] for flow {flow_key}");
                        break;
                    },
                }
            }
            // no need to remove
            if flow_info.status() == FlowStatus::Detached {
                return;
            }

            // The timer for a flow expired or was cancelled. Therefore the flow should be removed.
            // We use remove_if + ptr_eq so that a concurrently-inserted replacement is left intact
            // and try_read() instead of read() so as not to block
            loop {
                if let Some(table) = table.try_read() {
                    let res = table.remove_if(flow_key, |_, v| Arc::ptr_eq(v, &flow_info));
                    if res.is_none() {
                        debug!("Flow-timer: Unable to remove flow {flow_key}: not found");
                    } else {
                        live.fetch_sub(1, Ordering::Relaxed);
                    }
                    return;
                }
                // Pair admission and resharding hold the outer write lock. Back off so a
                // contending writer cannot cause this task to spin a tokio worker.
                debug!("Flow-timer: Waiting for table read access");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
    }

    fn reserve(&self, val: &Arc<FlowInfo>) -> Option<SlotReservation<'_>> {
        let mut live = self.live.load(Ordering::Relaxed);
        loop {
            if live >= self.capacity.load(Ordering::Relaxed)
                && !val
                    .related
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .is_some_and(|rel| rel.is_active())
            {
                return None;
            }
            match self.live.compare_exchange_weak(
                live,
                live.checked_add(1)?,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(SlotReservation {
                        live: Some(&self.live),
                    });
                }
                Err(current) => live = current,
            }
        }
    }

    fn displace(old: Option<&Arc<FlowInfo>>) {
        let Some(old) = old else {
            return;
        };
        old.update_status(FlowStatus::Detached);
        old.token.cancel();
        if let Some(related) = old.related.as_ref().and_then(Weak::upgrade) {
            debug!("insert: invalidating the partner of a displaced flow");
            related.invalidate();
        }
    }

    fn insert_common(&self, val: &Arc<FlowInfo>) -> Result<Option<Arc<FlowInfo>>, FlowTableError> {
        let table = self.table.read();
        let flow_key = val.flowkey();
        debug!("insert: inserting flow {flow_key}");

        let reservation = self.reserve(val).ok_or(FlowTableError::CapacityExceeded)?;

        let result = table.insert(*flow_key, val.clone());
        if result.is_none() {
            reservation.commit();
        } else {
            drop(reservation);
        }
        // Set Active only after the insert so that the invariant holds: Active iff in the
        // table.  The narrow window where the entry is in the DashMap but not yet Active is
        // harmless: drain_stale's stale condition is (status != Active || expires_at <= now),
        // and a freshly inserted flow always has expires_at in the future.
        val.update_status(FlowStatus::Active);
        drop(table);

        #[cfg(not(any(feature = "shuttle", feature = "loom")))]
        Self::start_timer(self.table.clone(), self.live.clone(), val.clone());

        Self::displace(result.as_ref());

        let Some(ret) = result else {
            return Ok(None);
        };

        if ret.status() == FlowStatus::Expired {
            return Ok(None);
        }

        Ok(Some(ret))
    }

    /// # Errors
    ///
    /// Returns [`FlowTableError::CapacityExceeded`] if the key is free and the table is full.
    pub fn insert_if_absent(&self, val: &Arc<FlowInfo>) -> Result<Insertion, FlowTableError> {
        let table = self.table.read();
        let flow_key = val.flowkey();
        debug!("insert: inserting flow {flow_key} unless it is already held");

        // Reserve before publication so removal cannot decrement an uncounted entry. Even
        // without a reservation, an occupied key can be returned or replaced without growing
        // the table.
        let reservation = self.reserve(val);

        let previous = val.update_status(FlowStatus::Active);

        // Keep admission and reservation updates outside DashMap's entry guard: the facade
        // atomics can yield under Shuttle, while the shard lock is an unmodeled parking_lot
        // lock that can block another green thread on the same OS thread.
        let mut counted = false;
        let found = match table.entry(*flow_key) {
            dashmap::Entry::Occupied(mut occupied) => {
                if occupied.get().is_active() {
                    Found::Held(occupied.get().clone())
                } else {
                    Found::Inserted(Some(occupied.insert(val.clone())))
                }
            }
            dashmap::Entry::Vacant(vacant) => {
                if reservation.is_some() {
                    vacant.insert(val.clone());
                    counted = true;
                    Found::Inserted(None)
                } else {
                    Found::Refused(FlowTableError::CapacityExceeded)
                }
            }
        };
        if let Some(reservation) = reservation
            && counted
        {
            reservation.commit();
        }
        let displaced = match found {
            Found::Inserted(displaced) => displaced,
            Found::Held(held) => {
                val.update_status(previous);
                drop(table);
                debug!("insert: flow {flow_key} is already held by a live flow");
                return Ok(Insertion::Occupied(held));
            }
            Found::Refused(e) => {
                val.update_status(previous);
                drop(table);
                return Err(e);
            }
        };

        drop(table);

        #[cfg(not(any(feature = "shuttle", feature = "loom")))]
        Self::start_timer(self.table.clone(), self.live.clone(), val.clone());

        Self::displace(displaced.as_ref());

        Ok(Insertion::Installed)
    }

    /// Install a fresh related pair without replacing a live owner of either key.
    ///
    /// Check both keys and publish both entries under the table's write lock, so lookups and
    /// competing creators cannot use a half-installed pair. A forward owner takes precedence;
    /// otherwise a reverse collision leaves the table unchanged. As with single-entry admission,
    /// the reverse entry may exceed capacity to complete a pair.
    ///
    /// # Errors
    ///
    /// Returns [`FlowTableError::CapacityExceeded`] if the forward key is free and the table is full.
    ///
    /// # Panics
    ///
    /// Panics if the flows are not distinct, detached, and related to each other. The caller must
    /// not hold a table guard.
    pub fn insert_pair_if_absent(
        &self,
        forward: &Arc<FlowInfo>,
        reverse: &Arc<FlowInfo>,
    ) -> Result<PairInsertion, FlowTableError> {
        assert_ne!(forward.flowkey(), reverse.flowkey());
        for (flow, partner) in [(forward, reverse), (reverse, forward)] {
            assert_eq!(flow.status(), FlowStatus::Detached);
            assert!(
                flow.related
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .is_some_and(|related| Arc::ptr_eq(&related, partner))
            );
        }

        let table = self.table.write();
        let old_forward = table
            .get(forward.flowkey())
            .map(|entry| entry.value().clone());
        if let Some(held) = old_forward.as_ref().filter(|held| held.is_active()) {
            return Ok(PairInsertion::ForwardOccupied(held.clone()));
        }
        let old_reverse = table
            .get(reverse.flowkey())
            .map(|entry| entry.value().clone());
        if old_reverse.as_ref().is_some_and(|held| held.is_active()) {
            return Ok(PairInsertion::ReverseOccupied);
        }
        if old_forward.is_none()
            && self.live.load(Ordering::Relaxed) >= self.capacity.load(Ordering::Relaxed)
        {
            return Err(FlowTableError::CapacityExceeded);
        }

        // Removal also takes the outer lock, so neither entry can disappear before it is counted.
        let added = usize::from(old_forward.is_none()) + usize::from(old_reverse.is_none());
        self.live.fetch_add(added, Ordering::Relaxed);
        table.insert(*forward.flowkey(), forward.clone());
        table.insert(*reverse.flowkey(), reverse.clone());
        forward.update_status(FlowStatus::Active);
        reverse.update_status(FlowStatus::Active);
        drop(table);

        Self::displace(old_forward.as_ref());
        Self::displace(old_reverse.as_ref());
        #[cfg(not(any(feature = "shuttle", feature = "loom")))]
        for flow in [forward, reverse] {
            Self::start_timer(self.table.clone(), self.live.clone(), flow.clone());
        }
        Ok(PairInsertion::Installed)
    }

    /// Lookup a flow in the table.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table.
    pub fn lookup<Q>(&self, flow_key: &Q) -> Option<Arc<FlowInfo>>
    where
        FlowKey: Borrow<Q>,
        Q: Hash + Eq + ?Sized + Debug + Display,
    {
        debug!("lookup: Looking up flow key {flow_key}");
        let table = self.table.read();
        Some(table.get(flow_key)?.value().clone())
    }

    /// Remove a flow from the table.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table.
    pub fn remove<Q>(&self, flow_key: &Q) -> Option<(FlowKey, Arc<FlowInfo>)>
    where
        FlowKey: Borrow<Q>,
        Q: Hash + Eq + ?Sized + Debug + Display,
    {
        debug!("remove: Removing flow key {flow_key}");
        let table = self.table.read();
        let result = table.remove(flow_key);
        if result.is_some() {
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some((_key, flow_info)) = result.as_ref() {
            flow_info.update_status(FlowStatus::Detached);
            flow_info.token.cancel();
        }
        result
    }

    #[allow(clippy::len_without_is_empty)]
    /// The number of entries and pending insertion reservations, used for capacity checks without
    /// read-locking every `DashMap` shard.
    ///
    /// A reservation is counted before publication and returned if no new entry is added. Removal
    /// decrements after deleting the entry, so the count can temporarily include unfinished
    /// operations. It equals the physical entry count once all mutations finish.
    #[must_use]
    pub fn live_len(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Returns the total number of entries physically stored in the table, regardless of
    /// their expiration status.  This is mostly for testing.
    #[must_use]
    pub fn len(&self) -> Option<usize> {
        let table = self.table.try_read()?;
        Some(table.len())
    }

    /// Whether the table contains no entries, including expired entries. Returns `None` if a
    /// table lock is unavailable, as [`Self::len`] does.
    #[must_use]
    pub fn is_empty(&self) -> Option<bool> {
        let table = self.table.try_read()?;
        Some(table.is_empty())
    }

    /// Returns the number of *active* (non-expired, non-cancelled) flows in the table.
    /// This is mostly for testing.
    #[must_use]
    pub fn active_len(&self) -> Option<usize> {
        let table = self.table.try_read()?;
        Some(
            table
                .iter()
                .filter(|e| e.value().status() == FlowStatus::Active)
                .count(),
        )
    }

    /// Execute a function for each flow in the table. This locks the table for reading.
    ///
    /// # Panics
    ///
    /// This function panics if locking the table for reading fails
    pub fn for_each_flow<F>(&self, mut func: F) -> FlowTableReadGuard<'_>
    where
        F: FnMut(&FlowKey, &FlowInfo),
    {
        let guard = self.table.read();
        for flow in guard.iter() {
            func(flow.key(), &flow);
        }
        FlowTableReadGuard(guard)
    }

    /// Same as `for_each_flow`, but allowing a filter to iterate only over the flows that match a predicate
    ///
    /// # Panics
    ///
    /// This function panics if locking the table for reading fails
    pub fn for_each_flow_filtered<F, P>(&self, filter: P, mut func: F) -> FlowTableReadGuard<'_>
    where
        F: FnMut(&FlowKey, &FlowInfo),
        P: Fn(&FlowKey, &FlowInfo) -> bool,
    {
        let guard = self.table.read();
        for flow in guard.iter().filter(|flow| filter(flow.key(), flow)) {
            func(flow.key(), &flow);
        }
        FlowTableReadGuard(guard)
    }

    /// Build an iterator of all flows in the table. Depending on how costly the processing of `f` in `for_each_flow`
    /// is, taking a snapshot first may be faster. This is just possible because flow-info's are stored in 'Arc's.
    /// There is little to no advantage of returning an iterator here because this method allocates anyway.
    /// The snapshot can be restricted with the filter.
    ///
    /// # Panics
    ///
    /// This function panics if locking the table for reading fails
    pub fn snapshot<P>(&self, filter: P) -> impl Iterator<Item = Arc<FlowInfo>>
    where
        P: Fn(&FlowKey, &FlowInfo) -> bool,
    {
        let table = self.table.read();
        let v: Vec<_> = table
            .iter()
            .filter(|flow| filter(flow.key(), flow))
            .map(|f| f.value().clone())
            .collect();

        v.into_iter()
    }

    /// FIXME: this does not provide any advantage
    /// Need to interleave `reads()` with periods where we release lock/guard
    /// I.e. need to chunk it
    /// # Panics
    ///
    /// This function panics if locking the table for reading fails
    pub fn for_each_flow_sharded<F>(&self, f: F)
    where
        F: Fn(&FlowKey, &FlowInfo),
    {
        let table = self.table.read();
        for shard in table.shards() {
            let g = shard.read();
            unsafe {
                for (flowkey, flow_info) in g
                    .iter()
                    .map(|bucket| bucket.as_ref())
                    .map(|(key, val)| (key, val.get().as_ref()))
                {
                    f(flowkey, flow_info);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use concurrency::concurrency_mode;
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;

    use net::flows::flow_key::FlowAddrs;
    use net::ipv4::UnicastIpv4Addr;
    use net::{FlowKey, IpProtoKey, TcpProtoKey};

    fn v4_addrs(src: &str, dst: &str) -> FlowAddrs {
        FlowAddrs::V4 {
            src: UnicastIpv4Addr::new(src.parse().unwrap()).unwrap(),
            dst: UnicastIpv4Addr::new(dst.parse().unwrap()).unwrap(),
        }
    }

    #[concurrency_mode(std)]
    mod std_tests {
        use net::flows::FlowInfoFlags;
        use tracing_test::traced_test;

        use super::*;

        #[tokio::test]
        async fn test_flow_table_insert_and_remove() {
            let now = clock::now();
            let five_seconds = Duration::new(5, 0);
            let five_seconds_from_now = now + five_seconds;

            let flow_table = FlowTable::default();
            let flow_key = FlowKey::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                v4_addrs("1.2.3.4", "4.5.6.7"),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1025).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            );

            let flow_info = FlowInfo::new(flow_key, five_seconds_from_now);

            flow_table.insert(flow_info).unwrap();
            let result = flow_table.remove(&flow_key).unwrap();
            assert_eq!(result.0, flow_key);
        }

        // start_paused so the timer task's sleep_until and the test's sleeps share tokio's
        // virtual clock; otherwise miri's slow interpretation can drift the wall clock far
        // enough between Instant::now() and the first sleep that the deadline elapses early.
        // Anchor `now` on the virtual clock too -- a std::Instant::now() here would be many
        // real-time seconds past the paused baseline under miri, putting the deadline beyond
        // any virtual-time advance the test performs.
        #[tokio::test(start_paused = true)]
        async fn test_flow_table_timeout() {
            let now = clock::now();
            let two_seconds = Duration::from_secs(2);
            let one_second = Duration::from_secs(1);

            let flow_table = FlowTable::default();
            let flow_key = FlowKey::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(42).unwrap())),
                v4_addrs("10.0.0.1", "10.0.0.2"),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1234).unwrap(),
                    dst_port: TcpPort::new_checked(5678).unwrap(),
                }),
            );

            let flow_info = FlowInfo::new(flow_key, now + two_seconds);
            flow_table.insert(flow_info).unwrap();

            // Wait 1 second — flow not yet expired, lookup should return Some.
            tokio::time::sleep(one_second).await;
            assert!(
                flow_table.lookup(&flow_key).is_some(),
                "Flow key should still be present after 1 second"
            );

            // Wait another 2 seconds (total 3s) — flow expired. It should be gone
            tokio::time::sleep(two_seconds).await;
            assert!(flow_table.lookup(&flow_key).is_none());
            assert_eq!(flow_table.live_len(), 0);
        }

        #[tokio::test]
        async fn test_flow_table_entry_replaced_on_insert() {
            let now = clock::now();
            let first_expiry_time = now + Duration::from_secs(5);
            let second_expiry_time = now + Duration::from_secs(10);

            let flow_table = FlowTable::default();
            let flow_key = FlowKey::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                v4_addrs("1.2.3.4", "4.5.6.7"),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1025).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            );

            // Insert first entry.
            let first_arc = Arc::new(FlowInfo::new(flow_key, first_expiry_time));
            flow_table.insert_from_arc(&first_arc).unwrap();

            // The entry stored in the table should be the first arc.
            {
                let table = flow_table.table.read();
                let entry = table
                    .get(&flow_key)
                    .expect("entry should exist after first insert");
                assert_eq!(entry.value().expires_at(), first_expiry_time);
            }

            // Insert a second entry under the same key.
            let second_arc = Arc::new(FlowInfo::new(flow_key, second_expiry_time));
            flow_table.insert_from_arc(&second_arc).unwrap();

            // The table should now point to the second entry.
            {
                let table = flow_table.table.read();
                let entry = table
                    .get(&flow_key)
                    .expect("entry should exist after second insert");
                assert_ne!(entry.value().expires_at(), first_expiry_time);

                assert_eq!(entry.value().expires_at(), second_expiry_time);
            }
        }

        #[tokio::test]
        async fn test_flow_table_remove_bolero() {
            bolero::check!()
                .with_type::<FlowKey>()
                .cloned()
                .for_each(|flow_key| {
                    let flow_table = FlowTable::default();
                    // Use a future expiry so the flow stays active long enough for remove().
                    flow_table
                        .insert(FlowInfo::new(
                            flow_key,
                            clock::now() + Duration::from_mins(1),
                        ))
                        .unwrap();
                    let flow_info = flow_table.lookup(&flow_key).unwrap();
                    assert!(flow_table.lookup(&flow_key.reverse(None)).is_none());

                    let result = flow_table.remove(&flow_key);
                    assert!(result.is_some());
                    let (k, v) = result.unwrap();
                    assert_eq!(k, flow_key);
                    assert!(Arc::ptr_eq(&v, &flow_info));
                    assert!(flow_table.lookup(&flow_key).is_none());
                });
        }

        #[tokio::test]
        #[cfg_attr(not(emulated), traced_test)]
        // tokio::time::sleep counts wall-clock seconds, so a 4s sleep under miri's slow
        // interpreter elapses many real-world seconds and the "extended" flow's std::Instant
        // deadline gets passed too. Fixing this would require running on tokio's paused
        // clock, but the per-flow timer task uses tokio::time::Instant::from_std on a
        // wall-clock std deadline; mixing virtual and real instants is messy. Revisit.
        #[cfg_attr(
            miri,
            ignore = "wall-clock sleep + std::Instant deadlines don't survive miri"
        )]
        /// Test that invalidating flows causes timer to expire and flows to be removed
        async fn test_flow_table_flow_invalidation() {
            const NUM_FLOWS: u16 = 10;
            let flow_table = FlowTable::default();
            let now = clock::now();
            let deadline = now + Duration::from_secs(3);

            let mut flow_keys = vec![];
            for src_port in 1..=NUM_FLOWS {
                let flow_key = FlowKey::new(
                    Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                    v4_addrs("1.2.3.4", "4.5.6.7"),
                    IpProtoKey::Tcp(TcpProtoKey {
                        src_port: TcpPort::new_checked(src_port).unwrap(),
                        dst_port: TcpPort::new_checked(2048).unwrap(),
                    }),
                );
                let flow_info = FlowInfo::new(flow_key, deadline);
                flow_table.insert(flow_info).unwrap();
                flow_keys.push(flow_key);
            }
            // all flows in table
            assert_eq!(flow_table.active_len().unwrap(), NUM_FLOWS.into());

            // look up all flows and: 1) invalidate one 2) extend the deadline of another one
            for (num, flow_key) in flow_keys.iter().enumerate() {
                let flow = flow_table.lookup(flow_key).unwrap();
                match num {
                    1 => flow.invalidate(),
                    2 => flow.extend_expiry(Duration::from_secs(2)).unwrap(),
                    _ => {}
                }
            }
            // invalidated should be gone
            assert_eq!(flow_table.active_len().unwrap(), (NUM_FLOWS - 1).into());

            // wait 4 > 3 seconds. All except the one extended should be gone
            tokio::time::sleep(Duration::from_secs(4)).await;
            assert_eq!(flow_table.active_len().unwrap(), 1);
        }

        #[tokio::test]
        #[cfg_attr(not(emulated), traced_test)]
        /// Test that invalidating flows causes timer to expire and flows to be removed
        async fn test_flow_table_flow_reinsertion() {
            let flow_table = FlowTable::default();
            let now = clock::now();
            let deadline = now + Duration::from_secs(2);

            let flow_key = FlowKey::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                v4_addrs("1.2.3.4", "4.5.6.7"),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            );
            let flow_info = FlowInfo::new(flow_key, deadline);
            flow_table.insert(flow_info).unwrap();

            let flow_info = FlowInfo::new(flow_key, deadline + Duration::from_secs(2));
            let old = flow_table.insert(flow_info).unwrap();
            assert!(old.is_some());
            assert_eq!(old.unwrap().expires_at(), deadline);
            assert_eq!(flow_table.active_len().unwrap(), 1);

            let () = tokio::time::sleep(Duration::from_secs(5)).await;
            assert_eq!(flow_table.active_len().unwrap(), 0);
            assert_eq!(flow_table.live_len(), 0);
        }

        #[tokio::test]
        async fn the_live_counter_tracks_what_the_table_holds() {
            let flow_table = FlowTable::default();
            let far_future = clock::now() + Duration::from_hours(1);
            let keys: Vec<FlowKey> = (0u16..8).map(|i| key_for(3000 + i)).collect();

            for key in &keys {
                flow_table
                    .insert_from_arc(&Arc::new(FlowInfo::new(*key, far_future)))
                    .unwrap();
            }
            assert_eq!(flow_table.live_len(), flow_table.len().unwrap());

            for key in keys.iter().take(3) {
                flow_table.remove(key);
            }
            assert_eq!(flow_table.live_len(), flow_table.len().unwrap());

            let held = Arc::new(FlowInfo::new(keys[4], far_future));
            flow_table.insert_from_arc(&held).unwrap();
            assert_eq!(
                flow_table.live_len(),
                flow_table.len().unwrap(),
                "replacing an existing key must not change the count"
            );

            let fresh = Arc::new(FlowInfo::new(key_for(4999), far_future));
            assert!(matches!(
                flow_table.insert_if_absent(&fresh).unwrap(),
                Insertion::Installed
            ));
            assert_eq!(flow_table.live_len(), flow_table.len().unwrap());

            let second = Arc::new(FlowInfo::new(key_for(4999), far_future));
            assert!(matches!(
                flow_table.insert_if_absent(&second).unwrap(),
                Insertion::Occupied(_)
            ));
            assert_eq!(
                flow_table.live_len(),
                flow_table.len().unwrap(),
                "reusing a live flow must not change the count"
            );
        }

        fn key_for(src_port: u16) -> FlowKey {
            FlowKey::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                v4_addrs("1.2.3.4", "4.5.6.7"),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(src_port).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            )
        }

        #[tokio::test]
        async fn an_active_flow_holds_its_key_against_a_second_insertion() {
            let flow_table = FlowTable::default();
            let key = key_for(1025);
            let far_future = clock::now() + Duration::from_hours(1);

            let first = Arc::new(FlowInfo::new(key, far_future));
            assert!(matches!(
                flow_table.insert_if_absent(&first).unwrap(),
                Insertion::Installed
            ));

            let second = Arc::new(FlowInfo::new(key, far_future));
            let outcome = flow_table.insert_if_absent(&second).unwrap();
            let Insertion::Occupied(held) = outcome else {
                panic!("a live flow was displaced by a second insertion: {outcome:?}");
            };
            assert!(Arc::ptr_eq(&held, &first), "the wrong flow was reported");
            assert_eq!(flow_table.live_len(), 1);

            let found = flow_table.lookup(&key).expect("the key is still served");
            assert!(Arc::ptr_eq(&found, &first));
            assert_ne!(second.status(), FlowStatus::Active);
        }

        #[tokio::test]
        async fn a_full_table_still_reports_the_flow_that_holds_a_key() {
            let flow_table = FlowTable::default();
            flow_table.set_capacity(1);
            let key = key_for(1029);
            let far_future = clock::now() + Duration::from_hours(1);

            let first = Arc::new(FlowInfo::new(key, far_future));
            assert!(matches!(
                flow_table.insert_if_absent(&first).unwrap(),
                Insertion::Installed
            ));

            let second = Arc::new(FlowInfo::new(key, far_future));
            let outcome = flow_table
                .insert_if_absent(&second)
                .expect("a key a live flow holds is not a capacity question");
            let Insertion::Occupied(held) = outcome else {
                panic!("a live flow was displaced by a second insertion: {outcome:?}");
            };
            assert!(Arc::ptr_eq(&held, &first), "the wrong flow was reported");
        }

        #[tokio::test]
        async fn a_full_table_refuses_a_free_key() {
            let flow_table = FlowTable::default();
            flow_table.set_capacity(1);
            let far_future = clock::now() + Duration::from_hours(1);

            let first = Arc::new(FlowInfo::new(key_for(1030), far_future));
            flow_table.insert_if_absent(&first).unwrap();

            let second = Arc::new(FlowInfo::new(key_for(1031), far_future));
            assert!(
                matches!(
                    flow_table.insert_if_absent(&second),
                    Err(FlowTableError::CapacityExceeded)
                ),
                "a full table grew for a key nobody held"
            );
            assert_eq!(flow_table.live_len(), 1);
        }

        #[tokio::test]
        async fn a_flow_that_is_not_live_is_displaced() {
            let flow_table = FlowTable::default();
            let key = key_for(1026);
            let far_future = clock::now() + Duration::from_hours(1);

            let first = Arc::new(FlowInfo::new(key, far_future));
            flow_table.insert_if_absent(&first).unwrap();
            first.invalidate();
            flow_table.set_capacity(1);

            let second = Arc::new(FlowInfo::new(key, far_future));
            assert!(
                matches!(
                    flow_table.insert_if_absent(&second).unwrap(),
                    Insertion::Installed
                ),
                "a flow that was no longer live held its key"
            );
            let found = flow_table.lookup(&key).expect("the key is served");
            assert!(Arc::ptr_eq(&found, &second));
            assert_eq!(flow_table.live_len(), 1);
        }

        #[tokio::test]
        async fn a_related_pair_can_complete_at_capacity() {
            for arbitrate in [false, true] {
                let flow_table = FlowTable::new(2);
                flow_table.set_capacity(1);
                let (forward, reverse) = FlowInfo::related_pair(
                    clock::now() + Duration::from_hours(1),
                    key_for(1040),
                    FlowInfoFlags::INITIATOR,
                    key_for(1041),
                    FlowInfoFlags::default(),
                )
                .unwrap();

                for flow in [&forward, &reverse] {
                    if arbitrate {
                        assert!(matches!(
                            flow_table.insert_if_absent(flow).unwrap(),
                            Insertion::Installed
                        ));
                    } else {
                        flow_table.insert_from_arc(flow).unwrap();
                    }
                }
                assert_eq!(flow_table.live_len(), 2);
                assert_eq!(flow_table.len(), Some(2));
            }
        }

        #[tokio::test]
        async fn displacing_a_flow_invalidates_its_partner() {
            let flow_table = FlowTable::default();
            let (forward_key, reverse_key) = (key_for(1027), key_for(1028));
            let far_future = clock::now() + Duration::from_hours(1);

            let (forward, reverse) = FlowInfo::related_pair(
                far_future,
                forward_key,
                FlowInfoFlags::INITIATOR,
                reverse_key,
                FlowInfoFlags::default(),
            )
            .expect("related_pair should succeed for distinct keys");
            flow_table.insert_from_arc(&forward).unwrap();
            flow_table.insert_from_arc(&reverse).unwrap();
            assert!(reverse.is_active());

            let replacement = Arc::new(FlowInfo::new(forward_key, far_future));
            flow_table.insert_from_arc(&replacement).unwrap();

            assert!(
                !reverse.is_active(),
                "the partner of a displaced flow was left live in the table"
            );
        }

        #[tokio::test]
        async fn test_flow_table_capacity_exceeded() {
            let flow_table = FlowTable::default();
            flow_table.set_capacity(2);

            let src_vpcd = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
            let addrs = v4_addrs("1.2.3.4", "5.6.7.8");
            let far_future = clock::now() + Duration::from_hours(1);

            // Insert up to the capacity limit — both should succeed.
            for i in 1u16..=2 {
                let src_port = TcpPort::new_checked(1000 + i).unwrap();
                let dst_port = TcpPort::new_checked(80).unwrap();
                let flow_key = FlowKey::new(
                    Some(src_vpcd),
                    addrs,
                    IpProtoKey::Tcp(TcpProtoKey { src_port, dst_port }),
                );
                flow_table
                    .insert(FlowInfo::new(flow_key, far_future))
                    .expect("insert under capacity should succeed");
            }

            // One more insert must fail with CapacityExceeded.
            let overflow_key = FlowKey::new(
                Some(src_vpcd),
                addrs,
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(9999).unwrap(),
                    dst_port: TcpPort::new_checked(80).unwrap(),
                }),
            );
            assert!(matches!(
                flow_table.insert(FlowInfo::new(overflow_key, far_future)),
                Err(FlowTableError::CapacityExceeded)
            ));
        }
    }

    // Shuttle-only: timers are bypassed there, and loom cannot clean up DashMap.
    #[cfg(all(feature = "shuttle", not(feature = "loom")))]
    mod concurrency_tests {
        use super::*;
        use crate::flow_table::FlowInfo;
        use concurrency::sync::Arc;
        use concurrency::thread;

        fn check_live_count_during_insert_and_remove(arbitrate: bool) {
            let scheduler = shuttle::scheduler::RandomScheduler::new_from_seed(0, 256);
            shuttle::Runner::new(scheduler, concurrency::shuttle_config()).run(move || {
                let flow_table = Arc::new(FlowTable::new(2));
                flow_table.set_capacity(1);
                let key = FlowKey::new(
                    Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                    v4_addrs("1.2.3.4", "5.6.7.8"),
                    IpProtoKey::Tcp(TcpProtoKey {
                        src_port: TcpPort::new_checked(1025).unwrap(),
                        dst_port: TcpPort::new_checked(2048).unwrap(),
                    }),
                );
                let deadline = clock::now() + Duration::from_hours(1);
                let inserting = flow_table.clone();
                let worker = thread::spawn(move || {
                    let flow = Arc::new(FlowInfo::new(key, deadline));
                    if arbitrate {
                        assert!(matches!(
                            inserting.insert_if_absent(&flow).unwrap(),
                            Insertion::Installed
                        ));
                    } else {
                        inserting.insert_from_arc(&flow).unwrap();
                    }
                });

                if flow_table.remove(&key).is_some() {
                    assert_eq!(
                        flow_table.live_len(),
                        0,
                        "removing the only entry must not wrap the live count"
                    );
                    let next = Arc::new(FlowInfo::new(key.reverse(None), deadline));
                    assert!(matches!(
                        flow_table.insert_if_absent(&next).unwrap(),
                        Insertion::Installed
                    ));
                }

                worker.join().unwrap();
                assert_eq!(flow_table.live_len(), flow_table.len().unwrap());
            });
        }

        #[test]
        fn live_count_during_insert_and_remove_shuttle() {
            check_live_count_during_insert_and_remove(false);
        }

        #[test]
        fn live_count_during_insert_if_absent_and_remove_shuttle() {
            check_live_count_during_insert_and_remove(true);
        }

        #[concurrency::test]
        fn concurrent_insertions_reserve_the_last_slot() {
            let flow_table = Arc::new(FlowTable::new(2));
            flow_table.set_capacity(1);
            let key = FlowKey::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                v4_addrs("1.2.3.4", "5.6.7.8"),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1025).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            );
            let deadline = clock::now() + Duration::from_hours(1);
            let inserting = flow_table.clone();
            let worker =
                thread::spawn(move || inserting.insert(FlowInfo::new(key, deadline)).is_ok());
            let second = Arc::new(FlowInfo::new(key.reverse(None), deadline));
            let second_admitted = flow_table.insert_if_absent(&second).is_ok();
            assert_ne!(
                worker.join().unwrap(),
                second_admitted,
                "exactly one insertion can claim the last slot"
            );
            assert_eq!(flow_table.live_len(), 1);
            assert_eq!(flow_table.len(), Some(1));
        }

        #[allow(clippy::too_many_lines)]
        #[concurrency::test]
        #[cfg_attr(not(emulated), tracing_test::traced_test)]
        fn test_flow_table_concurrent_insert_remove_lookup_expire() {
            const N: usize = 3;

            let two_seconds = Duration::from_secs(2);
            let flow_keys: Vec<_> = (0u16..2u16)
                .map(|i| {
                    FlowKey::new(
                        Some(VpcDiscriminant::VNI(
                            Vni::new_checked(u32::from(i) + 1).unwrap(),
                        )),
                        v4_addrs(&format!("10.0.{i}.1"), &format!("10.0.{i}.2")),
                        IpProtoKey::Tcp(TcpProtoKey {
                            src_port: TcpPort::new_checked(1000 + i).unwrap(),
                            dst_port: TcpPort::new_checked(2000 + i).unwrap(),
                        }),
                    )
                })
                .collect();

            let flow_table = Arc::new(FlowTable::default());

            let now = clock::now();

            // Insert the first flow
            let orig_flow_info = FlowInfo::new(flow_keys[0], now + two_seconds);
            flow_table.insert(orig_flow_info).unwrap();
            let flow_info = flow_table.lookup(&flow_keys[0]).unwrap();

            // This holder will retain the Arc until the inserter thread starts
            let mut flow_info_holder = Some(flow_info);

            let mut handles = vec![];

            // "expirer" thread — simulates what the tokio timer would do.
            handles.push(
                thread::Builder::new()
                    .name("expirer".to_string())
                    .spawn({
                        let flow_table = flow_table.clone();
                        let flow_key = flow_keys[0];
                        move || {
                            for _ in 0..N {
                                thread::yield_now();
                                if let Some(fi) = flow_table.lookup(&flow_key) {
                                    fi.update_status(FlowStatus::Expired);
                                }
                            }
                        }
                    })
                    .unwrap(),
            );

            handles.push(
                thread::Builder::new()
                    .name("inserter".to_string())
                    .spawn({
                        let flow_table = flow_table.clone();
                        let flow_info = flow_info_holder.take();
                        move || {
                            for _ in 0..N {
                                if let Some(flow_info) = flow_info.as_ref() {
                                    flow_table.insert_from_arc(flow_info).unwrap();
                                }
                                thread::yield_now();
                            }
                        }
                    })
                    .unwrap(),
            );

            handles.push(
                thread::Builder::new()
                    .name("remover".to_string())
                    .spawn({
                        let flow_table = flow_table.clone();
                        let flow_key = flow_keys[1];
                        move || {
                            for _ in 0..N {
                                thread::yield_now();
                                flow_table.remove(&flow_key);
                            }
                        }
                    })
                    .unwrap(),
            );

            handles.push(
                thread::Builder::new()
                    .name("lookup_and_lock".to_string())
                    .spawn({
                        let flow_table = flow_table.clone();
                        let flow_key = flow_keys[1];
                        move || {
                            for _ in 0..N {
                                thread::yield_now();
                                if let Some(flow_info) = flow_table.lookup(&flow_key) {
                                    let _guard = flow_info.locked.write();
                                }
                            }
                        }
                    })
                    .unwrap(),
            );

            for handle in handles {
                handle.join().unwrap();
            }

            // After all threads, flow[0] should be expired/gone (expirer thread ran).
            // Since timers are not started in shuttle tests, the flow should be there
            // but appear as Expired or Detached. Re-inserting a flow makes it active again,
            // therefore, the only non-feasible status is Cancellled.
            let found = flow_table.lookup(&flow_keys[0]).unwrap();
            assert_ne!(found.status(), FlowStatus::Cancelled);
        }

        #[concurrency::test]
        fn test_flow_table_reshard() {
            let flow_table = Arc::new(FlowTable::default());

            let five_seconds_from_now = clock::now() + Duration::from_secs(5);
            let flow_key1 = FlowKey::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                v4_addrs("1.2.3.4", "4.5.6.7"),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1025).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            );

            let flow_key2 = FlowKey::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(10).unwrap())),
                v4_addrs("10.2.3.4", "40.5.6.7"),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1025).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            );

            let flow_table_clone1 = flow_table.clone();
            let flow_table_clone2 = flow_table.clone();
            let flow_table_clone3 = flow_table.clone();

            let mut handles = vec![];

            handles.push(thread::spawn(move || {
                let flow_info = FlowInfo::new(flow_key1, five_seconds_from_now);
                flow_table_clone1.insert(flow_info).unwrap();
                let result = flow_table_clone1.remove(&flow_key1).unwrap();
                assert_eq!(result.0, flow_key1);
            }));

            handles.push(thread::spawn(move || {
                let flow_info = FlowInfo::new(flow_key2, five_seconds_from_now);
                flow_table_clone2.insert(flow_info).unwrap();
                let result = flow_table.remove(&flow_key2).unwrap();
                assert_eq!(result.0, flow_key2);
            }));

            handles.push(thread::spawn(move || flow_table_clone3.reshard(128)));

            let _results: Vec<()> = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect();
        }
    }
}
