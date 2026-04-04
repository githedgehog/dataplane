// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ahash::RandomState;
use dashmap::DashMap;
use net::FlowKey;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::Hash;
use std::time::Instant;
use tracing::debug;

use concurrency::sync::{Arc, RwLock, RwLockReadGuard};

use net::flows::{FlowInfo, FlowStatus};

#[derive(Debug, thiserror::Error)]
pub enum FlowTableError {
    #[error("Invalid number of shards: {0}. Must be a power of two.")]
    InvalidShardCount(usize),
}

type Table = DashMap<FlowKey, Arc<FlowInfo>, RandomState>;

#[derive(Debug)]
pub struct FlowTable {
    // TODO(mvachhar) move this to a cross beam sharded lock
    //
    // We need to push table lock ref down into tokio tasks
    // so invoked timer cleans up the table entry instead of just marking
    // the flow info expired and leaving cleanup to lazy expiration in lookup().
    pub(crate) table: Arc<RwLock<Table>>,
    reap_threshold: usize,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new(1024)
    }
}

fn hasher_state() -> &'static RandomState {
    use std::sync::OnceLock;
    static HASHER_STATE: OnceLock<RandomState> = OnceLock::new();
    HASHER_STATE.get_or_init(|| RandomState::with_seeds(0, 0, 0, 0))
}

impl FlowTable {
    /// When the raw `DashMap` entry count exceeds this threshold, `insert_common` will
    /// proactively purge all stale (Expired / Cancelled / deadline-passed) entries to
    /// prevent unbounded memory growth.
    pub const AGGRESSIVE_REAP_THRESHOLD: usize = 1_000_000;

    #[must_use]
    pub fn new(num_shards: usize) -> Self {
        Self {
            table: Arc::new(RwLock::new(Table::with_hasher_and_shard_amount(
                hasher_state().clone(),
                num_shards,
            ))),
            reap_threshold: Self::AGGRESSIVE_REAP_THRESHOLD,
        }
    }

    pub fn set_reap_threshold(&mut self, reap_threshold: usize) {
        self.reap_threshold = reap_threshold;
    }

    /// Reshard the flow table into the given number of shards.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of shards is not a power of two.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table or
    /// if the table lock is poisoned.
    pub fn reshard(&self, num_shards: usize) -> Result<(), FlowTableError> {
        if !num_shards.is_power_of_two() {
            return Err(FlowTableError::InvalidShardCount(num_shards));
        }
        debug!(
            "reshard: Resharding flow table from {} shards into {} shards",
            self.table.read().unwrap().shards().len(),
            num_shards
        );
        let mut locked_table = self.table.write().unwrap();
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
        Ok(())
    }

    /// Add a flow to the table.
    ///
    /// # Returns
    ///
    /// Returns the old `Arc<FlowInfo>` associated with the flow key, if any.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - this thread already holds the read lock on the table orif the table lock is poisoned.
    ///  - if the `flow_info` to insert has a key different from `flow_key`
    ///
    pub fn insert(&self, flow_key: FlowKey, mut flow_info: FlowInfo) -> Option<Arc<FlowInfo>> {
        // if the flow_info embeds its key already, it must match `flow_key`
        flow_info.flowkey().inspect(|key| {
            assert_eq!(
                *key, &flow_key,
                "Attempted to insert a flow with key: {key} with a distinct key: {flow_key}"
            );
        });

        // embed the key in the flow if it did not provide one
        if flow_info.flowkey().is_none() {
            flow_info.set_flowkey(flow_key);
        }

        debug!("Inserting flow {flow_key}");
        let val = Arc::new(flow_info);
        self.insert_common(flow_key, &val)
    }

    /// Add a flow entry to the table from a `&Arc<FlowInfo>`
    ///
    /// # Returns
    ///
    /// Returns the old `Arc<FlowInfo>` associated with the flow key, if any.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///   - this thread already holds the read lock on the table or if the table lock is poisoned.
    ///   - if the `flow_info` to insert has a key different from `flow_key`
    pub fn insert_from_arc(
        &self,
        flow_key: FlowKey,
        flow_info: &Arc<FlowInfo>,
    ) -> Option<Arc<FlowInfo>> {
        flow_info.flowkey().inspect(|key| {
            assert_eq!(
                *key, &flow_key,
                "Attempted to insert a flow with key: {key} with a distinct key: {flow_key}"
            );
        });
        debug!("insert: Inserting flow {flow_key}");
        self.insert_common(flow_key, flow_info)
    }

    /// Add a flow to the table via an Arc
    ///
    /// This is intended to re-add a flow to the flow table via the Arc returned from
    /// lookup, but it can be used with a fresh Arc as well.
    ///
    /// # Returns
    ///
    /// Returns the old `Arc<FlowInfo>` associated with the flow key, if any.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table or
    /// if the table lock is poisoned.
    pub fn reinsert(&self, flow_key: FlowKey, flow_info: &Arc<FlowInfo>) -> Option<Arc<FlowInfo>> {
        debug!("reinsert: Re-inserting flow key {flow_key}");
        self.insert_common(flow_key, flow_info)
    }

    /// Start a timer task for a flow
    fn start_timer(table: Arc<RwLock<Table>>, flow_info: Arc<FlowInfo>) {
        tokio::task::spawn(async move {
            let table = table;
            let flow_info = flow_info;
            let flow_key = flow_info.flowkey().unwrap_or_else(|| unreachable!()); // flows have key when inserted
            let mut deadline = flow_info.expires_at();
            loop {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                let status = flow_info.status();
                if status != FlowStatus::Active {
                    debug!("Flow {flow_key} is in status {status}");
                    break;
                }
                let new_deadline = flow_info.expires_at();
                if new_deadline > deadline {
                    deadline = new_deadline;
                    continue;
                }
                debug!("Timer for flow {flow_key} expired");
                flow_info.update_status(FlowStatus::Expired);
                break;
            }
            // Reached on every break (normal expiry or Cancelled/Expired early exit).
            // `continue` bypasses this, so removal only fires when the loop terminates.
            // Use remove_if + ptr_eq so a concurrently inserted replacement is left intact.
            // Use try_read() rather than read() to avoid undefined behaviour on
            // platforms where re-entrant locking may panic.  In practice the
            // write lock is only held by reshard(), which is synchronous and
            // never yields to the tokio executor, so WouldBlock is virtually
            // never observed; yield_now() is purely defensive.
            #[cfg(not(feature = "shuttle"))]
            let table = loop {
                // Evaluate try_read() and fully consume the Result before any
                // await point; RwLockReadGuard is !Send and must not be held
                // across an await even inside a non-Ok arm.
                let would_block = match table.try_read() {
                    Ok(guard) => break guard,
                    Err(std::sync::TryLockError::Poisoned(p)) => {
                        debug!(
                            "flow expiration task: FlowTable RwLock poisoned; \
                                     proceeding with possibly inconsistent table state"
                        );
                        break p.into_inner();
                    }
                    Err(std::sync::TryLockError::WouldBlock) => true,
                };
                // The Result (and any contained guard) is dropped here.
                if would_block {
                    tokio::task::yield_now().await;
                }
            };
            // shuttle::sync does not export TryLockError, and the timer task
            // never runs under shuttle (no tokio runtime), so we fall back to
            // the plain read() there.
            #[cfg(feature = "shuttle")]
            let table = table.read().unwrap_or_else(|poisoned| {
                debug!(
                    "flow expiration task: FlowTable RwLock poisoned; \
                             proceeding with possibly inconsistent table state"
                );
                poisoned.into_inner()
            });

            debug!("Removing flow {flow_key}:{flow_info}...");
            if table
                .remove_if(flow_key, |_, v| Arc::ptr_eq(v, &flow_info))
                .is_none()
            {
                debug!("Unable to remove flow {flow_key} from table: not found");
            }
        });
    }

    fn insert_common(&self, flow_key: FlowKey, val: &Arc<FlowInfo>) -> Option<Arc<FlowInfo>> {
        let table = self.table.read().unwrap();
        let result = table.insert(flow_key, val.clone());

        // TODO(smatov): add FlowTable capacity management to prevent unbounded growth of
        // expired entries in high-throughput scenarios.

        // Spawn a per-flow expiration timer when running inside a tokio runtime.
        // After the deadline elapses, the timer marks the flow Expired and removes its
        // own DashMap entry so expired flows are collected
        // promptly even when no subsequent lookup for the same key ever arrives.
        // Lazy cleanup in lookup() remains as a fallback for non-tokio contexts and
        // for entries cancelled or expired via other paths.
        // In non-tokio contexts (shuttle tests, sync unit tests) a debug is logged
        // and no timer is spawned; lazy time-checking in `lookup` handles expiration.
        //
        // Only spawn a timer for a genuinely new Arc.  If the same Arc is being
        // reinserted (e.g. via reinsert()), its existing timer loop already handles
        // extended deadlines via the `new_deadline > deadline` re-check, so spawning
        // a second task would be redundant and would cause unbounded task growth.

        // Drop the outer read-guard before spawning; the timer task will acquire its
        // own read-guard later and std::sync::RwLock behaviour on re-entrant locking
        // is explicitly unspecified.
        drop(table);

        let need_timer = result.as_ref().is_none_or(|old| !Arc::ptr_eq(old, val));
        if need_timer {
            if tokio::runtime::Handle::try_current().is_err() {
                debug!(
                    "insert: no tokio runtime present, flow expiration timer not spawned; \
                     relying on lazy expiration in lookup()"
                );
            } else {
                Self::start_timer(self.table.clone(), val.clone());
            }
        }

        let ret = result?;

        if ret.status() == FlowStatus::Expired {
            return None;
        }

        Some(ret)
    }

    /// Lookup a flow in the table.
    ///
    /// Performs lazy time-based expiration: if the matched entry is still
    /// `Active` but its deadline has passed (e.g. because the tokio timer has
    /// not yet fired, or no tokio runtime is present), the entry is marked
    /// `Expired` and removed here.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table or
    /// if the table lock is poisoned.
    pub fn lookup<Q>(&self, flow_key: &Q) -> Option<Arc<FlowInfo>>
    where
        FlowKey: Borrow<Q>,
        Q: Hash + Eq + ?Sized + Debug,
    {
        debug!("lookup: Looking up flow key {:?}", flow_key);
        let table = self.table.read().unwrap();
        let item = table.get(flow_key)?.value().clone();
        // NOTE: the DashMap shard guard from `.get()` is dropped here.  Between this
        // point and any removal below, another thread may have replaced the entry under
        // the same key with a fresh flow.  We therefore use `remove_if` with an
        // `Arc::ptr_eq` guard so that we only delete the specific Arc we examined —
        // a concurrent replacement will cause `ptr_eq` to be false and the new entry
        // will be left intact.
        let status = item.status();
        match status {
            FlowStatus::Active => {
                // Lazy expiration: cover non-tokio contexts and timer scheduling lag.
                if item.expires_at() <= Instant::now() {
                    debug!(
                        "lookup: Flow key {:?} has passed its deadline, expiring",
                        flow_key
                    );
                    item.update_status(FlowStatus::Expired);
                    table.remove_if(flow_key, |_, v| Arc::ptr_eq(v, &item));
                    return None;
                }
                Some(item)
            }
            FlowStatus::Expired | FlowStatus::Cancelled => {
                debug!("lookup: Flow key {:?} is '{status}', removing", flow_key);
                table.remove_if(flow_key, |_, v| Arc::ptr_eq(v, &item));
                None
            }
        }
    }

    /// Remove a flow from the table.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table or
    /// if the table lock is poisoned.
    pub fn remove<Q>(&self, flow_key: &Q) -> Option<(FlowKey, Arc<FlowInfo>)>
    where
        FlowKey: Borrow<Q>,
        Q: Hash + Eq + ?Sized + Debug,
    {
        debug!("remove: Removing flow key {:?}", flow_key);
        let table = self.table.read().unwrap();
        Self::remove_with_read_lock(&table, flow_key)
    }

    fn remove_with_read_lock<Q>(
        table: &RwLockReadGuard<DashMap<FlowKey, Arc<FlowInfo>, RandomState>>,
        flow_key: &Q,
    ) -> Option<(FlowKey, Arc<FlowInfo>)>
    where
        FlowKey: Borrow<Q>,
        Q: Hash + Eq + ?Sized + Debug,
    {
        let (k, v) = table.remove(flow_key)?;
        if v.status() == FlowStatus::Expired {
            return None;
        }
        Some((k, v))
    }

    /// Remove all stale entries from the table (entries that are `Expired`, `Cancelled`, or
    /// whose deadline has already passed).
    ///
    /// Returns the number of entries removed.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table or if the lock is poisoned.
    #[must_use]
    pub fn drain_stale(&self) -> usize {
        let table = self.table.read().unwrap();
        Self::drain_stale_with_read_lock(&table)
    }

    /// Purge all stale entries from the `DashMap` using [`DashMap::retain`].
    ///
    /// `retain` acquires the **write** lock on each `DashMap` shard in turn.
    /// This will deadlock if any caller on the same thread — or any other
    /// thread — is holding a live shard read guard (a [`dashmap::mapref::one::Ref`]
    /// obtained via [`DashMap::get`] or similar) at the time of the call.
    ///
    /// Currently this function is only reachable through the public
    /// [`FlowTable::drain_stale`], which holds only the outer `RwLock` read
    /// guard and never leaks a `DashMap` shard reference to callers.  Any future
    /// call site must uphold the same guarantee: no live `DashMap` `Ref` guards
    /// may exist on any thread when this function runs.
    fn drain_stale_with_read_lock(
        table: &RwLockReadGuard<DashMap<FlowKey, Arc<FlowInfo>, RandomState>>,
    ) -> usize {
        let now = Instant::now();
        let mut removed = 0usize;
        // `retain` holds the write lock on each DashMap shard while evaluating the
        // predicate, making the staleness check and the removal atomic per shard.
        // This closes the race that the previous collect-then-remove-by-key pattern
        // had: a concurrent insert could no longer slip a fresh entry under a key
        // between the time we marked it for removal and the time we called remove().
        // As a bonus, retain is a single O(n) pass with no temporary Vec allocation.
        table.retain(|_key, val| {
            let stale = match val.status() {
                FlowStatus::Expired | FlowStatus::Cancelled => true,
                FlowStatus::Active if val.expires_at() <= now => {
                    // Deadline passed but the tokio timer has not fired yet; mark and remove.
                    val.update_status(FlowStatus::Expired);
                    true
                }
                FlowStatus::Active => false,
            };
            if stale {
                removed += 1;
            }
            !stale
        });
        debug!("drain_stale: Removed {removed} stale flows");
        removed
    }

    #[allow(clippy::len_without_is_empty)]
    /// Returns the total number of entries physically stored in the table, regardless of
    /// their expiration status.  This is mostly for testing.
    #[must_use]
    pub fn len(&self) -> Option<usize> {
        let table = self.table.try_read().ok()?;
        Some(table.len())
    }

    /// Returns the number of *active* (non-expired, non-cancelled) flows in the table.
    /// This is mostly for testing.
    #[must_use]
    pub fn active_len(&self) -> Option<usize> {
        let table = self.table.try_read().ok()?;
        Some(
            table
                .iter()
                .filter(|e| e.value().status() == FlowStatus::Active)
                .count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    use concurrency::concurrency_mode;
    use concurrency::thread;
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;

    use net::{FlowKey, FlowKeyData, IpProtoKey, TcpProtoKey};

    #[concurrency_mode(std)]
    mod std_tests {
        use super::*;

        #[test]
        fn test_flow_table_insert_and_remove() {
            let now = Instant::now();
            let five_seconds = Duration::new(5, 0);
            let five_seconds_from_now = now + five_seconds;

            let flow_table = FlowTable::default();
            let flow_key = FlowKey::Unidirectional(FlowKeyData::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "4.5.6.7".parse::<IpAddr>().unwrap(),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1025).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            ));

            let flow_info = FlowInfo::new(five_seconds_from_now);

            flow_table.insert(flow_key, flow_info);
            let result = flow_table.remove(&flow_key).unwrap();
            assert!(result.0 == flow_key);
        }

        #[test]
        fn test_flow_table_timeout() {
            let now = Instant::now();
            let two_seconds = Duration::from_secs(2);
            let one_second = Duration::from_secs(1);

            let flow_table = FlowTable::default();
            let flow_key = FlowKey::Unidirectional(FlowKeyData::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(42).unwrap())),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "10.0.0.2".parse::<IpAddr>().unwrap(),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1234).unwrap(),
                    dst_port: TcpPort::new_checked(5678).unwrap(),
                }),
            ));

            let flow_info = FlowInfo::new(now + two_seconds);
            flow_table.insert(flow_key, flow_info);

            // Wait 1 second — flow not yet expired, lazy lookup should return Some.
            thread::sleep(one_second);
            assert!(
                flow_table.lookup(&flow_key).is_some(),
                "Flow key should still be present after 1 second"
            );

            // Wait another 2 seconds (total 3s) — flow expired.
            // Lazy expiration in lookup cleans it up.
            thread::sleep(two_seconds);
            assert!(
                flow_table.lookup(&flow_key).is_none(),
                "Flow key should have expired and been removed"
            );
        }

        #[test]
        fn test_flow_table_entry_replaced_on_insert() {
            let now = Instant::now();
            let first_expiry_time = now + Duration::from_secs(5);
            let second_expiry_time = now + Duration::from_secs(10);

            let flow_table = FlowTable::default();
            let flow_key = FlowKey::Unidirectional(FlowKeyData::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "4.5.6.7".parse::<IpAddr>().unwrap(),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1025).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            ));

            // Insert first entry.
            let first_arc = Arc::new(FlowInfo::new(first_expiry_time));
            flow_table.insert_from_arc(flow_key, &first_arc);

            // The entry stored in the table should be the first arc.
            {
                let table = flow_table.table.read().unwrap();
                let entry = table
                    .get(&flow_key)
                    .expect("entry should exist after first insert");
                assert_eq!(entry.value().expires_at(), first_expiry_time);
            }

            // Insert a second entry under the same key.
            let second_arc = Arc::new(FlowInfo::new(second_expiry_time));
            flow_table.insert_from_arc(flow_key, &second_arc);

            // The table should now point to the second entry.
            {
                let table = flow_table.table.read().unwrap();
                let entry = table
                    .get(&flow_key)
                    .expect("entry should exist after second insert");
                assert_ne!(entry.value().expires_at(), first_expiry_time);
                assert_eq!(entry.value().expires_at(), second_expiry_time);
            }
        }

        #[test]
        fn test_flow_table_expire_bolero() {
            let flow_table = FlowTable::default();
            bolero::check!()
                .with_type::<FlowKey>()
                .for_each(|flow_key| {
                    // Insert with a future expiry so early lookups see the flow.
                    flow_table.insert(
                        *flow_key,
                        FlowInfo::new(Instant::now() + Duration::from_secs(60)),
                    );
                    let flow_info = flow_table.lookup(flow_key).unwrap();
                    assert!(flow_table.lookup(&flow_key.reverse(None)).is_none());

                    // Simulate expiration (what the tokio timer would do).
                    flow_info.update_status(FlowStatus::Expired);

                    // Lazy cleanup on next lookup.
                    let result = flow_table.lookup(flow_key);
                    assert!(
                        result.is_none(),
                        "expired flow should be removed by lookup, inserted {flow_info:?}"
                    );
                });
        }

        #[test]
        fn test_flow_table_remove_bolero() {
            let flow_table = FlowTable::default();
            bolero::check!()
                .with_type::<FlowKey>()
                .for_each(|flow_key| {
                    // Use a future expiry so the flow stays active long enough for remove().
                    flow_table.insert(
                        *flow_key,
                        FlowInfo::new(Instant::now() + Duration::from_secs(60)),
                    );
                    let flow_info = flow_table.lookup(flow_key).unwrap();
                    assert!(flow_table.lookup(&flow_key.reverse(None)).is_none());

                    let result = flow_table.remove(flow_key);
                    assert!(result.is_some());
                    let (k, v) = result.unwrap();
                    assert_eq!(k, *flow_key);
                    assert!(Arc::ptr_eq(&v, &flow_info));
                    assert!(flow_table.lookup(flow_key).is_none());
                });
        }

        #[test]
        fn test_aggressive_reap_threshold() {
            // Must be small enough to stay within u16 port range (< 65_535).
            const REAP_THRESHOLD_TEST: usize = 10_000;

            let mut flow_table = FlowTable::default();
            flow_table.set_reap_threshold(REAP_THRESHOLD_TEST);

            let src_vpcd = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
            let src_ip: IpAddr = "1.2.3.4".parse().unwrap();
            let dst_ip: IpAddr = "5.6.7.8".parse().unwrap();

            // Insert REAP_THRESHOLD_TEST + 100 flows, all Active with a far-future expiry.
            for src_port in 1..=REAP_THRESHOLD_TEST + 100 {
                #[allow(clippy::cast_possible_truncation)]
                let src_port = TcpPort::new_checked(src_port as u16).unwrap();
                let dst_port = TcpPort::new_checked(100).unwrap();
                let flow_key = FlowKey::Unidirectional(FlowKeyData::new(
                    Some(src_vpcd),
                    src_ip,
                    dst_ip,
                    IpProtoKey::Tcp(TcpProtoKey { src_port, dst_port }),
                ));
                let flow_info = FlowInfo::new(Instant::now() + Duration::from_secs(3600));
                flow_table.insert(flow_key, flow_info);
            }

            // We inserted more flows than the threshold.
            assert!(flow_table.active_len().unwrap() > REAP_THRESHOLD_TEST);

            // drain_stale: nothing should be reaped because all are Active with far-future expiry.
            let reaped = flow_table.drain_stale();
            assert_eq!(reaped, 0);
            assert!(flow_table.active_len().unwrap() > REAP_THRESHOLD_TEST);

            // Mark all flows except the first one as Cancelled.
            let mut kept = 0usize;
            for entry in flow_table.table.read().unwrap().iter() {
                if kept == 0 {
                    kept += 1;
                    continue;
                }
                entry.value().update_status(FlowStatus::Cancelled);
            }

            // drain_stale: all Cancelled flows should be purged, leaving exactly 1.
            let reaped = flow_table.drain_stale();
            assert_eq!(reaped, REAP_THRESHOLD_TEST + 100 - 1);
            assert_eq!(flow_table.active_len().unwrap(), 1);
        }
    }

    #[concurrency_mode(shuttle)]
    mod shuttle_tests {
        use super::*;
        use crate::flow_table::FlowInfo;
        use concurrency::sync::Arc;

        #[test]
        fn test_flow_table_timeout() {
            shuttle::check_random(
                move || {
                    let now = Instant::now();
                    let two_seconds = Duration::from_secs(2);

                    let flow_table = FlowTable::default();
                    let flow_key = FlowKey::Unidirectional(FlowKeyData::new(
                        Some(VpcDiscriminant::VNI(Vni::new_checked(42).unwrap())),
                        "10.0.0.1".parse::<IpAddr>().unwrap(),
                        "10.0.0.2".parse::<IpAddr>().unwrap(),
                        IpProtoKey::Tcp(TcpProtoKey {
                            src_port: TcpPort::new_checked(1234).unwrap(),
                            dst_port: TcpPort::new_checked(5678).unwrap(),
                        }),
                    ));

                    let flow_info = FlowInfo::new(now + two_seconds);
                    flow_table.insert(flow_key, flow_info);

                    // Flow is active; lookup should return Some.
                    assert!(
                        flow_table.lookup(&flow_key).is_some(),
                        "Flow key should be present"
                    );

                    // Simulate timer expiration by marking the flow directly.
                    if let Some(fi) = flow_table.lookup(&flow_key) {
                        fi.update_status(FlowStatus::Expired);
                    }

                    // Lazy cleanup on next lookup.
                    assert!(
                        flow_table.lookup(&flow_key).is_none(),
                        "Flow key should be gone after expiration"
                    );
                },
                100,
            );
        }

        #[allow(clippy::too_many_lines)]
        #[test]
        #[tracing_test::traced_test]
        fn test_flow_table_concurrent_insert_remove_lookup_expire() {
            const N: usize = 3;

            let two_seconds = Duration::from_secs(2);
            let flow_keys: Vec<_> = (0u16..2u16)
                .map(|i| {
                    FlowKey::Unidirectional(FlowKeyData::new(
                        Some(VpcDiscriminant::VNI(
                            Vni::new_checked(u32::from(i) + 1).unwrap(),
                        )),
                        format!("10.0.{i}.1").parse::<IpAddr>().unwrap(),
                        format!("10.0.{i}.2").parse::<IpAddr>().unwrap(),
                        IpProtoKey::Tcp(TcpProtoKey {
                            src_port: TcpPort::new_checked(1000 + i).unwrap(),
                            dst_port: TcpPort::new_checked(2000 + i).unwrap(),
                        }),
                    ))
                })
                .collect();

            shuttle::check_random(
                move || {
                    let flow_table = Arc::new(FlowTable::default());

                    let now = Instant::now();

                    let orig_flow_info = FlowInfo::new(now + two_seconds);

                    // Insert the first flow
                    flow_table.insert(flow_keys[0], orig_flow_info);
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
                                let flow_key = flow_keys[1];

                                let flow_info = flow_info_holder.take();
                                move || {
                                    for _ in 0..N {
                                        if let Some(flow_info) = flow_info.as_ref() {
                                            flow_table.reinsert(flow_key, flow_info);
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
                                            let _guard = flow_info.locked.write().unwrap();
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
                    assert!(
                        flow_table.lookup(&flow_keys[0]).is_none(),
                        "Flow key[0] should have been expired"
                    );
                },
                100,
            );
        }

        #[test]
        fn test_flow_table_reshard() {
            shuttle::check_random(
                move || {
                    let flow_table = Arc::new(FlowTable::default());

                    let five_seconds_from_now = Instant::now() + Duration::from_secs(5);
                    let flow_key1 = FlowKey::Unidirectional(FlowKeyData::new(
                        Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                        "1.2.3.4".parse::<IpAddr>().unwrap(),
                        "4.5.6.7".parse::<IpAddr>().unwrap(),
                        IpProtoKey::Tcp(TcpProtoKey {
                            src_port: TcpPort::new_checked(1025).unwrap(),
                            dst_port: TcpPort::new_checked(2048).unwrap(),
                        }),
                    ));

                    let flow_key2 = FlowKey::Unidirectional(FlowKeyData::new(
                        Some(VpcDiscriminant::VNI(Vni::new_checked(10).unwrap())),
                        "10.2.3.4".parse::<IpAddr>().unwrap(),
                        "40.5.6.7".parse::<IpAddr>().unwrap(),
                        IpProtoKey::Tcp(TcpProtoKey {
                            src_port: TcpPort::new_checked(1025).unwrap(),
                            dst_port: TcpPort::new_checked(2048).unwrap(),
                        }),
                    ));

                    let flow_table_clone1 = flow_table.clone();
                    let flow_table_clone2 = flow_table.clone();
                    let flow_table_clone3 = flow_table.clone();

                    let mut handles = vec![];

                    handles.push(thread::spawn(move || {
                        let flow_info = FlowInfo::new(five_seconds_from_now);
                        flow_table_clone1.insert(flow_key1, flow_info);
                        let result = flow_table_clone1.remove(&flow_key1).unwrap();
                        assert!(result.0 == flow_key1);
                    }));

                    handles.push(thread::spawn(move || {
                        let flow_info = FlowInfo::new(five_seconds_from_now);
                        flow_table_clone2.insert(flow_key2, flow_info);
                        let result = flow_table.remove(&flow_key2).unwrap();
                        assert!(result.0 == flow_key2);
                    }));

                    handles.push(thread::spawn(move || {
                        flow_table_clone3.reshard(128).unwrap();
                    }));

                    let _results: Vec<()> = handles
                        .into_iter()
                        .map(|handle| handle.join().unwrap())
                        .collect();
                },
                100,
            );
        }
    }
}
