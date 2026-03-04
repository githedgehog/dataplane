// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ahash::RandomState;
use dashmap::DashMap;
use net::FlowKey;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::Hash;
use std::time::Instant;
use tracing::{debug, warn};

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
    pub(crate) table: RwLock<Table>,
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
            table: RwLock::new(Table::with_hasher_and_shard_amount(
                hasher_state().clone(),
                num_shards,
            )),
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

        debug!("insert: Inserting flow key {:?}", flow_key);
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
        debug!("insert: Inserting flow key {:?}", flow_key);
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
        debug!("reinsert: Re-inserting flow key {:?}", flow_key);
        self.insert_common(flow_key, flow_info)
    }

    fn insert_common(&self, flow_key: FlowKey, val: &Arc<FlowInfo>) -> Option<Arc<FlowInfo>> {
        let table = self.table.read().unwrap();
        let result = table.insert(flow_key, val.clone());

        // Proactively purge stale entries when the raw table size exceeds the threshold.
        // This bounds memory growth when flows expire faster than they are looked up,
        // since expired entries otherwise accumulate in the `DashMap` until a lookup hits them.
        let raw_len = table.len();
        if raw_len > self.reap_threshold {
            warn!(
                "The number of flows ({raw_len}) exceeds {}. Reaping stale entries...",
                self.reap_threshold
            );
            Self::drain_stale_with_read_lock(&table);
        }

        // Spawn a per-flow expiration timer when running inside a tokio runtime.
        // The timer marks the flow as Expired; the `DashMap` entry is cleaned up
        // lazily the next time lookup() is called for this key.
        // In non-tokio contexts (shuttle tests, sync unit tests) the guard fails
        // gracefully and lazy time-checking in `lookup` handles expiration instead.
        //
        // Only spawn a timer for a genuinely new Arc.  If the same Arc is being
        // reinserted (e.g. via reinsert()), its existing timer loop already handles
        // extended deadlines via the `new_deadline > deadline` re-check, so spawning
        // a second task would be redundant and would cause unbounded task growth.
        //
        // The timer holds a Weak<FlowInfo> rather than Arc<FlowInfo> and drops the
        // upgrade before sleeping, so the timer task does not extend the lifetime of
        // the FlowInfo allocation.  Once the DashMap entry is removed (drain_stale,
        // lookup lazy cleanup, or explicit remove) and all other callers drop their
        // Arc clones, the allocation is freed even if the timer has not yet woken up.
        // The status check after each sleep avoids redundant work for flows that were
        // already Cancelled before their deadline elapsed.
        let need_timer = result.as_ref().is_none_or(|old| !Arc::ptr_eq(old, val));
        if need_timer && tokio::runtime::Handle::try_current().is_ok() {
            let fi_weak = Arc::downgrade(val);
            tokio::task::spawn(async move {
                loop {
                    // Upgrade to check status and read the deadline.  If the Arc has
                    // already been dropped (no DashMap entry, no in-flight holders),
                    // there is nothing left to expire.
                    let Some(fi) = fi_weak.upgrade() else { break };
                    if fi.status() != FlowStatus::Active {
                        // Already Cancelled or Expired by another path; nothing to do.
                        break;
                    }
                    let deadline = fi.expires_at();
                    // Drop the strong ref before sleeping so this task does not
                    // prevent the FlowInfo allocation from being freed.
                    drop(fi);
                    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                    // Re-acquire after sleeping and re-check before committing.
                    let Some(fi) = fi_weak.upgrade() else { break };
                    if fi.status() != FlowStatus::Active {
                        break;
                    }
                    let new_deadline = fi.expires_at();
                    if new_deadline > deadline {
                        // Deadline was extended (e.g. by StatefulNat); sleep again.
                        continue;
                    }
                    fi.update_status(FlowStatus::Expired);
                    break;
                }
            });
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
                    Self::remove_with_read_lock(&table, flow_key);
                    return None;
                }
                Some(item)
            }
            FlowStatus::Expired | FlowStatus::Cancelled => {
                debug!("lookup: Flow key {:?} is '{status}', removing", flow_key);
                Self::remove_with_read_lock(&table, flow_key);
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
    pub fn drain_stale(&self) -> usize {
        let table = self.table.read().unwrap();
        Self::drain_stale_with_read_lock(&table)
    }

    fn drain_stale_with_read_lock(
        table: &RwLockReadGuard<DashMap<FlowKey, Arc<FlowInfo>, RandomState>>,
    ) -> usize {
        let now = Instant::now();
        let to_remove: Vec<FlowKey> = table
            .iter()
            .filter_map(|entry| {
                let val = entry.value();
                match val.status() {
                    FlowStatus::Expired | FlowStatus::Cancelled => Some(*entry.key()),
                    FlowStatus::Active if val.expires_at() <= now => {
                        // Deadline passed but the tokio timer has not fired yet; mark and remove.
                        val.update_status(FlowStatus::Expired);
                        Some(*entry.key())
                    }
                    FlowStatus::Active => None,
                }
            })
            .collect();
        let removed = to_remove.len();
        for key in &to_remove {
            table.remove(key);
        }
        debug!("drain_stale: Removed {removed} stale flows");
        removed
    }

    #[allow(clippy::len_without_is_empty)]
    /// Returns the total number of entries physically stored in the table, regardless of
    /// their expiration status.  This is mostly for testing.
    pub fn len(&self) -> Option<usize> {
        let table = self.table.try_read().ok()?;
        Some(table.len())
    }

    /// Returns the number of *active* (non-expired, non-cancelled) flows in the table.
    /// This is mostly for testing.
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
            flow_table.drain_stale();
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
