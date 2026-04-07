// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ahash::RandomState;
use dashmap::DashMap;
use net::FlowKey;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::Hash;
use tracing::debug;

use concurrency::sync::{Arc, RwLock};

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
    pub(crate) table: Arc<RwLock<Table>>,
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
    #[must_use]
    pub fn new(num_shards: usize) -> Self {
        Self {
            table: Arc::new(RwLock::new(Table::with_hasher_and_shard_amount(
                hasher_state().clone(),
                num_shards,
            ))),
        }
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

        debug!("insert: Inserting flow {flow_key}");
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
    #[allow(unused)]
    fn start_timer(table: Arc<RwLock<Table>>, flow_info: Arc<FlowInfo>) {
        tokio::task::spawn(async move {
            let table = table;
            let flow_key = flow_info.flowkey().unwrap_or_else(|| unreachable!()); // flows have key when inserted
            let mut deadline = flow_info.expires_at();
            loop {
                tokio::select! {
                    () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        let status = flow_info.status();
                        if status != FlowStatus::Active {
                            debug!("Timer[EXPIRED]: Flow {flow_key} is in status {status}");
                            break;
                        }
                        let new_deadline = flow_info.expires_at();
                        if new_deadline > deadline {
                            debug!("Timer[EXTENDED] for Flow {flow_key}");
                            deadline = new_deadline;
                            continue;
                        }
                        debug!("Timer[EXPIRED] for flow {flow_key}");
                        flow_info.update_status(FlowStatus::Expired);
                        break;
                    },
                    () = flow_info.token.cancelled() =>  {
                        debug!("Timer[CANCELLED] for flow {flow_key}");
                        break;
                    },
                }
            }
            // no need to remove
            if flow_info.status() == FlowStatus::Detached {
                return;
            }

            // The timer for a flow expired or was cancelled. Therefore the flow should be removed.
            // We use remove_if + ptr_eq so that a concurrently-inserted replacement is left intact.

            let table = loop {
                // Use try_read() rather than read() to avoid undefined behaviour on
                // platforms where re-entrant locking may panic.  In practice the
                // write lock is only held by reshard(), which is synchronous and
                // never yields to the tokio executor, so WouldBlock is virtually
                // never observed; yield_now() is purely defensive.
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

            debug!("Timer: removing flow {flow_key}...");
            if table
                .remove_if(flow_key, |_, v| Arc::ptr_eq(v, &flow_info))
                .is_none()
            {
                debug!("Timer: Unable to remove flow {flow_key} from table: not found");
            }
        });
    }

    fn insert_common(&self, flow_key: FlowKey, val: &Arc<FlowInfo>) -> Option<Arc<FlowInfo>> {
        val.update_status(FlowStatus::Active);
        let table = self.table.read().unwrap();
        let result = table.insert(flow_key, val.clone());

        #[cfg(not(feature = "shuttle"))]
        Self::start_timer(self.table.clone(), val.clone());

        if let Some(old) = result.as_ref() {
            old.update_status(FlowStatus::Detached);
            #[cfg(not(feature = "shuttle"))]
            old.token.cancel();
        }
        result
    }

    /// Lookup a flow in the table.
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
        Some(table.get(flow_key)?.value().clone())
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
        let result = table.remove(flow_key);
        if let Some((_key, flow_info)) = result.as_ref() {
            flow_info.update_status(FlowStatus::Detached);
            #[cfg(not(feature = "shuttle"))]
            flow_info.token.cancel();
        }
        result
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
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;

    use net::{FlowKey, FlowKeyData, IpProtoKey, TcpProtoKey};

    #[concurrency_mode(std)]
    mod std_tests {
        use std::time::Instant;
        use tracing_test::traced_test;

        use super::*;

        #[tokio::test]
        async fn test_flow_table_insert_and_remove() {
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

        #[tokio::test]
        async fn test_flow_table_timeout() {
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

            // Wait 1 second — flow not yet expired, lookup should return Some.
            tokio::time::sleep(one_second).await;
            assert!(
                flow_table.lookup(&flow_key).is_some(),
                "Flow key should still be present after 1 second"
            );

            // Wait another 2 seconds (total 3s) — flow expired. It should be gone
            tokio::time::sleep(two_seconds).await;
            assert!(flow_table.lookup(&flow_key).is_none());
        }

        #[tokio::test]
        async fn test_flow_table_entry_replaced_on_insert() {
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

        #[tokio::test]
        async fn test_flow_table_remove_bolero() {
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

        #[tokio::test]
        #[traced_test]
        /// Test that invalidating flows causes timer to expire and flows to be removed
        async fn test_flow_table_flow_invalidation() {
            const NUM_FLOWS: u16 = 10;
            let flow_table = FlowTable::default();
            let now = Instant::now();
            let deadline = now + Duration::from_secs(3);

            let mut flow_keys = vec![];
            for src_port in 1..=NUM_FLOWS {
                let flow_key = FlowKey::Unidirectional(FlowKeyData::new(
                    Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                    "1.2.3.4".parse::<IpAddr>().unwrap(),
                    "4.5.6.7".parse::<IpAddr>().unwrap(),
                    IpProtoKey::Tcp(TcpProtoKey {
                        src_port: TcpPort::new_checked(src_port).unwrap(),
                        dst_port: TcpPort::new_checked(2048).unwrap(),
                    }),
                ));
                let flow_info = FlowInfo::new(deadline);
                flow_table.insert(flow_key, flow_info);
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
        #[traced_test]
        /// Test that invalidating flows causes timer to expire and flows to be removed
        async fn test_flow_table_flow_reinsertion() {
            let flow_table = FlowTable::default();
            let now = Instant::now();
            let deadline = now + Duration::from_secs(2);

            let flow_key = FlowKey::Unidirectional(FlowKeyData::new(
                Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "4.5.6.7".parse::<IpAddr>().unwrap(),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            ));
            let flow_info = FlowInfo::new(deadline);
            flow_table.insert(flow_key, flow_info);

            let flow_info = FlowInfo::new(deadline + Duration::from_secs(2));
            let old = flow_table.insert(flow_key, flow_info);
            assert!(old.is_some());
            assert_eq!(old.unwrap().expires_at(), deadline);
            assert_eq!(flow_table.active_len().unwrap(), 1);

            let () = tokio::time::sleep(Duration::from_secs(5)).await;
            assert_eq!(flow_table.active_len().unwrap(), 0);
        }
    }

    #[concurrency_mode(shuttle)]
    mod shuttle_tests {
        use super::*;
        use crate::flow_table::FlowInfo;
        use concurrency::sync::Arc;
        use concurrency::thread;
        use std::time::Instant;

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

                    // Lookup: will find it because we don't expire without tokio nor do lazy removals
                    let found = flow_table.lookup(&flow_key).unwrap();
                    assert_eq!(found.status(), FlowStatus::Expired);
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
                    // Since timers are not started in shuttle tests, the flow should be there
                    // but appear as Expired or Detached. Re-inserting a flow makes it active again,
                    // therefore, the only non-feasible status is Cancellled.
                    let found = flow_table.lookup(&flow_keys[0]).unwrap();
                    assert_ne!(found.status(), FlowStatus::Cancelled);
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
