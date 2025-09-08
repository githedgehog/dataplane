// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ahash::RandomState;
use dashmap::DashMap;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::Hash;
use std::time::Instant;
use tracing::{debug, error};

use concurrency::sync::{Arc, RwLock, RwLockReadGuard, Weak};

use crate::flow_table::thread_local_pq::{PQAction, ThreadLocalPriorityQueue};
use crate::flow_table::{FlowInfo, FlowKey, FlowStatus};

#[derive(Debug, thiserror::Error)]
pub enum FlowTableError {
    #[error("Invalid number of shards: {0}. Must be a power of two.")]
    InvalidShardCount(usize),
}

type PriorityQueue = ThreadLocalPriorityQueue<FlowKey, Arc<FlowInfo>>;
type Table = DashMap<FlowKey, Weak<FlowInfo>, RandomState>;

pub struct FlowTable {
    // TODO(mvachhar) move this to a cross beam sharded lock
    pub(crate) table: RwLock<Table>,
    pub(crate) priority_queue: PriorityQueue,
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
            table: RwLock::new(Table::with_hasher_and_shard_amount(
                hasher_state().clone(),
                num_shards,
            )),
            priority_queue: PriorityQueue::new(),
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
    /// Panics if this thread already holds the read lock on the table or
    /// if the table lock is poisoned.
    pub fn insert(&self, flow_key: FlowKey, flow_info: FlowInfo) -> Option<Arc<FlowInfo>> {
        debug!("insert: Inserting flow key {:?}", flow_key);
        let val = Arc::new(flow_info);
        self.insert_common(flow_key, &val)
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
        let expires_at = val.expires_at();
        let result = table.insert(flow_key, Arc::downgrade(val));
        self.priority_queue.push(flow_key, val.clone(), expires_at);
        let ret = match result {
            Some(w) => w.upgrade(),
            None => None,
        };

        let Some(ret) = ret else {
            return ret;
        };

        if ret.status() == FlowStatus::Expired {
            return None;
        }

        Some(ret)
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
        let item = table.get(flow_key)?.upgrade();
        let Some(item) = item else {
            debug!(
                "lookup: Removing flow key {:?}, found empty weak reference",
                flow_key
            );
            Self::remove_with_read_lock(&table, flow_key);
            return None;
        };
        if item.status() == FlowStatus::Expired {
            debug!("lookup: Flow key {:?} is expired, removing", flow_key);
            Self::remove_with_read_lock(&table, flow_key);
            return None;
        }
        Some(item)
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
        table: &RwLockReadGuard<DashMap<FlowKey, Weak<FlowInfo>, RandomState>>,
        flow_key: &Q,
    ) -> Option<(FlowKey, Arc<FlowInfo>)>
    where
        FlowKey: Borrow<Q>,
        Q: Hash + Eq + ?Sized + Debug,
    {
        let result = table.remove(flow_key);
        let (k, w) = result?;
        let old_val = w.upgrade()?;
        if old_val.status() == FlowStatus::Expired {
            return None;
        }
        Some((k, old_val))
    }

    fn decide_expiry(now: &Instant, k: &FlowKey, v: &Arc<FlowInfo>) -> PQAction {
        // Note(mvachhar)
        //
        //I'm not sure if marking the entry as expired is worthwhile here
        // nor am I sure of the performance cost of doing this.
        // It isn't strictly needed, though it means other holders of the Arc may
        // be able to read stale data and wouldn't know the entry is expired.
        //
        // If the common case is that the entry has no other references here,
        // then this operation should be cheap, though not free due to the
        // dereference of the value and the lock acquisition.
        #[allow(unused_must_use)]
        let expires_at = v.expires_at();
        if now >= &expires_at {
            debug!("decide_expiry: Reap for flow key {k:?} with expires_at {expires_at:?}");
            PQAction::Reap
        } else {
            debug!("decide_expiry: Update for flow key {k:?} with time {expires_at:?}");
            PQAction::Update(expires_at)
        }
    }

    // Pass by value here since the PQ doesn't know the value is an Arc
    // and we get ownership of the value here
    #[allow(clippy::needless_pass_by_value)]
    fn do_reap(k: FlowKey, v: Arc<FlowInfo>) {
        match v.update_status(FlowStatus::Expired) {
            Ok(()) => {
                debug!("do_reap: Updated flow status for {k:?} to expired");
            }
            Err(e) => {
                error!("do_reap: Failed to update flow status for {k:?}: {e:?}",);
            }
        }
    }

    /// Reap expired entries from the priority queue for the current thread.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe but should not be called if the current thread is
    /// holding a lock on any element in the flow table.
    ///
    /// # Panics
    ///
    /// Panics if any lock acquired by this method is poisoned.
    pub fn reap_expired(&self) -> usize {
        self.priority_queue
            .reap_expired(Self::decide_expiry, Self::do_reap)
    }

    pub fn reap_all_expired(&self) -> usize {
        self.priority_queue
            .reap_all_expired(Self::decide_expiry, Self::do_reap)
    }

    #[cfg(all(test, feature = "shuttle"))]
    pub fn reap_all_expired_with_time(&self, time: &Instant) -> usize {
        self.priority_queue
            .reap_all_expired_with_time(time, Self::decide_expiry, Self::do_reap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    use concurrency::concurrency_mode;
    use concurrency::thread;
    use flow_info::ExtractRef;
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;

    use crate::flow_table::{FlowKey, FlowKeyData, IpProtoKey, TcpProtoKey};

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
                Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
                "4.5.6.7".parse::<IpAddr>().unwrap(),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1025).unwrap(),
                    dst_port: TcpPort::new_checked(2048).unwrap(),
                }),
            ));

            let flow_info = FlowInfo::new(five_seconds_from_now);

            flow_info.locked.write().unwrap().dst_vpc_info =
                Some(Box::new(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())));

            flow_table.insert(flow_key, flow_info);
            let result = flow_table.remove(&flow_key).unwrap();
            assert!(result.0 == flow_key);
            assert_eq!(
                result
                    .1
                    .locked
                    .read()
                    .unwrap()
                    .dst_vpc_info
                    .extract_ref::<VpcDiscriminant>()
                    .unwrap(),
                &VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())
            );
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
                Some(VpcDiscriminant::VNI(Vni::new_checked(43).unwrap())),
                "10.0.0.2".parse::<IpAddr>().unwrap(),
                IpProtoKey::Tcp(TcpProtoKey {
                    src_port: TcpPort::new_checked(1234).unwrap(),
                    dst_port: TcpPort::new_checked(5678).unwrap(),
                }),
            ));

            let flow_info = FlowInfo::new(now + two_seconds);
            flow_table.insert(flow_key, flow_info);

            // Wait 1 second, should still be present
            thread::sleep(one_second);
            // Reap expired entries after 1 second (should not reap our entry)
            flow_table.reap_expired();
            assert!(
                flow_table.lookup(&flow_key).is_some(),
                "Flow key should still be present after 1 second"
            );

            // Wait another 2 seconds (total 3s), should be expired
            thread::sleep(two_seconds);
            // Reap expired entries
            flow_table.reap_expired();

            assert!(
                flow_table.lookup(&flow_key).is_none(),
                "Flow key should have expired and been removed"
            );
        }

        #[test]
        fn test_flow_table_expire_bolero() {
            let flow_table = FlowTable::default();
            bolero::check!()
                .with_type::<FlowKey>()
                .for_each(|flow_key| {
                    flow_table.insert(*flow_key, FlowInfo::new(Instant::now()));
                    let flow_info_str = format!("{:?}", flow_table.lookup(flow_key).unwrap());

                    // We purposely keep the flow alive here to make sure lookup reaps it
                    let flow_info = flow_table.lookup(flow_key).unwrap();
                    if let FlowKey::Bidirectional(_) = flow_key {
                        let reverse_info = flow_table.lookup(&flow_key.reverse()).unwrap();
                        assert!(Arc::ptr_eq(&reverse_info, &flow_info));
                    } else {
                        assert!(flow_table.lookup(&flow_key.reverse()).is_none());
                    }

                    thread::sleep(Duration::from_millis(100));
                    flow_table.reap_all_expired();

                    let result = flow_table.lookup(flow_key);
                    assert!(
                        result.is_none(),
                        "flow_key lookup is not none {result:#?}, inserted {flow_info_str}, now: {:?}",
                        Instant::now()
                    );
                });
        }

        #[test]
        fn test_flow_table_remove_bolero() {
            let flow_table = FlowTable::default();
            bolero::check!()
                .with_type::<FlowKey>()
                .for_each(|flow_key| {
                    flow_table.insert(*flow_key, FlowInfo::new(Instant::now()));
                    let flow_info = flow_table.lookup(flow_key).unwrap();
                    if let FlowKey::Bidirectional(_) = flow_key {
                        let reverse_info = flow_table.lookup(&flow_key.reverse()).unwrap();
                        assert!(Arc::ptr_eq(&reverse_info, &flow_info));
                    } else {
                        assert!(flow_table.lookup(&flow_key.reverse()).is_none());
                    }

                    let result = flow_table.remove(flow_key);
                    assert!(result.is_some());
                    let (k, v) = result.unwrap();
                    assert_eq!(k, *flow_key);
                    assert!(Arc::ptr_eq(&v, &flow_info));
                    assert!(flow_table.lookup(flow_key).is_none());
                });
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
                    let one_second = Duration::from_secs(1);

                    let flow_table = FlowTable::default();
                    let flow_key = FlowKey::Unidirectional(FlowKeyData::new(
                        Some(VpcDiscriminant::VNI(Vni::new_checked(42).unwrap())),
                        "10.0.0.1".parse::<IpAddr>().unwrap(),
                        Some(VpcDiscriminant::VNI(Vni::new_checked(43).unwrap())),
                        "10.0.0.2".parse::<IpAddr>().unwrap(),
                        IpProtoKey::Tcp(TcpProtoKey {
                            src_port: TcpPort::new_checked(1234).unwrap(),
                            dst_port: TcpPort::new_checked(5678).unwrap(),
                        }),
                    ));

                    let flow_info = FlowInfo::new(now + two_seconds);
                    flow_table.insert(flow_key, flow_info);

                    // Reap expired entries after 1 second (should not reap our entry)
                    // Shuttle does not model time, hence this hack
                    flow_table.reap_all_expired_with_time(&(now + one_second));
                    assert!(
                        flow_table.lookup(&flow_key).is_some(),
                        "Flow key should still be present after 1 second"
                    );

                    // Reap expired entries
                    // Shuttle does not model time, hence this hack
                    flow_table.reap_all_expired_with_time(&(now + two_seconds));

                    assert!(
                        flow_table.lookup(&flow_key).is_none(),
                        "Flow key should have expired and been removed"
                    );
                },
                100,
            );
        }

        #[allow(clippy::too_many_lines)]
        #[test]
        #[tracing_test::traced_test]
        fn test_flow_table_concurrent_insert_remove_lookup_timeout() {
            const N: usize = 3;

            let two_seconds = Duration::from_secs(2);
            let flow_keys: Vec<_> = (0u16..2u16)
                .map(|i| {
                    FlowKey::Unidirectional(FlowKeyData::new(
                        Some(VpcDiscriminant::VNI(
                            Vni::new_checked(u32::from(i) + 1).unwrap(),
                        )),
                        format!("10.0.{i}.1").parse::<IpAddr>().unwrap(),
                        Some(VpcDiscriminant::VNI(
                            Vni::new_checked(u32::from(i) + 100).unwrap(),
                        )),
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
                    handles.push(
                        thread::Builder::new()
                            .name("timeout_reaper".to_string())
                            .spawn({
                                let flow_table = flow_table.clone();
                                move || {
                                    for _ in 0..N {
                                        thread::yield_now();
                                        flow_table.reap_expired();
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

                    // Shuttle does not model time so we need this hack
                    let reap_time = now + two_seconds;
                    flow_table.reap_all_expired_with_time(&reap_time);

                    // After all threads, all keys should be either gone or expired
                    for key in &flow_keys {
                        let result = flow_table.lookup(key);
                        assert!(
                            result.is_none(),
                            "Flow key {:#?} should have expired at {:?} and been removed, now at create: {:?}, reap time: {:?}",
                            *key,
                            result.unwrap().expires_at(),
                            now,
                            reap_time
                        );
                    }
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
                        Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
                        "4.5.6.7".parse::<IpAddr>().unwrap(),
                        IpProtoKey::Tcp(TcpProtoKey {
                            src_port: TcpPort::new_checked(1025).unwrap(),
                            dst_port: TcpPort::new_checked(2048).unwrap(),
                        }),
                    ));

                    let flow_key2 = FlowKey::Unidirectional(FlowKeyData::new(
                        Some(VpcDiscriminant::VNI(Vni::new_checked(10).unwrap())),
                        "10.2.3.4".parse::<IpAddr>().unwrap(),
                        Some(VpcDiscriminant::VNI(Vni::new_checked(20).unwrap())),
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
                        flow_info.locked.write().unwrap().dst_vpc_info =
                            Some(Box::new(VpcDiscriminant::VNI(Vni::new_checked(3).unwrap())));
                        flow_table_clone1.insert(flow_key1, flow_info);
                        let result = flow_table_clone1.remove(&flow_key1).unwrap();
                        assert!(result.0 == flow_key1);
                        assert_eq!(
                            result
                                .1
                                .locked
                                .read()
                                .unwrap()
                                .dst_vpc_info
                                .extract_ref::<VpcDiscriminant>()
                                .unwrap(),
                            &VpcDiscriminant::VNI(Vni::new_checked(3).unwrap())
                        );
                    }));

                    handles.push(thread::spawn(move || {
                        let flow_info = FlowInfo::new(five_seconds_from_now);
                        flow_info.locked.write().unwrap().dst_vpc_info =
                            Some(Box::new(VpcDiscriminant::VNI(Vni::new_checked(4).unwrap())));
                        flow_table_clone2.insert(flow_key2, flow_info);
                        let result = flow_table.remove(&flow_key2).unwrap();
                        assert!(result.0 == flow_key2);
                        assert_eq!(
                            result
                                .1
                                .locked
                                .read()
                                .unwrap()
                                .dst_vpc_info
                                .extract_ref::<VpcDiscriminant>()
                                .unwrap(),
                            &VpcDiscriminant::VNI(Vni::new_checked(4).unwrap())
                        );
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
