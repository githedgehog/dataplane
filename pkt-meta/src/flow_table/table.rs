// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::borrow::Borrow;
use std::hash::Hash;
use std::sync::Weak;
use std::time::{Duration, Instant};

use ahash::RandomState;
use dashmap::DashMap;

use concurrency::sync::{Arc, RwLock};
use net::packet::VpcDiscriminant;

use crate::flow_table::AtomicInstant;
use crate::flow_table::FlowKey;
use crate::flow_table::thread_local_pq::{PQAction, ThreadLocalPriorityQueue};

#[derive(Debug, thiserror::Error)]
pub enum FlowInfoError {
    #[error("flow expired")]
    FlowExpired(Instant),
}

#[derive(Debug, Clone)]
pub struct FlowInfoLocked {
    pub dst_vpcd: VpcDiscriminant,
    pub expired: bool,
}

#[derive(Debug)]
pub struct FlowInfo {
    expires_at: AtomicInstant,
    pub locked: Arc<RwLock<FlowInfoLocked>>,
}

impl FlowInfo {
    pub fn expires_at(&self) -> Instant {
        self.expires_at.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Extend the expiry of the flow without checking if it is already expired.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe.
    ///
    pub fn extend_expiry_unchecked(&self, duration: Duration) {
        self.expires_at
            .fetch_add(duration, std::sync::atomic::Ordering::Relaxed);
    }
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
    pub fn reshard(&self, num_shards: usize) -> Result<(), String> {
        if !num_shards.is_power_of_two() {
            return Err("foo".to_string());
        }
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
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table or
    /// if the table lock is poisoned.
    pub fn insert(&self, flow_key: FlowKey, flow_info: FlowInfo) -> Option<Arc<FlowInfo>> {
        let table = self.table.read().unwrap();
        let val = Arc::new(flow_info);
        let expires_at = val.expires_at.load(std::sync::atomic::Ordering::Relaxed);
        let result = table.insert(flow_key, Arc::downgrade(&val));
        self.priority_queue.push(flow_key, val.clone(), expires_at);
        // This unwrap cannot fail as val is holding the Arc strong reference
        result.map(|w| w.upgrade().unwrap())
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
        Q: Hash + Eq + ?Sized,
    {
        let table = self.table.read().unwrap();
        let result = table.get(flow_key)?;
        let item = result.upgrade();
        let Some(item) = item else {
            self.remove(flow_key);
            return None;
        };
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
        Q: Hash + Eq + ?Sized,
    {
        let table = self.table.read().unwrap();
        let result = table.remove(flow_key);
        let (k, w) = result?;
        let old_val = w.upgrade()?;
        Some((k, old_val))
    }

    fn decide_expiry(now: &Instant, _k: &FlowKey, v: &Arc<FlowInfo>) -> PQAction {
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
        let expires_at = v.expires_at.load(std::sync::atomic::Ordering::Relaxed);
        if now > &expires_at {
            PQAction::Reap
        } else {
            PQAction::Update(expires_at)
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
            .reap_expired(Self::decide_expiry, |_, _| {})
    }

    pub fn reap_all_expired(&self) -> usize {
        self.priority_queue
            .reap_all_expired(Self::decide_expiry, |_, _| {})
    }
}

#[cfg(false)]
#[cfg(test)]
mod tests {
    use super::*;
    use concurrency::concurrency_mode;
    use net::vxlan::Vni;

    #[concurrency_mode(std)]
    mod std_tests {
        use super::*;

        #[test]
        fn test_flow_table_insert_and_remove() {
            let flow_table = FlowTable::default();
            let flow_key = FlowKey {
                src_vni: Vni::new_checked(1).unwrap(),
                src_ip: "1.2.3.4".parse::<IpAddr>().unwrap(),
                dst_ip: "4.5.6.7".parse::<IpAddr>().unwrap(),
                dst_vni: Vni::new_checked(2).unwrap(),
                ip_proto_number: 6,
            };
            let flow_info = FlowInfo { dst_vni: None };
            flow_table.insert(flow_key, flow_info);
            let result = flow_table.remove(&flow_key).unwrap();
            assert!(result.0 == flow_key);
            assert!(result.1.read().unwrap().dst_vni.is_none());
        }
    }
    #[concurrency_mode(shuttle)]
    mod shuttle_tests {
        use super::*;
        use concurrency::sync::Arc;
        use concurrency::thread;

        #[test]
        fn test_flow_table_reshard() {
            shuttle::check_random(
                move || {
                    let flow_table = Arc::new(FlowTable::default());

                    let flow_key1 = FlowKey {
                        src_vni: Vni::new_checked(1).unwrap(),
                        src_ip: "1.2.3.4".parse::<IpAddr>().unwrap(),
                        dst_ip: "4.5.6.7".parse::<IpAddr>().unwrap(),
                        dst_vni: Vni::new_checked(2).unwrap(),
                        ip_proto_number: 6,
                    };

                    let flow_key2 = FlowKey {
                        src_vni: Vni::new_checked(10).unwrap(),
                        src_ip: "10.2.3.4".parse::<IpAddr>().unwrap(),
                        dst_ip: "40.5.6.7".parse::<IpAddr>().unwrap(),
                        dst_vni: Vni::new_checked(20).unwrap(),
                        ip_proto_number: 6,
                    };

                    let flow_table_clone1 = flow_table.clone();
                    let flow_table_clone2 = flow_table.clone();
                    let flow_table_clone3 = flow_table.clone();

                    let mut handles = vec![];

                    handles.push(thread::spawn(move || {
                        flow_table_clone1.insert(
                            flow_key1,
                            FlowInfo {
                                dst_vni: Some(Vni::new_checked(3).unwrap()),
                            },
                        );
                        let result = flow_table_clone1.remove(&flow_key1).unwrap();
                        assert!(result.0 == flow_key1);
                        assert_eq!(
                            result.1.read().unwrap().dst_vni,
                            Some(Vni::new_checked(3).unwrap())
                        );
                    }));

                    handles.push(thread::spawn(move || {
                        flow_table_clone2.insert(
                            flow_key2,
                            FlowInfo {
                                dst_vni: Some(Vni::new_checked(4).unwrap()),
                            },
                        );
                        let result = flow_table.remove(&flow_key2).unwrap();
                        assert!(result.0 == flow_key2);
                        assert_eq!(
                            result.1.read().unwrap().dst_vni,
                            Some(Vni::new_checked(4).unwrap())
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
