// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use dashmap::DashMap;

use concurrency::sync::{Arc, RwLock};
use net::vxlan::Vni;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    src_vni: Vni,
    dst_vni: Vni,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ip_proto_number: u8,
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // FIXME(manishv) make this symmetric
        self.src_vni.hash(state);
        self.dst_vni.hash(state);
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.ip_proto_number.hash(state);
    }
}

pub struct FlowInfo {
    pub dst_vni: Option<Vni>,
}

pub struct FlowTable {
    // FIXME(mvachhar) move this to a cross beam sharded lock
    pub(crate) table: RwLock<DashMap<FlowKey, Arc<RwLock<FlowInfo>>>>,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl FlowTable {
    #[must_use]
    pub fn new(num_shards: usize) -> Self {
        Self {
            table: RwLock::new(DashMap::with_shard_amount(num_shards)),
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
        let new_table = DashMap::with_shard_amount(num_shards);
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
    pub fn insert(&self, flow_key: FlowKey, flow_info: FlowInfo) {
        let table = self.table.read().unwrap();
        table.insert(flow_key, Arc::new(RwLock::new(flow_info)));
    }

    /// Remove a flow from the table.
    ///
    /// # Panics
    ///
    /// Panics if this thread already holds the read lock on the table or
    /// if the table lock is poisoned.
    pub fn remove<Q>(&self, flow_key: &Q) -> Option<(FlowKey, Arc<RwLock<FlowInfo>>)>
    where
        FlowKey: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let table = self.table.read().unwrap();
        table.remove(flow_key)
    }
}

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
