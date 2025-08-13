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
    pub(crate) table: RwLock<DashMap<FlowKey, Arc<RwLock<FlowInfo>>>>,
}

impl FlowTable {
    #[must_use]
    pub fn new() -> RwLock<Self> {
        RwLock::new(Self {
            table: RwLock::new(DashMap::new()),
        })
    }

    /// Add a flow to the table.
    ///
    /// # Panics
    ///
    /// Panics if the this thread already holds the read lock on the table or
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
