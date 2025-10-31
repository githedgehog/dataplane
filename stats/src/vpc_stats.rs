// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VPC statistics store
//! Maintains per-VPC and per-VPC-pair counters and rates.
//! Iteratable for gRPC exposure.

use concurrency::sync::Arc;
use concurrency::sync::RwLock as StdRwLock;
use std::collections::HashMap;
use tokio::sync::RwLock;
use vpcmap::VpcDiscriminant;

pub type VpcId = VpcDiscriminant;
pub type VpcPairKey = (VpcId, VpcId);

#[derive(Debug, Clone, Copy, Default)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Rates {
    pub pps: f64,
    pub bps: f64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FlowStats {
    pub ctr: Counters, // monotonic counters
    pub rate: Rates,   // latest snapshot of rates
}

#[derive(Debug, Default)]
pub struct VpcStatsStore {
    /// Directional (src -> dst)
    pair_stats: RwLock<HashMap<VpcPairKey, FlowStats>>,
    /// Per-VPC totals (by src)
    vpc_stats: RwLock<HashMap<VpcId, FlowStats>>,
    /// Human-friendly names keyed by discriminant (seeded from config / refreshed by dpstats)
    vpc_names: StdRwLock<HashMap<VpcId, String>>,
}

impl VpcStatsStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_many_vpc_names_sync(&self, pairs: Vec<(VpcId, String)>) {
        let mut m = self
            .vpc_names
            .write()
            .expect("vpc_names write lock poisoned");
        for (id, name) in pairs {
            m.insert(id, name);
        }
    }

    pub fn set_vpc_name_sync(&self, id: VpcId, name: String) {
        let mut m = self
            .vpc_names
            .write()
            .expect("vpc_names write lock poisoned");
        m.insert(id, name);
    }

    pub fn name_of(&self, id: VpcId) -> Option<String> {
        self.vpc_names
            .read()
            .expect("vpc_names read lock poisoned")
            .get(&id)
            .cloned()
    }

    // ---------- Pair (src -> dst) ----------
    pub async fn add_pair_counts(&self, src: VpcId, dst: VpcId, add_packets: u64, add_bytes: u64) {
        let mut map = self.pair_stats.write().await;
        let e = map.entry((src, dst)).or_default();
        e.ctr.packets = e.ctr.packets.saturating_add(add_packets);
        e.ctr.bytes = e.ctr.bytes.saturating_add(add_bytes);
    }

    pub async fn set_pair_rates(&self, src: VpcId, dst: VpcId, pps: f64, bps: f64) {
        let mut map = self.pair_stats.write().await;
        let e = map.entry((src, dst)).or_default();
        e.rate.pps = pps;
        e.rate.bps = bps;
    }

    pub async fn record_pair(
        &self,
        src: VpcId,
        dst: VpcId,
        add_packets: u64,
        add_bytes: u64,
        pps: f64,
        bps: f64,
    ) {
        let mut map = self.pair_stats.write().await;
        let e = map.entry((src, dst)).or_default();
        e.ctr.packets = e.ctr.packets.saturating_add(add_packets);
        e.ctr.bytes = e.ctr.bytes.saturating_add(add_bytes);
        e.rate.pps = pps;
        e.rate.bps = bps;
    }

    // ---------- Per-VPC (src) totals ----------
    pub async fn add_vpc_counts(&self, vpc: VpcId, add_packets: u64, add_bytes: u64) {
        let mut map = self.vpc_stats.write().await;
        let e = map.entry(vpc).or_default();
        e.ctr.packets = e.ctr.packets.saturating_add(add_packets);
        e.ctr.bytes = e.ctr.bytes.saturating_add(add_bytes);
    }

    pub async fn set_vpc_rates(&self, vpc: VpcId, pps: f64, bps: f64) {
        let mut map = self.vpc_stats.write().await;
        let e = map.entry(vpc).or_default();
        e.rate.pps = pps;
        e.rate.bps = bps;
    }

    pub async fn record_vpc(
        &self,
        vpc: VpcId,
        add_packets: u64,
        add_bytes: u64,
        pps: f64,
        bps: f64,
    ) {
        let mut map = self.vpc_stats.write().await;
        let e = map.entry(vpc).or_default();
        e.ctr.packets = e.ctr.packets.saturating_add(add_packets);
        e.ctr.bytes = e.ctr.bytes.saturating_add(add_bytes);
        e.rate.pps = pps;
        e.rate.bps = bps;
    }

    // ---------- Snapshots ----------
    pub async fn snapshot_pairs(&self) -> Vec<(VpcPairKey, FlowStats)> {
        let map = self.pair_stats.read().await;
        map.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub async fn snapshot_vpcs(&self) -> Vec<(VpcId, FlowStats)> {
        let map = self.vpc_stats.read().await;
        map.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Snapshot all VPC names. Declared async to match callers that `.await` it,
    /// but it does not perform any awaits internally.
    pub async fn snapshot_names(&self) -> HashMap<VpcId, String> {
        self.vpc_names
            .read()
            .expect("vpc_names read lock poisoned")
            .clone()
    }
}
