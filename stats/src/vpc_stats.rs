// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VPC statistics in-memory store
//! iteratable by the gRPC server for reporting

use std::collections::HashMap;
use std::sync::Arc;
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
}

impl VpcStatsStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    // ---------- Pair (src -> dst) ----------

    /// Increment monotonic counters for (src,dst).
    pub async fn add_pair_counts(&self, src: VpcId, dst: VpcId, add_packets: u64, add_bytes: u64) {
        let mut map = self.pair_stats.write().await;
        let e = map.entry((src, dst)).or_default();
        e.ctr.packets = e.ctr.packets.saturating_add(add_packets);
        e.ctr.bytes = e.ctr.bytes.saturating_add(add_bytes);
    }

    /// Set current rates for (src,dst).
    pub async fn set_pair_rates(&self, src: VpcId, dst: VpcId, pps: f64, bps: f64) {
        let mut map = self.pair_stats.write().await;
        let e = map.entry((src, dst)).or_default();
        e.rate.pps = pps;
        e.rate.bps = bps;
    }

    /// Convenience: update both counters and rates in one call.
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

    // ---------- Snapshots (optional helpers) ----------

    pub async fn snapshot_pairs(&self) -> Vec<(VpcPairKey, FlowStats)> {
        let map = self.pair_stats.read().await;
        map.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub async fn snapshot_vpcs(&self) -> Vec<(VpcId, FlowStats)> {
        let map = self.vpc_stats.read().await;
        map.iter().map(|(k, v)| (*k, *v)).collect()
    }
}
