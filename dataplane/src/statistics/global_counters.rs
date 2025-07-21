// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::cast_precision_loss)]

use metrics::{counter, describe_counter, describe_gauge, gauge};
use stats::PacketStats;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Instant;

/// Metric name constants for absolute values
pub const VPC_PKTS: &str = "vpc_pkts";
pub const VPC_BYTES: &str = "vpc_octets";
pub const VPC_DROPPED_PKTS: &str = "vpc_dropped_pkts";

/// Metric name constants for per-second rates
pub const VPC_PKTS_PER_SECOND: &str = "vpc_pkts_per_sec";
pub const VPC_BYTES_PER_SECOND: &str = "vpc_octets_per_sec";
pub const VPC_DROPPED_PKTS_PER_SECOND: &str = "vpc_dropped_pkts_per_sec";

pub const METRICS_REQUESTS: &str = "metrics_requests";

/// Metric name constants for peering (absolute values)
pub const PEERING_PKTS: &str = "peering_pkts";
pub const PEERING_BYTES: &str = "peering_octets";
pub const PEERING_DROPPED_PKTS: &str = "peering_dropped_pkts";
pub const PEERING_DROPPED_BYTES: &str = "peering_dropped_octets";

/// Metric name constants for peering rates
pub const PEERING_PKTS_PER_SECOND: &str = "peering_pkts_per_sec";
pub const PEERING_BYTES_PER_SECOND: &str = "peering_octets_per_sec";
pub const PEERING_DROPPED_PKTS_PER_SECOND: &str = "peering_dropped_pkts_per_sec";
pub const PEERING_DROPPED_BYTES_PER_SECOND: &str = "peering_dropped_octets_per_sec";

/// We need to have a snapshot of the last statistics to calculate rates.
#[derive(Debug, Clone)]
struct VpcStatsSnapshot {
    rx_pkts: u64,
    rx_bytes: u64,
    tx_pkts: u64,
    tx_bytes: u64,
    // TODO: Add drops when available
}

#[derive(Debug, Clone)]
struct PeeringStatsSnapshot {
    pkts: u64,
    bytes: u64,
    pkts_dropped: u64,
    bytes_dropped: u64,
}

#[derive(Debug)]
struct StatsHistory {
    last_timestamp: Instant,
    vpc_stats: HashMap<String, VpcStatsSnapshot>,
    peering_stats: HashMap<String, PeeringStatsSnapshot>, // Key: "src_vpc:dst_vpc"
}

impl Default for StatsHistory {
    fn default() -> Self {
        Self {
            last_timestamp: Instant::now(),
            vpc_stats: HashMap::new(),
            peering_stats: HashMap::new(),
        }
    }
}

/// Global state for tracking previous statistics
static STATS_HISTORY: Mutex<Option<StatsHistory>> = Mutex::new(None);

/// Global state for tracking removed VPCs that need metric cleanup
static REMOVED_VPCS: Mutex<HashSet<String>> = Mutex::new(HashSet::new());

/// Global state for tracking all known VPCs and peerings for cleanup
static KNOWN_METRICS: Mutex<KnownMetrics> = Mutex::new(KnownMetrics::new());

#[derive(Debug)]
struct KnownMetrics {
    vpc_names: HashSet<String>,
    peering_keys: HashSet<String>, // "src_vpc:dst_vpc"
}

impl KnownMetrics {
    const fn new() -> Self {
        Self {
            vpc_names: HashSet::new(),
            peering_keys: HashSet::new(),
        }
    }
}

/// Store removed VPCs for cleanup (called from config processor)
pub fn store_removed_vpcs(removed_vpcs: Vec<String>) {
    let mut removed_guard = REMOVED_VPCS.lock().unwrap();
    for vpc in removed_vpcs {
        removed_guard.insert(vpc);
    }
}

/// Initialize metrics descriptions
pub fn init_metrics() {
    // Absolute value metrics
    describe_gauge!(VPC_PKTS, "Total packets per VPC");
    describe_gauge!(VPC_BYTES, "Total octets per VPC");
    describe_gauge!(VPC_DROPPED_PKTS, "Total packet drops per VPC");

    // Rate metrics
    describe_gauge!(VPC_PKTS_PER_SECOND, "Packets per second per VPC");
    describe_gauge!(VPC_BYTES_PER_SECOND, "Octets per second per VPC");
    describe_gauge!(
        VPC_DROPPED_PKTS_PER_SECOND,
        "Packet drops per second per VPC"
    );

    // Peering absolute metrics
    describe_gauge!(PEERING_PKTS, "Total packets between VPCs");
    describe_gauge!(PEERING_BYTES, "Total octets between VPCs");
    describe_gauge!(PEERING_DROPPED_PKTS, "Total packet drops between VPCs");
    describe_gauge!(PEERING_DROPPED_BYTES, "Total octets drops between VPCs");

    // Peering rate metrics
    describe_gauge!(PEERING_PKTS_PER_SECOND, "Packets per second between VPCs");
    describe_gauge!(PEERING_BYTES_PER_SECOND, "Octets per second between VPCs");
    describe_gauge!(
        PEERING_DROPPED_PKTS_PER_SECOND,
        "Packet drops per second between VPCs"
    );
    describe_gauge!(
        PEERING_DROPPED_BYTES_PER_SECOND,
        "Octets drops per second between VPCs"
    );

    describe_counter!(
        METRICS_REQUESTS,
        "Total number of /metrics endpoint requests"
    );
}

/// Zero out all metrics for a removed VPC
fn zero_vpc_metrics(vpc_name: &str) {
    // Zero VPC metrics for both directions
    gauge!(VPC_PKTS, "vpc" => vpc_name, "direction" => "rx").set(0.0);
    gauge!(VPC_BYTES, "vpc" => vpc_name, "direction" => "rx").set(0.0);
    gauge!(VPC_PKTS, "vpc" => vpc_name, "direction" => "tx").set(0.0);
    gauge!(VPC_BYTES, "vpc" => vpc_name, "direction" => "tx").set(0.0);
    gauge!(VPC_DROPPED_PKTS, "vpc" => vpc_name, "direction" => "rx").set(0.0);
    gauge!(VPC_DROPPED_PKTS, "vpc" => vpc_name, "direction" => "tx").set(0.0);
    
    // Zero rate metrics
    gauge!(VPC_PKTS_PER_SECOND, "vpc" => vpc_name, "direction" => "rx").set(0.0);
    gauge!(VPC_BYTES_PER_SECOND, "vpc" => vpc_name, "direction" => "rx").set(0.0);
    gauge!(VPC_PKTS_PER_SECOND, "vpc" => vpc_name, "direction" => "tx").set(0.0);
    gauge!(VPC_BYTES_PER_SECOND, "vpc" => vpc_name, "direction" => "tx").set(0.0);
    gauge!(VPC_DROPPED_PKTS_PER_SECOND, "vpc" => vpc_name, "direction" => "rx").set(0.0);
    gauge!(VPC_DROPPED_PKTS_PER_SECOND, "vpc" => vpc_name, "direction" => "tx").set(0.0);
}

/// Zero out all peering metrics for a specific VPC (as source or destination)
fn zero_peering_metrics_for_vpc(vpc_name: &str, known_metrics: &KnownMetrics) {
    // Find all peering keys that involve this VPC
    let affected_peerings: Vec<String> = known_metrics
        .peering_keys
        .iter()
        .filter(|key| {
            let parts: Vec<&str> = key.split(':').collect();
            parts.len() == 2 && (parts[0] == vpc_name || parts[1] == vpc_name)
        })
        .cloned()
        .collect();
    
    for peering_key in affected_peerings {
        let parts: Vec<&str> = peering_key.split(':').collect();
        if parts.len() == 2 { // SMATOV: I am paranoic about the format, so good old C style check
            let src_vpc = parts[0];
            let dst_vpc = parts[1];
            zero_single_peering_metrics(src_vpc, dst_vpc);
        }
    }
}

/// Zero out metrics for a specific peering relationship
fn zero_single_peering_metrics(src_vpc: &str, dst_vpc: &str) {
    gauge!(PEERING_PKTS, "src" => src_vpc, "dst" => dst_vpc).set(0.0);
    gauge!(PEERING_BYTES, "src" => src_vpc, "dst" => dst_vpc).set(0.0);
    gauge!(PEERING_DROPPED_PKTS, "src" => src_vpc, "dst" => dst_vpc).set(0.0);
    gauge!(PEERING_DROPPED_BYTES, "src" => src_vpc, "dst" => dst_vpc).set(0.0);
    
    gauge!(PEERING_PKTS_PER_SECOND, "src" => src_vpc, "dst" => dst_vpc).set(0.0);
    gauge!(PEERING_BYTES_PER_SECOND, "src" => src_vpc, "dst" => dst_vpc).set(0.0);
    gauge!(PEERING_DROPPED_PKTS_PER_SECOND, "src" => src_vpc, "dst" => dst_vpc).set(0.0);
    gauge!(PEERING_DROPPED_BYTES_PER_SECOND, "src" => src_vpc, "dst" => dst_vpc).set(0.0);
}

/// Handle cleanup of removed VPCs
fn handle_removed_vpcs_cleanup() {
    let mut removed_guard = REMOVED_VPCS.lock().unwrap();
    if removed_guard.is_empty() {
        return;
    }
    
    let known_metrics_guard = KNOWN_METRICS.lock().unwrap();
    
    // Zero out metrics for each removed VPC
    for vpc_name in removed_guard.iter() {
        zero_vpc_metrics(vpc_name);
        zero_peering_metrics_for_vpc(vpc_name, &known_metrics_guard);
    }
    
    // Clear the removed VPCs list
    removed_guard.clear();
    drop(known_metrics_guard);
    drop(removed_guard);
}

/// Clean up metrics for peerings that no longer exist
fn cleanup_stale_peering_metrics(current_peerings: &HashSet<String>) {
    let mut known_metrics_guard = KNOWN_METRICS.lock().unwrap();
    
    // Find peerings that existed before but don't exist now
    let removed_peerings: Vec<String> = known_metrics_guard
        .peering_keys
        .difference(current_peerings)
        .cloned()
        .collect();
    
    // Zero out metrics for removed peerings
    for peering_key in removed_peerings {
        let parts: Vec<&str> = peering_key.split(':').collect();
        if parts.len() == 2 {
            let src_vpc = parts[0];
            let dst_vpc = parts[1];
            zero_single_peering_metrics(src_vpc, dst_vpc);
        }
    }
    
    // Update known peerings
    known_metrics_guard.peering_keys = current_peerings.clone();
}

pub fn sync_to_prometheus(packet_stats: &PacketStats) {
    // Increment the metrics request counter
    counter!(METRICS_REQUESTS).increment(1);

    // Handle cleanup of removed VPCs first
    handle_removed_vpcs_cleanup();

    let now = Instant::now();
    let mut history_guard = STATS_HISTORY.lock().unwrap();

    // Calculate time delta
    let time_delta_secs = if let Some(ref history) = *history_guard {
        now.duration_since(history.last_timestamp).as_secs_f64()
    } else {
        // First run, no rate calculation possible
        1.0 // Avoid division by zero
    };

    // Track current VPCs and peerings for cleanup
    let mut current_vpc_names = HashSet::new();
    let mut current_peering_keys = HashSet::new();

    // Process VPC statistics
    packet_stats.vpcstats.values().for_each(|stats| {
        let vpc_name = &stats.vpc;
        current_vpc_names.insert(vpc_name.clone());

        // Set absolute values
        gauge!(VPC_PKTS, "vpc" => vpc_name.clone(), "direction" => "rx").set(stats.rx_pkts as f64);
        gauge!(VPC_BYTES, "vpc" => vpc_name.clone(), "direction" => "rx")
            .set(stats.rx_bytes as f64);
        gauge!(VPC_PKTS, "vpc" => vpc_name.clone(), "direction" => "tx").set(stats.tx_pkts as f64);
        gauge!(VPC_BYTES, "vpc" => vpc_name.clone(), "direction" => "tx")
            .set(stats.tx_bytes as f64);

        // Calculate and set rates if we have previous data
        if let Some(ref history) = *history_guard {
            if let Some(prev_stats) = history.vpc_stats.get(vpc_name) {
                if time_delta_secs > 0.0 {
                    // Calculate RX rates
                    let rx_pkts_rate =
                        (stats.rx_pkts.saturating_sub(prev_stats.rx_pkts) as f64) / time_delta_secs;
                    let rx_bytes_rate = (stats.rx_bytes.saturating_sub(prev_stats.rx_bytes) as f64)
                        / time_delta_secs;

                    // Calculate TX rates
                    let tx_pkts_rate =
                        (stats.tx_pkts.saturating_sub(prev_stats.tx_pkts) as f64) / time_delta_secs;
                    let tx_bytes_rate = (stats.tx_bytes.saturating_sub(prev_stats.tx_bytes) as f64)
                        / time_delta_secs;

                    // Set rate gauges
                    gauge!(VPC_PKTS_PER_SECOND, "vpc" => vpc_name.clone(), "direction" => "rx")
                        .set(rx_pkts_rate);
                    gauge!(VPC_BYTES_PER_SECOND, "vpc" => vpc_name.clone(), "direction" => "rx")
                        .set(rx_bytes_rate);
                    gauge!(VPC_PKTS_PER_SECOND, "vpc" => vpc_name.clone(), "direction" => "tx")
                        .set(tx_pkts_rate);
                    gauge!(VPC_BYTES_PER_SECOND, "vpc" => vpc_name.clone(), "direction" => "tx")
                        .set(tx_bytes_rate);
                }
            }
        }
    });

    // Process peering statistics
    packet_stats.vpcmatrix.values().for_each(|stats| {
        let src_vpc = &stats.src_vpc;
        let dst_vpc = &stats.dst_vpc;
        let peering_key = format!("{src_vpc}:{dst_vpc}");
        current_peering_keys.insert(peering_key.clone());

        // Set absolute values
        gauge!(PEERING_PKTS, "src" => src_vpc.clone(), "dst" => dst_vpc.clone()).set(stats.pkts as f64);
        gauge!(PEERING_BYTES, "src" => src_vpc.clone(), "dst" => dst_vpc.clone()).set(stats.bytes as f64);
        gauge!(PEERING_DROPPED_PKTS, "src" => src_vpc.clone(), "dst" => dst_vpc.clone()).set(stats.pkts_dropped as f64);
        gauge!(PEERING_DROPPED_BYTES, "src" => src_vpc.clone(), "dst" => dst_vpc.clone()).set(stats.bytes_dropped as f64);

        // Calculate and set rates if we have previous data
        if let Some(ref history) = *history_guard {
            if let Some(prev_stats) = history.peering_stats.get(&peering_key) {
                if time_delta_secs > 0.0 {
                    let pkts_rate = (stats.pkts.saturating_sub(prev_stats.pkts) as f64) / time_delta_secs;
                    let bytes_rate = (stats.bytes.saturating_sub(prev_stats.bytes) as f64) / time_delta_secs;
                    let pkts_dropped_rate = (stats.pkts_dropped.saturating_sub(prev_stats.pkts_dropped) as f64) / time_delta_secs;
                    let bytes_dropped_rate = (stats.bytes_dropped.saturating_sub(prev_stats.bytes_dropped) as f64) / time_delta_secs;

                    gauge!(PEERING_PKTS_PER_SECOND, "src" => src_vpc.clone(), "dst" => dst_vpc.clone()).set(pkts_rate);
                    gauge!(PEERING_BYTES_PER_SECOND, "src" => src_vpc.clone(), "dst" => dst_vpc.clone()).set(bytes_rate);
                    gauge!(PEERING_DROPPED_PKTS_PER_SECOND, "src" => src_vpc.clone(), "dst" => dst_vpc.clone()).set(pkts_dropped_rate);
                    gauge!(PEERING_DROPPED_BYTES_PER_SECOND, "src" => src_vpc.clone(), "dst" => dst_vpc.clone()).set(bytes_dropped_rate);
                }
            }
        }
    });

    // Clean up stale peering metrics
    cleanup_stale_peering_metrics(&current_peering_keys);

    // Update history with current values
    let mut new_vpc_stats = HashMap::new();
    packet_stats.vpcstats.values().for_each(|stats| {
        new_vpc_stats.insert(
            stats.vpc.clone(),
            VpcStatsSnapshot {
                rx_pkts: stats.rx_pkts,
                rx_bytes: stats.rx_bytes,
                tx_pkts: stats.tx_pkts,
                tx_bytes: stats.tx_bytes,
            },
        );
    });

    let mut new_peering_stats = HashMap::new();
    packet_stats.vpcmatrix.values().for_each(|stats| {
        let peering_key = format!("{}:{}", stats.src_vpc, stats.dst_vpc);
        new_peering_stats.insert(
            peering_key,
            PeeringStatsSnapshot {
                pkts: stats.pkts,
                bytes: stats.bytes,
                pkts_dropped: stats.pkts_dropped,
                bytes_dropped: stats.bytes_dropped,
            },
        );
    });

    *history_guard = Some(StatsHistory {
        last_timestamp: now,
        vpc_stats: new_vpc_stats,
        peering_stats: new_peering_stats,
    });

    // Update known metrics for future cleanup
    {
        let mut known_metrics_guard = KNOWN_METRICS.lock().unwrap();
        known_metrics_guard.vpc_names = current_vpc_names;
        known_metrics_guard.peering_keys = current_peering_keys;
    }
}