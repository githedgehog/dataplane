// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::cast_precision_loss)]

use metrics::{counter, describe_counter, describe_gauge, gauge};
use stats::PacketStats;

/// Metric name constants
pub const VPC_PKTS: &str = "vpc_pkts";
pub const VPC_BYTES: &str = "vpc_octets";
pub const VPC_DROPPED_PKTS: &str = "vpc_dropped_pkts";
pub const METRICS_REQUESTS: &str = "metrics_requests";

/// Metric name constants
pub const PEERING_PKTS: &str = "peering_pkts";
pub const PEERING_BYTES: &str = "peering_octets";
pub const PEERING_DROPPED_PKTS: &str = "peering_dropped_pkts";
pub const PEERING_DROPPED_BYTES: &str = "peering_dropped_octets";

/// Initialize metrics descriptions
pub fn init_metrics() {
    describe_gauge!(VPC_PKTS, "Total packets per VPC");
    describe_gauge!(VPC_BYTES, "Total octets per VPC");
    describe_gauge!(VPC_DROPPED_PKTS, "Total packet drops per VPC");
    describe_counter!(
        METRICS_REQUESTS,
        "Total number of /metrics endpoint requests"
    );
}

pub fn sync_to_prometheus(packet_stats: &PacketStats) {
    // Increment the metrics request counter
    counter!(METRICS_REQUESTS).increment(1);

    packet_stats.vpcstats.values().for_each(|stats| {
        // packets RX by VPC
        gauge!(VPC_PKTS, "vpc" => stats.vpc.clone(), "direction" => "rx").set(stats.rx_pkts as f64);

        // bytes RX by VPC
        gauge!(VPC_BYTES, "vpc" => stats.vpc.clone(), "direction" => "rx")
            .set(stats.rx_bytes as f64);

        // packets TX by VPC
        gauge!(VPC_PKTS, "vpc" => stats.vpc.clone(), "direction" => "tx").set(stats.tx_pkts as f64);

        // bytes TX by VPC
        gauge!(VPC_BYTES, "vpc" => stats.vpc.clone(), "direction" => "tx")
            .set(stats.tx_bytes as f64);

        // TODO(fredi): add support for drops
    });

    // FIXME(fredi): expose peering names
    packet_stats.vpcmatrix.values().for_each(|stats| {
        // packets from src to dst
        gauge!(PEERING_PKTS, "src" => stats.src_vpc.clone(), "dst" => stats.dst_vpc.clone())
            .set(stats.pkts as f64);

        // octets from src to dst
        gauge!(PEERING_BYTES, "src" => stats.src_vpc.clone(), "dst" => stats.dst_vpc.clone())
            .set(stats.bytes as f64);

        // packet drops from src to dst
        gauge!(PEERING_DROPPED_PKTS, "src" => stats.src_vpc.clone(), "dst" => stats.dst_vpc.clone())
            .set(stats.pkts_dropped as f64);

        // octets drops from src to dst
        gauge!(PEERING_DROPPED_BYTES, "src" => stats.src_vpc.clone(), "dst" => stats.dst_vpc.clone())
            .set(stats.bytes_dropped as f64);
    });
}
