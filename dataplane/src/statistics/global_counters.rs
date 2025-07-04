// src/statistics/global_counters.rs

use metrics::{counter, describe_counter, describe_gauge, gauge};
use stats::PacketStats;

/// Metric name constants
pub const VPC_PACKETS_TOTAL: &str = "vpc_packets_total";
pub const VPC_BYTES_TOTAL: &str = "vpc_bytes_total";
pub const VPC_DROPS_TOTAL: &str = "vpc_drops_total";
pub const METRICS_REQUESTS_TOTAL: &str = "metrics_requests_total";

/// Initialize metrics descriptions
pub fn init_metrics() {
    describe_gauge!(VPC_PACKETS_TOTAL, "Total packets per VPC");
    describe_gauge!(VPC_BYTES_TOTAL, "Total bytes per VPC");
    describe_gauge!(VPC_DROPS_TOTAL, "Total packet drops per VPC");
    describe_counter!(
        METRICS_REQUESTS_TOTAL,
        "Total number of /metrics endpoint requests"
    );
}

pub fn sync_to_prometheus(packet_stats: &PacketStats) {
    // Increment the metrics request counter
    counter!(METRICS_REQUESTS_TOTAL).increment(1);

    packet_stats.vpcstats.values().for_each(|stats| {
        // packets RX by VPC
        gauge!(VPC_PACKETS_TOTAL, "vpc" => stats.vpc.clone(), "direction" => "rx")
            .set(stats.rx_pkts as f64);

        // bytes RX by VPC
        gauge!(VPC_BYTES_TOTAL, "vpc" => stats.vpc.clone(), "direction" => "rx")
            .set(stats.rx_bytes as f64);

        // packets TX by VPC
        gauge!(VPC_PACKETS_TOTAL, "vpc" => stats.vpc.clone(), "direction" => "tx")
            .set(stats.tx_pkts as f64);

        // bytes TX by VPC
        gauge!(VPC_BYTES_TOTAL, "vpc" => stats.vpc.clone(), "direction" => "tx")
            .set(stats.tx_bytes as f64);

        // TODO(fredi): add support for drops
    });
}
