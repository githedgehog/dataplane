// src/statistics/global_counters.rs

use metrics::{counter, describe_counter, describe_gauge, gauge};

#[derive(Debug, Clone)]
pub struct VpcCounters {
    pub name: String,
    pub rx: u64,
    pub tx: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub drops: u64,
}

impl VpcCounters {
    pub fn new(name: String) -> Self {
        Self {
            name,
            rx: 0,
            tx: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            drops: 0,
        }
    }
}

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

/// Sync VPC data to Prometheus metrics (called on /metrics request)
pub fn sync_to_prometheus(vpc_counters: Vec<VpcCounters>) {
    // Increment the metrics request counter
    counter!(METRICS_REQUESTS_TOTAL).increment(1);

    // Populate metrics crate counters using gauge!() macro
    for vpc in vpc_counters {
        let vpc_name = vpc.name.clone();

        // RX packets
        gauge!(VPC_PACKETS_TOTAL, "vpc" => vpc_name.clone(), "direction" => "rx")
            .set(vpc.rx as f64);

        // TX packets
        gauge!(VPC_PACKETS_TOTAL, "vpc" => vpc_name.clone(), "direction" => "tx")
            .set(vpc.tx as f64);

        // RX bytes
        gauge!(VPC_BYTES_TOTAL, "vpc" => vpc_name.clone(), "direction" => "rx")
            .set(vpc.rx_bytes as f64);

        // TX bytes
        gauge!(VPC_BYTES_TOTAL, "vpc" => vpc_name.clone(), "direction" => "tx")
            .set(vpc.tx_bytes as f64);

        // Drops
        gauge!(VPC_DROPS_TOTAL, "vpc" => vpc_name).set(vpc.drops as f64);
    }
}
