// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What each worker did on each of its ports.
//!
//! Drivers convert their own totals into [`WorkerCounters`], keeping this API independent of any
//! one driver. [`WorkerMetrics`] registers once per worker and port and publishes cumulative values
//! with [`Counter::absolute`](metrics::Counter::absolute), as [`PortMetrics`](crate::PortMetrics)
//! does. Series are `worker_<counter>`, labelled `worker` and `port`.

use metrics::Unit;

use crate::register::{Register, Registered};
use crate::spec::MetricSpec;

/// Base id of the worker counter family. Every series is `{BASE}_{suffix}`.
pub(crate) const WORKER_METRIC_BASE: &str = "worker";

/// A worker's totals for one port, since it started.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct WorkerCounters {
    /// Packets received.
    pub rx_packets: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// Packets received that the pipeline dropped.
    pub pipeline_drops: u64,
    /// Packets that could not be transmitted.
    pub tx_drops: u64,
    /// Packets for the kernel that could not be handed to it.
    pub punt_drops: u64,
    /// Frames that did not parse.
    pub parse_errors: u64,
    /// Frames larger than the receive buffer.
    pub truncated: u64,
    /// Empty reads (kernel driver).
    pub zero_len: u64,
    /// Frames the kernel dropped before the worker read them (kernel driver).
    pub kernel_drops: u64,
}

/// Metric handles for one worker's port, registered once and reused for each poll.
#[derive(Debug)]
pub struct WorkerMetrics {
    series: [Registered<metrics::Counter>; 9],
}

/// A series' suffix, its description, and the field it carries.
type Series = (&'static str, &'static str, fn(&WorkerCounters) -> u64);

/// Every series.
const SERIES: [Series; 9] = [
    (
        "rx_packets",
        "packets the worker received on the port",
        |c| c.rx_packets,
    ),
    (
        "tx_packets",
        "packets the worker transmitted on the port",
        |c| c.tx_packets,
    ),
    ("pipeline_drops", "packets the pipeline dropped", |c| {
        c.pipeline_drops
    }),
    ("tx_drops", "packets that could not be transmitted", |c| {
        c.tx_drops
    }),
    (
        "punt_drops",
        "packets for the kernel that could not be handed to it",
        |c| c.punt_drops,
    ),
    ("parse_errors", "frames that did not parse", |c| {
        c.parse_errors
    }),
    ("truncated", "frames larger than the receive buffer", |c| {
        c.truncated
    }),
    ("zero_len", "empty reads", |c| c.zero_len),
    (
        "kernel_drops",
        "frames the kernel dropped before the worker read them",
        |c| c.kernel_drops,
    ),
];

impl WorkerMetrics {
    /// Register the counters of worker `worker` on port `port`, the configured interface name.
    #[must_use]
    pub fn new(worker: usize, port: &str) -> WorkerMetrics {
        let series = SERIES.map(|(suffix, description, _)| {
            let mut spec = MetricSpec::new(
                format!("{WORKER_METRIC_BASE}_{suffix}"),
                Unit::Count,
                vec![
                    ("worker".to_string(), worker.to_string()),
                    ("port".to_string(), port.to_string()),
                ],
            );
            spec.description = description.to_string();
            spec.register()
        });
        WorkerMetrics { series }
    }

    /// Publish a snapshot of the totals.
    pub fn publish(&self, counters: &WorkerCounters) {
        for (registered, (_, _, field)) in self.series.iter().zip(SERIES) {
            registered.metric.absolute(field(counters));
        }
    }
}

#[cfg(test)]
mod exported {
    use super::*;
    use crate::scrape::Scrape;

    fn distinct() -> WorkerCounters {
        WorkerCounters {
            rx_packets: 11,
            tx_packets: 22,
            pipeline_drops: 33,
            tx_drops: 44,
            punt_drops: 55,
            parse_errors: 66,
            truncated: 77,
            zero_len: 88,
            kernel_drops: 99,
        }
    }

    #[test]
    fn every_counter_reaches_its_own_series_for_its_worker_and_port() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            WorkerMetrics::new(0, "eth0").publish(&distinct());
            WorkerMetrics::new(1, "eth0").publish(&WorkerCounters::default());
        });
        let counters = distinct();
        for (suffix, _, field) in SERIES {
            let id = format!("{WORKER_METRIC_BASE}_{suffix}");
            assert_eq!(
                scrape.counter(&id, &[("worker", "0"), ("port", "eth0")]),
                Some(field(&counters)),
                "{id} did not export the value it was given"
            );
            assert_eq!(
                scrape.counter(&id, &[("worker", "1"), ("port", "eth0")]),
                Some(0),
                "{id} mixed up its workers"
            );
            assert_eq!(
                scrape.label_shapes(&id),
                [vec!["port".to_string(), "worker".to_string()]]
                    .into_iter()
                    .collect(),
            );
        }
    }

    #[test]
    fn republishing_does_not_accumulate() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let metrics = WorkerMetrics::new(0, "eth0");
            metrics.publish(&distinct());
            metrics.publish(&distinct());
        });
        assert_eq!(
            scrape.counter("worker_rx_packets", &[("worker", "0"), ("port", "eth0")]),
            Some(11)
        );
    }
}
