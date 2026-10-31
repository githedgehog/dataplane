// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What each worker did with what arrived on each of its ports.
//!
//! Drivers convert their own totals into [`WorkerCounters`], keeping this API independent of any
//! one driver. [`WorkerMetrics`] registers once per worker, port and queue and publishes cumulative
//! values with [`Counter::absolute`](metrics::Counter::absolute), as
//! [`PortMetrics`](crate::PortMetrics) does. Series are `worker_<counter>`, labelled `worker`,
//! `port` (the configured interface name) and `queue` (which of the port's receive queues).
//!
//! A packet counts against the port it arrived on, whichever port it left by: one received on
//! `eth0` and sent out of `eth1` is forwarded on `eth0`. What leaves a port is the NIC's to count,
//! as `port_tx_packets`. The exception is what the kernel sends out of a port through the worker,
//! which counts against that port as injected.

use metrics::Unit;

use crate::register::{Register, Registered};
use crate::spec::MetricSpec;

/// Base id of the worker counter family. Every series is `{BASE}_{suffix}`.
pub(crate) const WORKER_METRIC_BASE: &str = "worker";

/// A worker's totals for one port, since it started.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct WorkerCounters {
    /// Packets received.
    pub rx_packets: u64,
    /// Packets received and transmitted, on whichever port they left by.
    pub forwarded_packets: u64,
    /// Packets received that the pipeline dropped.
    pub pipeline_drops: u64,
    /// Packets received that the pipeline forwarded but that could not be transmitted.
    pub forward_drops: u64,
    /// Packets received for the kernel that could not be handed to it.
    pub punt_drops: u64,
    /// Frames that did not parse.
    pub parse_errors: u64,
    /// Frames larger than the receive buffer.
    pub truncated: u64,
    /// Frames whose checksum state the kernel did not report, treated as needing a refresh
    /// (kernel driver).
    pub csum_unknown: u64,
    /// Empty reads (kernel driver).
    pub zero_len: u64,
    /// Frames the kernel dropped before the worker read them (kernel driver).
    pub kernel_drops: u64,
    /// Frames the kernel sent out of the port that the worker transmitted (DPDK driver).
    pub injected_packets: u64,
    /// Frames the kernel sent out of the port that could not be transmitted (DPDK driver).
    pub inject_drops: u64,
    /// Receive calls that returned packets; `rx_packets` over this is the mean batch.
    pub bursts: u64,
    /// Receive calls that returned as many packets as they could: the queue had more waiting.
    pub full_bursts: u64,
}

/// Metric handles for one worker's port queue, registered once and reused for each poll.
#[derive(Debug)]
pub struct WorkerMetrics {
    series: [Registered<metrics::Counter>; 14],
}

/// A series' suffix, its description, and the field it carries.
type Series = (&'static str, &'static str, fn(&WorkerCounters) -> u64);

/// Every series.
const SERIES: [Series; 14] = [
    (
        "rx_packets",
        "packets the worker received on the port",
        |c| c.rx_packets,
    ),
    (
        "forwarded_packets",
        "packets received on the port that the worker transmitted, on whichever port they left by",
        |c| c.forwarded_packets,
    ),
    (
        "pipeline_drops",
        "packets received on the port that the pipeline dropped",
        |c| c.pipeline_drops,
    ),
    (
        "forward_drops",
        "packets received on the port that the pipeline forwarded but could not be transmitted",
        |c| c.forward_drops,
    ),
    (
        "punt_drops",
        "packets received on the port for the kernel that could not be handed to it",
        |c| c.punt_drops,
    ),
    (
        "parse_errors",
        "frames received on the port that did not parse",
        |c| c.parse_errors,
    ),
    (
        "truncated",
        "frames received on the port larger than the receive buffer",
        |c| c.truncated,
    ),
    (
        "csum_unknown",
        "frames received on the port whose checksum state the kernel did not report",
        |c| c.csum_unknown,
    ),
    ("zero_len", "empty reads on the port", |c| c.zero_len),
    (
        "kernel_drops",
        "frames for the port that the kernel dropped before the worker read them",
        |c| c.kernel_drops,
    ),
    (
        "injected_packets",
        "frames the kernel sent out of the port that the worker transmitted",
        |c| c.injected_packets,
    ),
    (
        "inject_drops",
        "frames the kernel sent out of the port that could not be transmitted",
        |c| c.inject_drops,
    ),
    (
        "bursts",
        "receive calls on the port that returned packets; rx_packets over this is the mean batch",
        |c| c.bursts,
    ),
    (
        "full_bursts",
        "receive calls on the port that returned as many packets as they could: the worker is \
         falling behind that queue",
        |c| c.full_bursts,
    ),
];

impl WorkerMetrics {
    /// Register the counters of worker `worker` on `queue` of port `port`, the configured interface
    /// name.
    #[must_use]
    pub fn new(worker: usize, port: &str, queue: &str) -> WorkerMetrics {
        let series = SERIES.map(|(suffix, description, _)| {
            let mut spec = MetricSpec::new(
                format!("{WORKER_METRIC_BASE}_{suffix}"),
                Unit::Count,
                vec![
                    ("worker".to_string(), worker.to_string()),
                    ("port".to_string(), port.to_string()),
                    ("queue".to_string(), queue.to_string()),
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
            forwarded_packets: 22,
            pipeline_drops: 33,
            forward_drops: 44,
            punt_drops: 55,
            parse_errors: 66,
            truncated: 77,
            csum_unknown: 133,
            zero_len: 88,
            kernel_drops: 99,
            injected_packets: 111,
            inject_drops: 122,
            bursts: 144,
            full_bursts: 155,
        }
    }

    #[test]
    fn every_counter_reaches_its_own_series_for_its_worker_port_and_queue() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            WorkerMetrics::new(0, "eth0", "data").publish(&distinct());
            WorkerMetrics::new(1, "eth0", "data").publish(&WorkerCounters::default());
            WorkerMetrics::new(0, "eth0", "control").publish(&WorkerCounters::default());
        });
        let counters = distinct();
        for (suffix, _, field) in SERIES {
            let id = format!("{WORKER_METRIC_BASE}_{suffix}");
            assert_eq!(
                scrape.counter(&id, &[("worker", "0"), ("port", "eth0"), ("queue", "data")]),
                Some(field(&counters)),
                "{id} did not export the value it was given"
            );
            assert_eq!(
                scrape.counter(&id, &[("worker", "1"), ("port", "eth0"), ("queue", "data")]),
                Some(0),
                "{id} mixed up its workers"
            );
            assert_eq!(
                scrape.counter(
                    &id,
                    &[("worker", "0"), ("port", "eth0"), ("queue", "control")]
                ),
                Some(0),
                "{id} mixed up its queues"
            );
            assert_eq!(
                scrape.label_shapes(&id),
                [vec![
                    "port".to_string(),
                    "queue".to_string(),
                    "worker".to_string()
                ]]
                .into_iter()
                .collect(),
            );
        }
    }

    /// Whatever the totals, a series carries the latest given, rather than adding them up.
    #[test]
    fn republishing_does_not_accumulate() {
        bolero::check!()
            .with_type::<(WorkerCounters, u32)>()
            .for_each(|(first, more)| {
                // Totals only grow: the later ones are the first plus some more of each.
                let later = |c: u64| c.saturating_add(u64::from(*more));
                let then = WorkerCounters {
                    rx_packets: later(first.rx_packets),
                    forwarded_packets: later(first.forwarded_packets),
                    pipeline_drops: later(first.pipeline_drops),
                    forward_drops: later(first.forward_drops),
                    punt_drops: later(first.punt_drops),
                    parse_errors: later(first.parse_errors),
                    truncated: later(first.truncated),
                    csum_unknown: later(first.csum_unknown),
                    zero_len: later(first.zero_len),
                    kernel_drops: later(first.kernel_drops),
                    injected_packets: later(first.injected_packets),
                    inject_drops: later(first.inject_drops),
                    bursts: later(first.bursts),
                    full_bursts: later(first.full_bursts),
                };
                let scrape = Scrape::default();
                metrics::with_local_recorder(&scrape, || {
                    let metrics = WorkerMetrics::new(0, "eth0", "data");
                    metrics.publish(first);
                    metrics.publish(first);
                    metrics.publish(&then);
                });
                for (suffix, _, field) in SERIES {
                    let id = format!("{WORKER_METRIC_BASE}_{suffix}");
                    assert_eq!(
                        scrape
                            .counter(&id, &[("worker", "0"), ("port", "eth0"), ("queue", "data")]),
                        Some(field(&then)),
                        "{id} did not carry the latest total"
                    );
                }
            });
    }
}
