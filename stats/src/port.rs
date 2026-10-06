// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Device counters, including drops before a packet reaches the pipeline.
//!
//! Drivers convert snapshots into [`PortCounters`], keeping this API independent of DPDK.
//! [`PortMetrics`] registers once per port and publishes cumulative values with
//! [`Counter::absolute`](metrics::Counter::absolute), so repeated polls do not double-count.

use crate::register::{Register, Registered};
use crate::spec::MetricSpec;
use metrics::Unit;

/// Base id of the port counter metric family. Every series below is `{BASE}_{suffix}`.
pub(crate) const PORT_METRIC_BASE: &str = "port";

/// A snapshot of the counters a device keeps for one port.
///
/// Cumulative since the port started, not deltas.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct PortCounters {
    /// Packets the port received and delivered to the dataplane.
    pub rx_packets: u64,
    /// Packets the port transmitted.
    pub tx_packets: u64,
    /// Bytes the port received.
    pub rx_bytes: u64,
    /// Bytes the port transmitted.
    pub tx_bytes: u64,
    /// Packets dropped because no receive descriptor was free; absent from pipeline counters.
    pub rx_missed: u64,
    /// Erroneous packets received.
    pub rx_errors: u64,
    /// Packets that failed to transmit.
    pub tx_errors: u64,
    /// Receive mbuf allocation failures, counted separately from [`Self::rx_missed`].
    pub rx_no_mbuf: u64,
}

/// Metric handles registered once per port and reused for each poll.
#[derive(Debug)]
pub struct PortMetrics {
    rx_packets: Registered<metrics::Counter>,
    tx_packets: Registered<metrics::Counter>,
    rx_bytes: Registered<metrics::Counter>,
    tx_bytes: Registered<metrics::Counter>,
    rx_missed: Registered<metrics::Counter>,
    rx_errors: Registered<metrics::Counter>,
    tx_errors: Registered<metrics::Counter>,
    rx_no_mbuf: Registered<metrics::Counter>,
}

impl PortMetrics {
    /// Register counters using the configured interface name as the `port` label.
    #[must_use]
    pub fn new(port: &str) -> PortMetrics {
        let counter = |suffix: &str, unit: Unit, description: &str| {
            let mut spec = MetricSpec::new(
                format!("{PORT_METRIC_BASE}_{suffix}"),
                unit,
                vec![("port".to_string(), port.to_string())],
            );
            spec.description = description.to_string();
            spec.register()
        };

        PortMetrics {
            rx_packets: counter("rx_packets", Unit::Count, "packets received by the port"),
            tx_packets: counter("tx_packets", Unit::Count, "packets transmitted by the port"),
            rx_bytes: counter("rx_bytes", Unit::Bytes, "bytes received by the port"),
            tx_bytes: counter("tx_bytes", Unit::Bytes, "bytes transmitted by the port"),
            rx_missed: counter(
                "rx_missed",
                Unit::Count,
                "packets dropped by the port for want of a free receive descriptor; \
                 the dataplane is not keeping up",
            ),
            rx_errors: counter("rx_errors", Unit::Count, "erroneous packets received"),
            tx_errors: counter("tx_errors", Unit::Count, "packets that failed to transmit"),
            rx_no_mbuf: counter(
                "rx_no_mbuf",
                Unit::Count,
                "receive mbuf allocation failures; the port's pool is too small",
            ),
        }
    }

    /// Publish a counter snapshot.
    ///
    /// Absolute rather than incremental: see the module docs.
    pub fn publish(&self, counters: &PortCounters) {
        self.rx_packets.metric.absolute(counters.rx_packets);
        self.tx_packets.metric.absolute(counters.tx_packets);
        self.rx_bytes.metric.absolute(counters.rx_bytes);
        self.tx_bytes.metric.absolute(counters.tx_bytes);
        self.rx_missed.metric.absolute(counters.rx_missed);
        self.rx_errors.metric.absolute(counters.rx_errors);
        self.tx_errors.metric.absolute(counters.tx_errors);
        self.rx_no_mbuf.metric.absolute(counters.rx_no_mbuf);
    }
}

#[cfg(test)]
mod exported {
    use super::*;
    use crate::scrape::Scrape;

    /// A series suffix paired with the accessor for the field it must carry.
    type CounterUnderTest = (&'static str, fn(&PortCounters) -> u64);

    /// Every counter this module publishes.
    const EVERY_COUNTER: [CounterUnderTest; 8] = [
        ("rx_packets", |c| c.rx_packets),
        ("tx_packets", |c| c.tx_packets),
        ("rx_bytes", |c| c.rx_bytes),
        ("tx_bytes", |c| c.tx_bytes),
        ("rx_missed", |c| c.rx_missed),
        ("rx_errors", |c| c.rx_errors),
        ("tx_errors", |c| c.tx_errors),
        ("rx_no_mbuf", |c| c.rx_no_mbuf),
    ];

    /// Distinct values throughout, so a counter wired to the wrong field cannot pass by accident.
    fn distinct() -> PortCounters {
        PortCounters {
            rx_packets: 11,
            tx_packets: 22,
            rx_bytes: 33,
            tx_bytes: 44,
            rx_missed: 55,
            rx_errors: 66,
            tx_errors: 77,
            rx_no_mbuf: 88,
        }
    }

    fn published(scrape: &Scrape, suffix: &str, port: &str) -> Option<u64> {
        scrape.counter(&format!("{PORT_METRIC_BASE}_{suffix}"), &[("port", port)])
    }

    #[test]
    fn every_counter_reaches_its_own_series() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            PortMetrics::new("eth0").publish(&distinct());
        });

        let counters = distinct();
        for (suffix, field) in EVERY_COUNTER {
            assert_eq!(
                published(&scrape, suffix, "eth0"),
                Some(field(&counters)),
                "port_{suffix} did not export the value it was given"
            );
        }
    }

    #[test]
    fn republishing_a_snapshot_does_not_accumulate() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let metrics = PortMetrics::new("eth0");
            metrics.publish(&distinct());
            metrics.publish(&distinct());
            metrics.publish(&distinct());
        });

        assert_eq!(published(&scrape, "rx_packets", "eth0"), Some(11));
        assert_eq!(published(&scrape, "rx_missed", "eth0"), Some(55));
    }

    #[test]
    fn a_later_reading_advances_the_counter() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let metrics = PortMetrics::new("eth0");
            metrics.publish(&PortCounters {
                rx_packets: 10,
                ..PortCounters::default()
            });
            metrics.publish(&PortCounters {
                rx_packets: 1_000,
                ..PortCounters::default()
            });
        });

        assert_eq!(published(&scrape, "rx_packets", "eth0"), Some(1_000));
    }

    #[test]
    fn each_port_gets_its_own_series() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            PortMetrics::new("eth0").publish(&PortCounters {
                rx_packets: 10,
                ..PortCounters::default()
            });
            PortMetrics::new("eth1").publish(&PortCounters {
                rx_packets: 4_000,
                ..PortCounters::default()
            });
        });

        assert_eq!(published(&scrape, "rx_packets", "eth0"), Some(10));
        assert_eq!(published(&scrape, "rx_packets", "eth1"), Some(4_000));
    }

    #[test]
    fn publishing_does_not_re_register() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let metrics = PortMetrics::new("eth0");
            let after_registration = scrape.registrations();
            assert_eq!(
                after_registration,
                EVERY_COUNTER.len(),
                "a port should register exactly one series per counter"
            );
            for _ in 0..50 {
                metrics.publish(&distinct());
            }
            assert_eq!(
                scrape.registrations(),
                after_registration,
                "publishing re-registered the metric family"
            );
        });
    }

    #[test]
    fn every_series_has_exactly_the_port_label() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            PortMetrics::new("eth0").publish(&distinct());
        });

        for (suffix, _) in EVERY_COUNTER {
            let shapes = scrape.label_shapes(&format!("{PORT_METRIC_BASE}_{suffix}"));
            assert_eq!(
                shapes,
                [vec!["port".to_string()]].into_iter().collect(),
                "port_{suffix} has the wrong label shape"
            );
        }
    }
}
