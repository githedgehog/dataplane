// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Counters the *device* keeps for a network port, as opposed to the ones the pipeline keeps.
//!
//! Everything else in this crate counts what the dataplane did with a packet. These count what
//! happened before the dataplane ever saw it, which is the only place some failures are visible at
//! all: a frame the NIC dropped for want of a free receive descriptor never reaches a worker, is
//! never parsed, and is absent from every pipeline counter. Without
//! [`rx_missed`](PortCounters::rx_missed) and [`rx_no_mbuf`](PortCounters::rx_no_mbuf) the symptom
//! of an overloaded dataplane is indistinguishable from a quiet wire.
//!
//! That distinction is the whole reason this module exists: it is what makes a load test mean
//! something.
//!
//! # Why counters and not gauges
//!
//! A device reports these cumulatively, monotonically increasing since the port started. That is
//! exactly a Prometheus counter, so they are published with
//! [`Counter::absolute`](metrics::Counter::absolute) rather than accumulated with `increment`.
//! Publishing an absolute value is also idempotent, which matters because the poller is a timer:
//! a missed tick loses resolution but never loses count, and a doubled tick cannot double-count.
//!
//! # Why the counters are a plain struct
//!
//! [`PortCounters`] deliberately names no DPDK type. This crate does not depend on `dpdk` and
//! should not: a port's counters are not a DPDK concept, and the kernel driver has the same
//! question to answer about its own interfaces. The driver converts.

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
    /// Packets the port had and dropped because no receive descriptor was free.
    ///
    /// "The wire delivered it and we were not keeping up." This is the counter that says a
    /// dataplane is overloaded, and it is invisible to every pipeline counter because the packet
    /// never reached a worker.
    pub rx_missed: u64,
    /// Erroneous packets received.
    pub rx_errors: u64,
    /// Packets that failed to transmit.
    pub tx_errors: u64,
    /// Receive mbuf allocation failures.
    ///
    /// "The pool was too small." Distinct from [`rx_missed`](Self::rx_missed), which is the
    /// application being too slow rather than the pool being too small -- the remedies differ
    /// (more workers or queues, versus a bigger pool), so the two must not be summed.
    pub rx_no_mbuf: u64,
}

/// Registered metric handles for one port.
///
/// Registration is configuration work and publishing follows traffic, so the handles are built
/// once when a port comes up and reused for every poll. Re-registering per publish is what made
/// the VPC collector quadratic, and there is no reason to repeat it here.
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
    /// Register the counter family for the port named `port`.
    ///
    /// `port` is the configured interface name, which is what the rest of the system -- the
    /// routing tables, the control-plane bridge, the operator -- knows the port by. Deliberately
    /// not the DPDK port index, which is only the order the EAL happened to probe in and would
    /// change between runs.
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

    /// Every field reaches its own series, under the port's name.
    ///
    /// The values are all different, so this fails if any two counters are crossed -- which a
    /// same-value snapshot would happily accept.
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

    /// The counters a device reports are cumulative, so publishing the same snapshot twice must
    /// leave the series where it was. Using `increment` instead of `absolute` would double it --
    /// and would keep doubling on every poll, which is the failure this guards.
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

    /// A later, larger reading advances the series -- the ordinary case, and the one that would
    /// break if `absolute` were mistaken for "set once".
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

    /// Two ports get two independent series, distinguished by the `port` label.
    ///
    /// Sharing a series would silently sum the ports, which reads as one very busy port and hides
    /// an idle one entirely.
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

    /// Registration happens when the port comes up, not on every publish.
    ///
    /// Re-registering per publish is what made the VPC collector quadratic. One `PortMetrics` is
    /// eight series however many times it publishes.
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

    /// Every series carries exactly the `port` label and nothing else.
    ///
    /// Two registration sites disagreeing about the base label set has happened before in this
    /// crate and produced series with a duplicated label, so the shape is worth pinning.
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
