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

/// How a worker's rx task fares, as the driver's supervisor last found it.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct RxTaskHealth {
    /// The task did not pat its watchdog, and saw no frames, over the supervisor's last check.
    pub stuck: bool,
    /// The supervisor's checks that found the task stuck, since it started.
    pub watchdog_misses: u64,
}

/// Metric handles for one worker's port queue, registered once and reused for each poll.
#[derive(Debug)]
pub struct WorkerMetrics {
    series: [Registered<metrics::Counter>; 14],
    stuck: Registered<metrics::Gauge>,
    watchdog_misses: Registered<metrics::Counter>,
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
        let spec = |suffix: &str, description: &str| {
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
            spec
        };
        WorkerMetrics {
            series: SERIES.map(|(suffix, description, _)| spec(suffix, description).register()),
            stuck: spec(
                "stuck",
                "1 if the worker neither patted its watchdog nor saw a frame on the queue over the \
                 supervisor's last check, else 0",
            )
            .register(),
            watchdog_misses: spec(
                "watchdog_misses",
                "supervisor checks that found the worker stuck on the queue",
            )
            .register(),
        }
    }

    /// Publish how the rx task fares.
    pub fn publish_health(&self, health: &RxTaskHealth) {
        self.stuck.metric.set(f64::from(u8::from(health.stuck)));
        self.watchdog_misses.metric.absolute(health.watchdog_misses);
    }

    /// Publish a snapshot of the totals.
    pub fn publish(&self, counters: &WorkerCounters) {
        for (registered, (_, _, field)) in self.series.iter().zip(SERIES) {
            registered.metric.absolute(field(counters));
        }
    }
}

/// Whether a worker thread is still running, registered once per worker.
#[derive(Debug)]
pub struct WorkerStateMetrics {
    running: Registered<metrics::Gauge>,
}

impl WorkerStateMetrics {
    /// Register the state of worker `worker`.
    #[must_use]
    pub fn new(worker: usize) -> WorkerStateMetrics {
        let mut spec = MetricSpec::new(
            format!("{WORKER_METRIC_BASE}_running"),
            Unit::Count,
            vec![("worker".to_string(), worker.to_string())],
        );
        spec.description = "1 while the worker thread runs, 0 once it has ended, for whatever \
                            reason"
            .to_string();
        WorkerStateMetrics {
            running: spec.register(),
        }
    }

    /// Publish whether the worker runs.
    pub fn publish(&self, running: bool) {
        self.running.metric.set(f64::from(u8::from(running)));
    }
}

/// What a polling worker spent its time on, and how it idles, since it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerLoadCounters<'a> {
    /// Nanoseconds spent in each state the worker was registered with, by its name.
    pub time_ns: &'a [(&'a str, u64)],
    /// Low-power monitor waits (or timed sleeps) the worker went into.
    pub monitor_sleeps: u64,
    /// Sleeps on interrupts the worker went into.
    pub interrupt_sleeps: u64,
    /// The idle mode the worker idles in now, one of those it was registered with.
    pub effective_mode: &'a str,
    /// Flows the worker's timer wheel expired.
    pub expired_flows: u64,
    /// Expiry passes that ended with work left over: a worker that is behind on every pass is
    /// holding expired flows in the table.
    pub expiry_behind: u64,
}

/// Metric handles for one polling worker's load, registered once and reused for each poll.
///
/// `worker_time_nanoseconds{state}` is a counter per state the worker's time goes to, so that
/// `rate()` of one over the sum of all is the share of its time spent there: `state="busy"` is how
/// loaded it is, whatever the operating system's CPU accounting says of a thread that polls or
/// sleeps in a monitor wait. `worker_idle_sleeps{kind}` counts the sleeps, and `worker_idle_mode`
/// is 1 for the mode the worker idles in now and 0 for the others, labelled with the mode it was
/// configured with: one that `mode` and `configured` disagree on has fallen back.
#[derive(Debug)]
pub struct WorkerLoadMetrics {
    time: Vec<(String, Registered<metrics::Counter>)>,
    monitor_sleeps: Registered<metrics::Counter>,
    interrupt_sleeps: Registered<metrics::Counter>,
    modes: Vec<(String, Registered<metrics::Gauge>)>,
    expired_flows: Registered<metrics::Counter>,
    expiry_behind: Registered<metrics::Counter>,
}

impl WorkerLoadMetrics {
    /// Register the load of worker `worker`, which divides its time among `states` and idles in one
    /// of `modes`, having been configured with `configured`.
    #[must_use]
    pub fn new(worker: usize, states: &[&str], modes: &[&str], configured: &str) -> Self {
        let spec = |suffix: &str, unit: Unit, description: &str, label: Option<(&str, &str)>| {
            let mut labels = vec![("worker".to_string(), worker.to_string())];
            if let Some((key, value)) = label {
                labels.push((key.to_string(), value.to_string()));
            }
            if suffix == "idle_mode" {
                labels.push(("configured".to_string(), configured.to_string()));
            }
            let mut spec = MetricSpec::new(format!("{WORKER_METRIC_BASE}_{suffix}"), unit, labels);
            spec.description = description.to_string();
            spec
        };
        let sleeps = |kind: &str| {
            spec(
                "idle_sleeps",
                Unit::Count,
                "sleeps the worker went into for want of anything to do, by kind",
                Some(("kind", kind)),
            )
            .register()
        };
        WorkerLoadMetrics {
            time: states
                .iter()
                .map(|state| {
                    let registered = spec(
                        "time_nanoseconds",
                        Unit::Nanoseconds,
                        "time the worker spent in each state; rate over the sum of all states is \
                         the share",
                        Some(("state", state)),
                    )
                    .register();
                    ((*state).to_string(), registered)
                })
                .collect(),
            monitor_sleeps: sleeps("monitor"),
            interrupt_sleeps: sleeps("interrupt"),
            expired_flows: spec(
                "expired_flows",
                Unit::Count,
                "flows the worker's timer wheel expired and removed from the flow table",
                None,
            )
            .register(),
            expiry_behind: spec(
                "expiry_behind",
                Unit::Count,
                "expiry passes that ended with expired flows left for the next pass",
                None,
            )
            .register(),
            modes: modes
                .iter()
                .map(|mode| {
                    let registered = spec(
                        "idle_mode",
                        Unit::Count,
                        "1 for the idle mode the worker idles in now, 0 for the others; it can be \
                         weaker than the configured one",
                        Some(("mode", mode)),
                    )
                    .register();
                    ((*mode).to_string(), registered)
                })
                .collect(),
        }
    }

    /// Publish a snapshot of the load. States and modes the worker was not registered with are
    /// ignored.
    pub fn publish(&self, load: &WorkerLoadCounters<'_>) {
        for (state, nanos) in load.time_ns {
            if let Some((_, registered)) = self.time.iter().find(|(name, _)| name == state) {
                registered.metric.absolute(*nanos);
            }
        }
        self.monitor_sleeps.metric.absolute(load.monitor_sleeps);
        self.interrupt_sleeps.metric.absolute(load.interrupt_sleeps);
        self.expired_flows.metric.absolute(load.expired_flows);
        self.expiry_behind.metric.absolute(load.expiry_behind);
        for (mode, registered) in &self.modes {
            registered
                .metric
                .set(f64::from(u8::from(mode == load.effective_mode)));
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

    /// A stuck task and its misses reach their own series, as does whether its worker runs; a
    /// task that recovers is no longer stuck, and keeps its misses.
    #[test]
    fn health_reaches_its_series() {
        let scrape = Scrape::default();
        let labels = [("worker", "2"), ("port", "eth1"), ("queue", "data")];
        metrics::with_local_recorder(&scrape, || {
            let metrics = WorkerMetrics::new(2, "eth1", "data");
            let state = WorkerStateMetrics::new(2);
            metrics.publish_health(&RxTaskHealth {
                stuck: true,
                watchdog_misses: 3,
            });
            state.publish(true);
            assert_eq!(scrape.get("worker_stuck", &labels), Some(1.0));
            assert_eq!(scrape.get("worker_running", &[("worker", "2")]), Some(1.0));

            metrics.publish_health(&RxTaskHealth {
                stuck: false,
                watchdog_misses: 3,
            });
            state.publish(false);
        });
        assert_eq!(scrape.get("worker_stuck", &labels), Some(0.0));
        assert_eq!(scrape.counter("worker_watchdog_misses", &labels), Some(3));
        assert_eq!(scrape.get("worker_running", &[("worker", "2")]), Some(0.0));
    }

    /// Each state's time and each kind of sleep reaches its own series, and exactly one mode is
    /// marked, labelled with the configured one.
    #[test]
    fn load_reaches_its_series() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let metrics = WorkerLoadMetrics::new(
                3,
                &["busy", "polling"],
                &["poll", "monitor", "interrupt"],
                "interrupt",
            );
            metrics.publish(&WorkerLoadCounters {
                time_ns: &[("busy", 10), ("polling", 30), ("elsewhere", 99)],
                monitor_sleeps: 4,
                interrupt_sleeps: 5,
                effective_mode: "monitor",
                expired_flows: 6,
                expiry_behind: 7,
            });
        });
        let time = |state| {
            scrape.counter(
                "worker_time_nanoseconds",
                &[("worker", "3"), ("state", state)],
            )
        };
        assert_eq!((time("busy"), time("polling")), (Some(10), Some(30)));
        assert_eq!(time("elsewhere"), None);
        let sleeps =
            |kind| scrape.counter("worker_idle_sleeps", &[("worker", "3"), ("kind", kind)]);
        assert_eq!((sleeps("monitor"), sleeps("interrupt")), (Some(4), Some(5)));
        let worker = [("worker", "3")];
        assert_eq!(scrape.counter("worker_expired_flows", &worker), Some(6));
        assert_eq!(scrape.counter("worker_expiry_behind", &worker), Some(7));
        let mode = |mode| {
            scrape.get(
                "worker_idle_mode",
                &[("worker", "3"), ("mode", mode), ("configured", "interrupt")],
            )
        };
        assert_eq!(
            (mode("poll"), mode("monitor"), mode("interrupt")),
            (Some(0.0), Some(1.0), Some(0.0))
        );
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
