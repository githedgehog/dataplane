// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What the pipeline did with packets, and how many flows it holds.
//!
//! [`PipelineMetrics`] exports [`PacketStats`]: one `pipeline_packets` series per [`DoneReason`],
//! labelled `reason`. [`FlowTableMetrics`] exports the flow table's size. Both are published by
//! polling, as [`PortMetrics`](crate::PortMetrics) is: the counts already exist, and a periodic
//! snapshot costs the packet path nothing.

use metrics::Unit;
use net::packet::{DoneReason, PacketStats};
use strum::IntoEnumIterator;

use crate::register::{Register, Registered};
use crate::spec::MetricSpec;

/// Id of the per-reason packet counter.
pub(crate) const PIPELINE_PACKETS: &str = "pipeline_packets";

/// Id of the flow table size gauge.
pub(crate) const FLOW_TABLE_ENTRIES: &str = "flow_table_entries";

/// Id of the flow table capacity gauge.
pub(crate) const FLOW_TABLE_CAPACITY: &str = "flow_table_capacity";

/// The `reason` label a [`DoneReason`] is exported under: its variant name, which is fixed by
/// the variant rather than by how it happens to print.
#[must_use]
pub fn reason_label(reason: DoneReason) -> &'static str {
    reason.into()
}

/// One counter per [`DoneReason`], registered once and reused for each poll.
#[derive(Debug)]
pub struct PipelineMetrics {
    by_reason: Vec<(DoneReason, Registered<metrics::Counter>)>,
}

impl PipelineMetrics {
    /// Register a counter for every reason a packet can finish for.
    #[must_use]
    pub fn new() -> PipelineMetrics {
        let by_reason = DoneReason::iter()
            .map(|reason| {
                let mut spec = MetricSpec::new(
                    PIPELINE_PACKETS,
                    Unit::Count,
                    vec![("reason".to_string(), reason_label(reason).to_string())],
                );
                spec.description =
                    "packets the pipeline finished with, by the reason it finished".to_string();
                (reason, spec.register())
            })
            .collect();
        PipelineMetrics { by_reason }
    }

    /// Publish `stats`' current counts.
    pub fn publish(&self, stats: &PacketStats) {
        for (reason, counter) in &self.by_reason {
            counter.metric.absolute(stats.get(*reason));
        }
    }
}

impl Default for PipelineMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// The flow table's size, registered once and reused for each poll.
#[derive(Debug)]
pub struct FlowTableMetrics {
    entries: Registered<metrics::Gauge>,
    capacity: Registered<metrics::Gauge>,
}

impl FlowTableMetrics {
    /// Register the gauge.
    #[must_use]
    pub fn new() -> FlowTableMetrics {
        let gauge = |id: &str, description: &str| {
            let mut spec = MetricSpec::new(id, Unit::Count, vec![]);
            spec.description = description.to_string();
            spec.register()
        };
        FlowTableMetrics {
            entries: gauge(
                FLOW_TABLE_ENTRIES,
                "entries in the flow table, expired ones included",
            ),
            capacity: gauge(
                FLOW_TABLE_CAPACITY,
                "entries the flow table admits before new flows are dropped as \
                 FlowCapacityExceeded",
            ),
        }
    }

    /// Publish the table's size and its capacity.
    #[allow(clippy::cast_precision_loss)] // exact up to 2^53 entries
    pub fn publish(&self, entries: usize, capacity: usize) {
        self.entries.metric.set(entries as f64);
        self.capacity.metric.set(capacity as f64);
    }
}

impl Default for FlowTableMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Which build is running: `dataplane_build_info{version}`, always 1, so that a dashboard can
/// tell builds apart and join on the label.
#[derive(Debug)]
pub struct BuildInfoMetrics {
    info: Registered<metrics::Gauge>,
}

impl BuildInfoMetrics {
    /// Register the build's `version`.
    #[must_use]
    pub fn new(version: &str) -> BuildInfoMetrics {
        let mut spec = MetricSpec::new(
            "dataplane_build_info",
            Unit::Count,
            vec![("version".to_string(), version.to_string())],
        );
        spec.description = "1, labelled with the version of the running build".to_string();
        let info: Registered<metrics::Gauge> = spec.register();
        info.metric.set(1.0);
        BuildInfoMetrics { info }
    }

    /// Publish it again, should the exporter have let it go idle.
    pub fn publish(&self) {
        self.info.metric.set(1.0);
    }
}

#[cfg(test)]
mod exported {
    use super::*;
    use crate::scrape::Scrape;
    use strum::EnumCount;

    #[test]
    fn every_reason_reaches_its_own_series() {
        let stats = PacketStats::new();
        // Distinct counts, so a reason wired to the wrong series cannot pass by accident.
        for (n, reason) in DoneReason::iter().enumerate() {
            stats.incr(reason, n as u64 * 10 + 1);
        }
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || PipelineMetrics::new().publish(&stats));

        for reason in DoneReason::iter() {
            let label = reason_label(reason);
            assert_eq!(
                scrape.counter(PIPELINE_PACKETS, &[("reason", label)]),
                Some(stats.get(reason)),
                "{label} did not export its own count"
            );
        }
        assert_eq!(scrape.registrations(), DoneReason::COUNT);
    }

    /// Whatever the counts, a series carries its reason's count as it stands when published:
    /// publishing again, with or without more packets in between, does not add them up.
    #[test]
    fn republishing_does_not_accumulate() {
        bolero::check!()
            .with_type::<(Vec<u32>, Vec<u32>)>()
            .for_each(|(before, between)| {
                let stats = PacketStats::new();
                let count = |counts: &[u32]| {
                    for (reason, n) in DoneReason::iter().zip(counts) {
                        stats.incr(reason, u64::from(*n));
                    }
                };
                let scrape = Scrape::default();
                metrics::with_local_recorder(&scrape, || {
                    let metrics = PipelineMetrics::new();
                    count(before);
                    metrics.publish(&stats);
                    metrics.publish(&stats);
                    count(between);
                    metrics.publish(&stats);
                });
                for reason in DoneReason::iter() {
                    assert_eq!(
                        scrape.counter(PIPELINE_PACKETS, &[("reason", reason_label(reason))]),
                        Some(stats.get(reason)),
                    );
                }
            });
    }

    #[test]
    fn the_build_is_labelled_with_its_version() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || BuildInfoMetrics::new("v1.2.3").publish());
        assert_eq!(
            scrape.get("dataplane_build_info", &[("version", "v1.2.3")]),
            Some(1.0)
        );
    }

    #[test]
    fn the_flow_table_size_is_a_gauge() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let metrics = FlowTableMetrics::new();
            metrics.publish(10, 100);
            metrics.publish(3, 50);
        });
        assert_eq!(scrape.get(FLOW_TABLE_ENTRIES, &[]), Some(3.0));
        assert_eq!(scrape.get(FLOW_TABLE_CAPACITY, &[]), Some(50.0));
    }
}
