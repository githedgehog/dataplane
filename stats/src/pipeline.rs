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

/// The `reason` label a [`DoneReason`] is exported under: its variant name.
#[must_use]
pub fn reason_label(reason: DoneReason) -> String {
    format!("{reason:?}")
}

/// One counter per [`DoneReason`], registered once and reused for each poll.
#[derive(Debug)]
pub struct PipelineMetrics {
    /// Indexed by `DoneReason as usize`, as [`PacketStats::snapshot`] is.
    by_reason: Vec<Registered<metrics::Counter>>,
}

impl PipelineMetrics {
    /// Register a counter for every reason a packet can finish for.
    #[must_use]
    pub fn new() -> PipelineMetrics {
        let mut by_reason: Vec<(usize, Registered<metrics::Counter>)> = DoneReason::iter()
            .map(|reason| {
                let mut spec = MetricSpec::new(
                    PIPELINE_PACKETS,
                    Unit::Count,
                    vec![("reason".to_string(), reason_label(reason))],
                );
                spec.description =
                    "packets the pipeline finished with, by the reason it finished".to_string();
                (reason as usize, spec.register())
            })
            .collect();
        by_reason.sort_by_key(|(index, _)| *index);
        PipelineMetrics {
            by_reason: by_reason.into_iter().map(|(_, counter)| counter).collect(),
        }
    }

    /// Publish `stats`' current counts.
    pub fn publish(&self, stats: &PacketStats) {
        for (counter, count) in self.by_reason.iter().zip(stats.snapshot()) {
            counter.metric.absolute(count);
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
}

impl FlowTableMetrics {
    /// Register the gauge.
    #[must_use]
    pub fn new() -> FlowTableMetrics {
        let mut spec = MetricSpec::new(FLOW_TABLE_ENTRIES, Unit::Count, vec![]);
        spec.description = "entries in the flow table, expired ones included".to_string();
        FlowTableMetrics {
            entries: spec.register(),
        }
    }

    /// Publish the table's size.
    #[allow(clippy::cast_precision_loss)] // exact up to 2^53 entries
    pub fn publish(&self, entries: usize) {
        self.entries.metric.set(entries as f64);
    }
}

impl Default for FlowTableMetrics {
    fn default() -> Self {
        Self::new()
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
                scrape.counter(PIPELINE_PACKETS, &[("reason", &label)]),
                Some(stats.get(reason)),
                "{label} did not export its own count"
            );
        }
        assert_eq!(scrape.registrations(), DoneReason::COUNT);
    }

    #[test]
    fn republishing_does_not_accumulate() {
        let stats = PacketStats::new();
        stats.incr(DoneReason::Delivered, 7);
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let metrics = PipelineMetrics::new();
            metrics.publish(&stats);
            metrics.publish(&stats);
        });
        let label = reason_label(DoneReason::Delivered);
        assert_eq!(
            scrape.counter(PIPELINE_PACKETS, &[("reason", &label)]),
            Some(7)
        );
    }

    #[test]
    fn the_flow_table_size_is_a_gauge() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let metrics = FlowTableMetrics::new();
            metrics.publish(10);
            metrics.publish(3);
        });
        assert_eq!(scrape.get(FLOW_TABLE_ENTRIES, &[]), Some(3.0));
    }
}
