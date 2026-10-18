// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Publishing what the pipeline and the workers count as metrics.
//!
//! The counts already exist -- per-reason packet counts, the flow table, the driver's per-worker
//! totals -- for the CLI. [`Telemetry`] polls them and publishes absolute values, so exporting
//! them costs the packet path nothing.

use std::collections::HashMap;
use std::time::Duration;

use concurrency::sync::Arc;
use flow_entry::flow_table::FlowTable;
use net::packet::PacketStats;
use stats::{FlowTableMetrics, PipelineMetrics, WorkerCounters, WorkerMetrics};

use crate::drivers::status::{DriverStatusReader, RxTaskStatus};

/// How often production publishes. Scrapers poll far less often than this.
pub(crate) const PUBLISH_EVERY: Duration = Duration::from_secs(1);

/// Where the published counts come from.
pub(crate) struct TelemetrySources {
    /// Packets the pipeline finished with, by reason.
    pub(crate) packets: Arc<PacketStats>,
    /// The flow table.
    pub(crate) flows: Arc<FlowTable>,
    /// The driver's per-worker totals.
    pub(crate) driver: DriverStatusReader,
}

/// Publishes [`TelemetrySources`] to the installed metrics recorder.
pub(crate) struct Telemetry {
    sources: TelemetrySources,
    pipeline: PipelineMetrics,
    flows: FlowTableMetrics,
    /// Registered as each worker's port first appears in the driver's status.
    workers: HashMap<(usize, Arc<str>), WorkerMetrics>,
}

impl Telemetry {
    /// Register the metrics with the installed recorder; install it first.
    pub(crate) fn new(sources: TelemetrySources) -> Telemetry {
        Telemetry {
            sources,
            pipeline: PipelineMetrics::new(),
            flows: FlowTableMetrics::new(),
            workers: HashMap::new(),
        }
    }

    /// Publish every count as it stands.
    pub(crate) fn publish(&mut self) {
        self.pipeline.publish(&self.sources.packets);
        // A table busy being written is skipped this round rather than waited for.
        if let Some(entries) = self.sources.flows.len() {
            self.flows.publish(entries);
        }
        let status = self.sources.driver.load();
        for worker in &status.workers {
            for task in &worker.rx_tasks {
                self.workers
                    .entry((worker.worker, task.ifname.clone()))
                    .or_insert_with(|| WorkerMetrics::new(worker.worker, &task.ifname))
                    .publish(&counters(task));
            }
        }
    }
}

/// A worker's totals for one port, as the driver's status holds them.
fn counters(task: &RxTaskStatus) -> WorkerCounters {
    WorkerCounters {
        rx_packets: task.total_rx,
        tx_packets: task.total_tx,
        pipeline_drops: task.total_ppline_drops,
        tx_drops: task.total_tx_drops,
        punt_drops: task.total_punt_drops,
        parse_errors: task.total_parse_errors,
        truncated: task.total_truncated,
        zero_len: task.total_zero_len,
        kernel_drops: task.total_kernel_drops,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use metrics_exporter_prometheus::PrometheusBuilder;
    use net::packet::DoneReason;

    use super::*;
    use crate::drivers::status::{DriverStatus, WorkerStatus, driver_status_access};

    /// Every series in `rendered` Prometheus text, by its line's name-and-labels part.
    fn series(rendered: &str) -> BTreeMap<String, f64> {
        rendered
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .filter_map(|line| {
                let (series, value) = line.rsplit_once(' ')?;
                Some((series.to_string(), value.parse().ok()?))
            })
            .collect()
    }

    /// What the pipeline and the driver count reaches the exporter production scrapes.
    #[test]
    fn counts_reach_the_prometheus_exporter() {
        let packets = Arc::new(PacketStats::new());
        packets.incr(DoneReason::Delivered, 5);
        let (writer, driver) = driver_status_access();
        let mut task = RxTaskStatus::new("eth0".into());
        task.total_rx = 3;
        task.total_ppline_drops = 2;
        let mut worker = WorkerStatus::new(1);
        worker.rx_tasks.push(task);
        writer.publish(DriverStatus {
            max_rx_batch: 32,
            workers: vec![worker],
        });

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let mut telemetry = Telemetry::new(TelemetrySources {
                packets: packets.clone(),
                flows: Arc::new(FlowTable::default()),
                driver,
            });
            telemetry.publish();
            // Counts advance; publishing again carries them, rather than adding them up.
            packets.incr(DoneReason::Delivered, 1);
            telemetry.publish();
        });

        let rendered = series(&handle.render());
        assert_eq!(
            rendered.get(r#"pipeline_packets{reason="Delivered"}"#),
            Some(&6.0)
        );
        assert_eq!(
            rendered.get(r#"pipeline_packets{reason="Unroutable"}"#),
            Some(&0.0)
        );
        assert_eq!(rendered.get("flow_table_entries"), Some(&0.0));
        assert_eq!(
            rendered.get(r#"worker_rx_packets{port="eth0",worker="1"}"#),
            Some(&3.0)
        );
        assert_eq!(
            rendered.get(r#"worker_pipeline_drops{port="eth0",worker="1"}"#),
            Some(&2.0)
        );
    }
}
