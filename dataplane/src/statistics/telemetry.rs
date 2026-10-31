// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Publishing what the pipeline and the workers count as metrics.
//!
//! The counts already exist -- per-reason packet counts, the flow table, the driver's per-worker
//! totals -- for the CLI. [`Telemetry`] reads them as they stand and publishes absolute values
//! when asked, which production does as each scrape comes, so exporting them costs the packet
//! path nothing.

use std::collections::HashMap;

use concurrency::sync::Arc;
use flow_entry::flow_table::FlowTable;
use net::packet::PacketStats;
use stats::{FlowTableMetrics, PipelineMetrics, WorkerCounters, WorkerMetrics};

use crate::drivers::status::{DriverStatusReader, RxQueue};
use crate::drivers::watchdog::RxCounters;

/// Where the published counts come from.
pub(crate) struct TelemetrySources {
    /// Packets the pipeline finished with, by reason.
    pub(crate) packets: Arc<PacketStats>,
    /// The flow table.
    pub(crate) flows: Arc<FlowTable>,
    /// The driver's workers, and their totals.
    pub(crate) driver: DriverStatusReader,
}

/// Publishes [`TelemetrySources`] to the installed metrics recorder.
pub(crate) struct Telemetry {
    sources: TelemetrySources,
    pipeline: PipelineMetrics,
    flows: FlowTableMetrics,
    /// Registered as each worker's port queue first appears in the driver's status.
    workers: HashMap<(usize, Arc<str>, RxQueue), WorkerMetrics>,
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
        // Kept by the table as it changes: reading it locks nothing.
        self.flows.publish(self.sources.flows.live_len());
        let status = self.sources.driver.load();
        for worker in &status.workers {
            for task in &worker.rx_tasks {
                self.workers
                    .entry((worker.worker, task.port.clone(), task.queue))
                    .or_insert_with(|| {
                        WorkerMetrics::new(worker.worker, &task.port, task.queue.name())
                    })
                    .publish(&counters(&task.totals.load()));
            }
        }
    }
}

/// A worker's totals for one port queue, as its rx task counts them.
fn counters(totals: &RxCounters) -> WorkerCounters {
    WorkerCounters {
        rx_packets: totals.rx,
        forwarded_packets: totals.tx,
        pipeline_drops: totals.ppline_drops,
        forward_drops: totals.tx_drops,
        punt_drops: totals.punt_drops,
        parse_errors: totals.parse_errors,
        truncated: totals.truncated,
        csum_unknown: totals.csum_unknown,
        zero_len: totals.zero_len,
        kernel_drops: totals.kernel_drops,
        injected_packets: totals.injected,
        inject_drops: totals.inject_drops,
        bursts: totals.bursts,
        full_bursts: totals.full_bursts,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use metrics_exporter_prometheus::PrometheusBuilder;
    use net::packet::DoneReason;

    use super::*;
    use crate::drivers::status::{DriverStatus, RxTaskStatus, WorkerStatus, driver_status_access};
    use crate::drivers::watchdog::Watchdog;

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

    /// What the pipeline and the workers count reaches the exporter production scrapes, as it
    /// stands when published: the workers' counts too, whenever the driver last published its
    /// status.
    #[test]
    fn counts_reach_the_prometheus_exporter() {
        let packets = Arc::new(PacketStats::new());
        packets.incr(DoneReason::Delivered, 5);
        let data = Watchdog::new();
        let control = Watchdog::new();
        let (writer, driver) = driver_status_access();
        let mut worker = WorkerStatus::new(1);
        worker.rx_tasks = vec![
            RxTaskStatus::new("eth0".into(), RxQueue::Data, data.reader()),
            RxTaskStatus::new("eth0".into(), RxQueue::Control, control.reader()),
        ];
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
            data.record(&RxCounters {
                rx: 3,
                tx: 2,
                ppline_drops: 1,
                ..RxCounters::default()
            });
            control.record(&RxCounters {
                rx: 4,
                injected: 6,
                ..RxCounters::default()
            });
            telemetry.publish();
        });

        let rendered = series(&handle.render());
        let get = |series: &str| rendered.get(series).copied();
        assert_eq!(get(r#"pipeline_packets{reason="Delivered"}"#), Some(6.0));
        assert_eq!(get(r#"pipeline_packets{reason="Unroutable"}"#), Some(0.0));
        assert_eq!(get("flow_table_entries"), Some(0.0));
        let data = |name: &str| get(&format!(r#"{name}{{port="eth0",queue="data",worker="1"}}"#));
        let control = |name: &str| {
            get(&format!(
                r#"{name}{{port="eth0",queue="control",worker="1"}}"#
            ))
        };
        assert_eq!(data("worker_rx_packets"), Some(3.0));
        assert_eq!(data("worker_forwarded_packets"), Some(2.0));
        assert_eq!(data("worker_pipeline_drops"), Some(1.0));
        assert_eq!(control("worker_rx_packets"), Some(4.0));
        assert_eq!(control("worker_injected_packets"), Some(6.0));
    }
}
