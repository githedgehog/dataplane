// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Publishing what the pipeline and the workers count as metrics.
//!
//! The counts already exist -- per-reason packet counts, the flow table, the driver's per-worker
//! totals -- for the CLI. [`Telemetry`] reads them as they stand and publishes absolute values
//! when asked, which production does as each scrape comes, so exporting them costs the packet
//! path nothing.

use std::collections::HashMap;

use args::{HugepagePlan, IdleMode};
use concurrency::sync::Arc;
use flow_entry::flow_table::FlowTable;
use nat::masquerade::NatAllocatorReader;
use net::packet::{PacketStats, VpcDiscriminant};
use stats::{
    BuildInfoMetrics, FlowTableMetrics, HugepageMetrics, MasqueradeMetrics, MasqueradeRegion,
    PipelineMetrics, RxTaskHealth, TapMetrics, WorkerCounters, WorkerLoadCounters,
    WorkerLoadMetrics, WorkerMetrics, WorkerStateMetrics,
};

use crate::drivers::cpbridge::TapCounters;
use crate::drivers::load::Spent;
use crate::drivers::status::{DriverStatusReader, RxQueue, WorkerLoadStatus, WorkerState};
use crate::drivers::watchdog::Activity;
use crate::drivers::watchdog::RxCounters;

/// Where the published counts come from.
pub(crate) struct TelemetrySources {
    /// Packets the pipeline finished with, by reason.
    pub(crate) packets: Arc<PacketStats>,
    /// The flow table.
    pub(crate) flows: Arc<FlowTable>,
    /// The driver's workers, and their totals.
    pub(crate) driver: DriverStatusReader,
    /// Masquerade's allocator, as the current configuration has it.
    pub(crate) masquerade: NatAllocatorReader,
    /// Each port's tap, by the port's configured name.
    pub(crate) taps: Vec<(String, TapCounters)>,
    /// The hugepages init set aside for EAL, if it did.
    pub(crate) hugepages: Option<HugepagePlan>,
}

/// Publishes [`TelemetrySources`] to the installed metrics recorder.
pub(crate) struct Telemetry {
    sources: TelemetrySources,
    pipeline: PipelineMetrics,
    flows: FlowTableMetrics,
    masquerade: MasqueradeMetrics,
    build: BuildInfoMetrics,
    hugepages: Option<HugepageMetrics>,
    /// One per tap, in the order of [`TelemetrySources::taps`].
    taps: Vec<TapMetrics>,
    /// Registered as each worker's port queue first appears in the driver's status.
    workers: HashMap<(usize, Arc<str>, RxQueue), WorkerMetrics>,
    /// Registered as each worker first appears in the driver's status.
    states: HashMap<usize, WorkerStateMetrics>,
    /// Registered as each polling worker first appears in the driver's status.
    loads: HashMap<usize, WorkerLoadMetrics>,
}

impl Telemetry {
    /// Register the metrics with the installed recorder; install it first.
    pub(crate) fn new(sources: TelemetrySources) -> Telemetry {
        let taps = sources
            .taps
            .iter()
            .map(|(port, _)| TapMetrics::new(port))
            .collect();
        Telemetry {
            taps,
            // As the startup banner reports it: "dev" for a build that does not ship.
            build: BuildInfoMetrics::new(option_env!("VERSION").unwrap_or("dev")),
            hugepages: sources.hugepages.as_ref().map(hugepage_metrics),
            sources,
            pipeline: PipelineMetrics::new(),
            flows: FlowTableMetrics::new(),
            masquerade: MasqueradeMetrics::new(),
            workers: HashMap::new(),
            states: HashMap::new(),
            loads: HashMap::new(),
        }
    }

    /// Publish every count as it stands.
    pub(crate) fn publish(&mut self) {
        self.pipeline.publish(&self.sources.packets);
        // Kept by the table as it changes: reading it locks nothing.
        self.flows
            .publish(self.sources.flows.live_len(), self.sources.flows.capacity());
        self.build.publish();
        if let Some(hugepages) = &self.hugepages {
            hugepages.publish();
        }
        self.publish_masquerade();
        for ((_, counters), metrics) in self.sources.taps.iter().zip(&self.taps) {
            metrics.publish(&counters.load());
        }
        let status = self.sources.driver.load();
        for worker in &status.workers {
            self.states
                .entry(worker.worker)
                .or_insert_with(|| WorkerStateMetrics::new(worker.worker))
                .publish(matches!(worker.state, WorkerState::Running));
            if let Some(load) = &worker.load {
                publish_load(&mut self.loads, worker.worker, load);
            }
            for task in &worker.rx_tasks {
                let metrics = self
                    .workers
                    .entry((worker.worker, task.port.clone(), task.queue))
                    .or_insert_with(|| {
                        WorkerMetrics::new(worker.worker, &task.port, task.queue.name())
                    });
                metrics.publish(&counters(&task.totals.load()));
                metrics.publish_health(&RxTaskHealth {
                    stuck: task.activity == Activity::Stuck,
                    watchdog_misses: task.misses,
                });
            }
        }
    }
}

/// Register what `plan` set aside: its page size, and the bytes on each node, with `any` for the
/// memory on no node in particular.
fn hugepage_metrics(plan: &HugepagePlan) -> HugepageMetrics {
    const MIB: u64 = 1 << 20;
    let unplaced = (plan.unplaced_mb > 0).then(|| ("any".to_string(), plan.unplaced_mb));
    HugepageMetrics::new(
        plan.page_size_kb * 1024,
        plan.per_node_mb
            .iter()
            .map(|(node, mb)| (node.to_string(), *mb))
            .chain(unplaced)
            .map(|(node, mb)| (node, mb * MIB)),
    )
}

impl Telemetry {
    /// Publish how much of masquerade's public space is in use; none of it without an allocator.
    fn publish_masquerade(&mut self) {
        let usage = self
            .sources
            .masquerade
            .get()
            .map(|allocator| allocator.usage())
            .unwrap_or_default();
        let labels: Vec<(String, String)> = usage
            .iter()
            .map(|u| {
                let VpcDiscriminant::VNI(vni) = u.dst_vpcd;
                (u.protocol.to_string(), vni.as_u32().to_string())
            })
            .collect();
        let regions: Vec<MasqueradeRegion<'_>> = usage
            .iter()
            .zip(&labels)
            .map(|(u, (protocol, dst_vpc))| MasqueradeRegion {
                protocol,
                dst_vpc,
                region: &u.region,
                addresses: u.addresses,
                addresses_in_use: u.addresses_in_use,
                port_blocks_in_use: u.port_blocks_in_use,
                port_blocks_free: u.port_blocks_free,
            })
            .collect();
        self.masquerade.publish(&regions);
    }
}

/// Every idle mode, as `--idle` spells it.
const MODES: [IdleMode; 3] = [IdleMode::Poll, IdleMode::Monitor, IdleMode::Interrupt];

/// Publish a polling worker's load, registering it the first time.
fn publish_load(
    loads: &mut HashMap<usize, WorkerLoadMetrics>,
    worker: usize,
    load: &WorkerLoadStatus,
) {
    let metrics = loads.entry(worker).or_insert_with(|| {
        let states = Spent::ALL.map(Spent::name);
        let modes = MODES.map(|mode| mode.to_string());
        let modes: Vec<&str> = modes.iter().map(String::as_str).collect();
        WorkerLoadMetrics::new(
            worker,
            &states,
            &modes,
            &load.reader.configured().to_string(),
        )
    });
    let totals = load.reader.load();
    let time_ns = Spent::ALL.map(|spent| (spent.name(), totals.nanos(spent)));
    metrics.publish(&WorkerLoadCounters {
        time_ns: &time_ns,
        monitor_sleeps: totals.monitor_sleeps,
        interrupt_sleeps: totals.interrupt_sleeps,
        effective_mode: &load.reader.effective().to_string(),
        expired_flows: totals.expired_flows,
        expiry_behind: totals.expiry_behind,
    });
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
    use crate::drivers::load::{Load, LoadTotals};
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
        worker.rx_tasks[1].activity = Activity::Stuck;
        worker.rx_tasks[1].misses = 2;
        let load = Load::new(IdleMode::Interrupt);
        worker.load = Some(WorkerLoadStatus {
            reader: load.reader(),
            recent: LoadTotals::default(),
        });
        writer.publish(DriverStatus {
            max_rx_batch: 32,
            workers: vec![worker],
            ports: Vec::new(),
        });

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let mut telemetry = Telemetry::new(TelemetrySources {
                packets: packets.clone(),
                flows: Arc::new(FlowTable::default()),
                driver,
                masquerade: nat::masquerade::NatAllocatorWriter::new().get_reader(),
                taps: vec![("eth0".to_string(), TapCounters::default())],
                hugepages: Some(HugepagePlan {
                    page_size_kb: 1 << 20,
                    per_node_mb: vec![(1, 3072)],
                    unplaced_mb: 512,
                }),
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
        assert!(
            rendered
                .keys()
                .any(|series| series.starts_with("dataplane_build_info{"))
        );
        assert_eq!(get(r#"port_tap_punted{port="eth0"}"#), Some(0.0));
        assert_eq!(
            get(r#"dpdk_hugepages_reserved_bytes{node="any"}"#),
            Some(536_870_912.0)
        );
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

        assert_eq!(get(r#"worker_running{worker="1"}"#), Some(1.0));
        assert_eq!(data("worker_stuck"), Some(0.0));
        assert_eq!(control("worker_stuck"), Some(1.0));
        assert_eq!(control("worker_watchdog_misses"), Some(2.0));

        // A polling worker's load: nothing spent yet, idling as configured.
        assert_eq!(
            get(r#"worker_time_nanoseconds{state="busy",worker="1"}"#),
            Some(0.0)
        );
        assert_eq!(
            get(r#"worker_idle_sleeps{kind="interrupt",worker="1"}"#),
            Some(0.0)
        );
        let mode = |mode: &str| {
            get(&format!(
                r#"worker_idle_mode{{configured="interrupt",mode="{mode}",worker="1"}}"#
            ))
        };
        assert_eq!(
            (mode("poll"), mode("monitor"), mode("interrupt")),
            (Some(0.0), Some(0.0), Some(1.0))
        );
    }

    /// Whatever init set aside, the series carry all of it, in bytes, under one label each: every
    /// node of the plan, and `any` exactly when some is on no node in particular.
    #[test]
    #[allow(clippy::cast_precision_loss)] // u16 MiB counts, summed, stay far below 2^52 bytes
    fn a_hugepage_plan_is_published_whole() {
        bolero::check!()
            .with_type::<(bool, BTreeMap<u32, u16>, u16)>()
            .for_each(|(gib_pages, nodes, unplaced)| {
                let plan = HugepagePlan {
                    page_size_kb: if *gib_pages { 1 << 20 } else { 2048 },
                    per_node_mb: nodes
                        .iter()
                        .map(|(node, mb)| (*node, u64::from(*mb)))
                        .collect(),
                    unplaced_mb: u64::from(*unplaced),
                };
                let recorder = PrometheusBuilder::new().build_recorder();
                let handle = recorder.handle();
                metrics::with_local_recorder(&recorder, || {
                    hugepage_metrics(&plan);
                });
                let rendered = series(&handle.render());
                let reserved: BTreeMap<&str, f64> = rendered
                    .iter()
                    .filter_map(|(series, bytes)| {
                        let node = series
                            .strip_prefix(r#"dpdk_hugepages_reserved_bytes{node=""#)?
                            .strip_suffix(r#""}"#)?;
                        Some((node, *bytes))
                    })
                    .collect();
                assert_eq!(
                    rendered.get("dpdk_hugepage_size_bytes"),
                    Some(&((plan.page_size_kb * 1024) as f64))
                );
                for (node, mb) in &plan.per_node_mb {
                    assert_eq!(
                        reserved.get(node.to_string().as_str()),
                        Some(&((mb << 20) as f64))
                    );
                }
                assert_eq!(
                    reserved.get("any"),
                    (plan.unplaced_mb > 0)
                        .then_some((plan.unplaced_mb << 20) as f64)
                        .as_ref()
                );
                let total_mb =
                    plan.per_node_mb.iter().map(|(_, mb)| mb).sum::<u64>() + plan.unplaced_mb;
                assert_eq!(reserved.values().sum::<f64>(), (total_mb << 20) as f64);
            });
    }
}
