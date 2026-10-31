// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use flow_entry::flow_table::{TimerRegistry, WorkerFlowTable};
mod egress;
#[cfg(test)]
mod fuzz;
mod ingress;
mod ipforward;

use super::drivers::status::{DpdkPortStatsCli, DpdkPortsCli, DriverStatusReader};
#[allow(unused)]
use super::packet_processor::egress::Egress;
use super::packet_processor::ingress::Ingress;
use super::packet_processor::ipforward::IpForwarder;

use capture::{CaptureController, CaptureDirectory, CaptureStage, Direction};
use concurrency::sync::Arc;

use acl_filter::{AclFilter, AclFilterContextReaderFactory, AclFilterContextWriter};
use flow_entry::flow_table::{FlowLookup, FlowTable, FlowTableSummary};
use flow_filter::{FlowFilter, FlowFilterContextReaderFactory, FlowFilterContextWriter};
use rate_limit::{PeeringRules, RateLimitReader, RateLimitWriter, RateLimiter, RateLimits};
use std::num::NonZeroUsize;

use nat::masquerade::{NatAllocatorReaderFactory, NatAllocatorWriter};
use nat::portfw::{PortForwarder, PortFwTableReaderFactory, PortFwTableWriter};
use nat::static_nat::NatTablesWriter;
use nat::static_nat::natrw::NatTablesReaderFactory;
use nat::{FlowTracker, IcmpErrorHandler, Masquerade, StaticNat};
use net::packet::PacketStats;

use net::buffer::PacketBufferMut;
use pipeline::sample_nfs::{PacketDumper, PacketStatsNF};
use pipeline::{DynPipeline, PipelineData};

use routing::{
    AtableReaderFactory, CliSources, FibTableReaderFactory, IfTableReaderFactory, Router,
    RouterError, RouterParams,
};

use vpcmap::map::VpcMapWriter;

use stats::{PacketStatsWriter, Stats, StatsCollector, VpcMapName, VpcStatsStore};

pub(crate) struct InternalSetup {
    pub router: Router,
    /// Shared pipeline inputs; the driver chooses the buffer type.
    pub pipeline: PipelineIngredients,
    pub flow_table: Arc<FlowTable>,
    pub vpcmapw: VpcMapWriter<VpcMapName>,
    pub nattablesw: NatTablesWriter,
    pub natallocatorw: NatAllocatorWriter,
    pub flow_filter_writer: FlowFilterContextWriter,
    pub aclfiltertablesw: AclFilterContextWriter,
    pub rate_limits: RateLimitWriter<PeeringRules>,
    pub stats: StatsCollector,
    pub vpc_stats_store: Arc<VpcStatsStore>,
    pub portfw_w: PortFwTableWriter,
    /// Where the LLDP agent publishes its neighbours for the CLI.
    pub lldp_neighbors: tokio::sync::watch::Sender<crate::lldp_agent::NeighborSnapshot>,
    /// Where the transceiver agent publishes what it last read from each port's module.
    pub transceivers: tokio::sync::watch::Sender<crate::transceiver_agent::ModuleSnapshot>,
    /// Where the phy agent publishes what `mstlink` last said about each port.
    pub phy: tokio::sync::watch::Sender<crate::phy_agent::PhySnapshot>,
    /// Packets the pipeline finished with, by reason, for telemetry.
    pub pkt_stats: Arc<PacketStats>,
}

/// Shared inputs for building a separate pipeline on each worker thread.
pub(crate) struct PipelineIngredients {
    pdata: Arc<PipelineData>,
    iftr_factory: IfTableReaderFactory,
    fibtr_factory: FibTableReaderFactory,
    atabler_factory: AtableReaderFactory,
    nattabler_factory: NatTablesReaderFactory,
    natallocator_factory: NatAllocatorReaderFactory,
    flow_filter_reader_factory: FlowFilterContextReaderFactory,
    aclfiltertablesr_factory: AclFilterContextReaderFactory,
    rate_limits: RateLimitReader<PeeringRules>,
    portfw_factory: PortFwTableReaderFactory,
    stats_w: PacketStatsWriter,
    pkt_stats: Arc<PacketStats>,
    flow_table: Arc<FlowTable>,
    /// Every worker's timer queue; each worker's pipeline registers its own.
    timers: TimerRegistry,
    capture: CaptureController,
}

impl PipelineIngredients {
    /// The generation counter shared with the management plane.
    pub(crate) fn data(&self) -> Arc<PipelineData> {
        self.pdata.clone()
    }

    /// Create a shared factory for the driver's buffer type and lifetime.
    /// The returned pipelines are constructed and used on their worker threads.
    pub(crate) fn factory<'nf, Buf: PacketBufferMut + 'nf>(self) -> PipelineFactory<'nf, Buf> {
        Arc::new(move || {
            // This worker's handle on the shared flow table, for the stages that create flows.
            let flows = WorkerFlowTable::registered(self.flow_table.clone(), &self.timers);

            // Build network functions
            let stage_ingress = Ingress::new("Ingress", self.iftr_factory.handle());
            let stage_egress = Egress::new(
                "Egress",
                self.iftr_factory.handle(),
                self.atabler_factory.handle(),
            );
            let iprouter1 = IpForwarder::new("IP-Forward-1", self.fibtr_factory.handle());
            let iprouter2 = IpForwarder::new("IP-Forward-2", self.fibtr_factory.handle());
            let static_nat = StaticNat::with_reader(
                "static-NAT",
                self.nattabler_factory.handle(),
                flows.clone(),
            );
            let masquerade = Masquerade::new(
                "masquerade",
                flows.clone(),
                self.natallocator_factory.handle(),
            );
            let flow_tracker = FlowTracker::new("flow-tracker", flows.clone());
            let pktdump = PacketDumper::new("pipeline-end", true, None);
            let stats_stage = Stats::new("stats", self.stats_w.clone());
            let flow_filter =
                FlowFilter::new("flow-filter", self.flow_filter_reader_factory.handle());
            let acl_filter = AclFilter::new("acl-filter", self.aclfiltertablesr_factory.handle());
            let rate_limiter = RateLimiter::new(self.rate_limits.clone());
            let icmp_error_handler = IcmpErrorHandler::new(self.flow_table.clone());
            let flow_lookup = FlowLookup::new("flow-lookup", self.flow_table.clone());
            let portfw = PortForwarder::new(
                "port-forwarder",
                self.portfw_factory.handle(),
                flows.clone(),
            );
            let pkt_stats_nf = PacketStatsNF::new(self.pkt_stats.clone());
            // First and right after egress, so the two views of a packet can be compared.
            let capture_ingress =
                CaptureStage::new(Direction::Ingress, self.capture.sink(Direction::Ingress));
            let capture_egress =
                CaptureStage::new(Direction::Egress, self.capture.sink(Direction::Egress));

            // Build the pipeline for a router. The composition of the pipeline (in stages) is
            // currently hard-coded. Flows expire on the worker's timer wheel, which the worker
            // drives through `WorkerFlowTable::expire`; no stage is needed for it.
            let pipeline = DynPipeline::new()
                .set_data(self.pdata.clone())
                .add_stage(capture_ingress)
                .add_stage(stage_ingress)
                .add_stage(iprouter1)
                .add_stage(icmp_error_handler)
                .add_stage(flow_lookup)
                .add_stage(flow_filter)
                .add_stage(acl_filter)
                // After the ACLs, so that denied packets are not charged; before NAT, so that rate
                // limits see destinations as the source VPC addresses them.
                .add_stage(rate_limiter)
                .add_stage(static_nat)
                .add_stage(portfw)
                .add_stage(masquerade)
                .add_stage(flow_tracker)
                .add_stage(iprouter2)
                .add_stage(stage_egress)
                .add_stage(capture_egress)
                .add_stage(pktdump)
                .add_stage(pkt_stats_nf)
                .add_stage(stats_stage);
            WorkerPipeline { pipeline, flows }
        })
    }
}

/// A pipeline built on, and for, one worker thread, with that worker's handle on the flow table.
///
/// The worker owns the expiry of every flow its pipeline creates, and drives it by calling
/// [`WorkerFlowTable::expire`] on `flows` from its loop, with up to [`expiry_budget`] timers each
/// time.
pub(crate) struct WorkerPipeline<'nf, Buf: PacketBufferMut> {
    pub(crate) pipeline: DynPipeline<'nf, Buf>,
    pub(crate) flows: WorkerFlowTable,
}

/// How many times its usual budget a worker that is behind on expiry spends per pass.
const EXPIRY_CATCH_UP: usize = 4;

/// Flow timers a worker looks at per expiry pass, when one pass receives up to `bursts` bursts of
/// up to `burst` packets each and the last pass was or was not left `behind`.
///
/// Every packet can open a flow pair, which is two timers, so twice what a pass can receive keeps
/// pace with a flood of new flows. A worker that is behind spends [`EXPIRY_CATCH_UP`] times that,
/// so that a backlog drains rather than holding steady.
pub(crate) fn expiry_budget(burst: usize, bursts: usize, behind: bool) -> usize {
    let pace = 2 * burst * bursts.max(1);
    if behind { pace * EXPIRY_CATCH_UP } else { pace }
}

/// Builds a worker's pipeline, on the worker's thread.
pub(crate) type PipelineFactory<'nf, Buf> =
    Arc<dyn Send + Sync + Fn() -> WorkerPipeline<'nf, Buf> + 'nf>;

/// Start a router and provide the ingredients for its pipeline
pub(crate) fn start_router(
    router: &lifecycle::Subsystem,
    params: RouterParams,
    driver_status: DriverStatusReader,
    capture_dir: Option<String>,
    workers: NonZeroUsize,
) -> Result<InternalSetup, RouterError> {
    let vpcmapw = VpcMapWriter::<VpcMapName>::new();
    let vpc_stats_store: Arc<VpcStatsStore> = VpcStatsStore::new();

    // Build stats collector + writer, wiring the same store instance in
    // Also returns stats store handle for gRPC server access
    let (stats, stats_w, vpc_stats_store) =
        StatsCollector::new_with_store(vpcmapw.get_reader(), vpc_stats_store.clone());

    // create entities shared by management and data-path NFs
    let flow_table = Arc::new(FlowTable::default());
    let flow_filter_writer = FlowFilterContextWriter::new();
    let flow_filter_reader_factory = flow_filter_writer.get_reader_factory();
    let aclfiltertablesw = AclFilterContextWriter::new();
    let aclfiltertablesr_factory = aclfiltertablesw.get_reader_factory();
    let rate_limits = RateLimitWriter::new(RateLimits::empty(), workers);
    let nattablesw = NatTablesWriter::new();
    // Workers register with this as they build their pipelines. Through it, the control plane puts
    // the reapers of mappings it carries over on a configuration change on the workers' wheels.
    let timers = TimerRegistry::new();
    let natallocatorw = NatAllocatorWriter::with_timers(timers.clone());
    let nattabler_factory = nattablesw.get_reader_factory();
    let natallocator_factory = natallocatorw.get_reader_factory();
    let portfw_w = PortFwTableWriter::new();
    let portfw_factory = portfw_w.reader().factory();
    let pdata = Arc::from(PipelineData::new(0));
    let pkt_stats = Arc::from(PacketStats::new());
    let capture = CaptureController::new();
    let (lldp_neighbors, lldp_heard) =
        tokio::sync::watch::channel(crate::lldp_agent::NeighborSnapshot::default());
    let (transceivers, transceivers_read) =
        tokio::sync::watch::channel(crate::transceiver_agent::ModuleSnapshot::default());
    let (phy, phy_read) = tokio::sync::watch::channel(crate::phy_agent::PhySnapshot::default());

    // collect readers and the like for cli
    let cli_sources = CliSources {
        flow_table: Some(Box::new(flow_table.clone())),
        flow_filter: Some(Box::new(flow_filter_reader_factory.handle().inner())),
        portfw_table: Some(Box::new(portfw_w.reader().inner())),
        nat_tables: Some(Box::new(nattabler_factory.handle().inner())),
        masquerade_state: Some(Box::new(natallocator_factory.handle().inner())),
        pkt_stats: Some(Box::new(pkt_stats.clone())),
        driver_status: Some(Box::new(driver_status.clone())),
        dpdk_ports: Some(Box::new(DpdkPortsCli(driver_status.clone()))),
        dpdk_port_stats: Some(Box::new(DpdkPortStatsCli(driver_status))),
        flow_table_summary: Some(Box::new(FlowTableSummary(flow_table.clone()))),
        capture: Some(CaptureDirectory::new(
            capture.clone(),
            capture_dir.map(std::path::PathBuf::from),
        )),
        lldp_neighbors: Some(Box::new(crate::lldp_agent::NeighborsCli(lldp_heard))),
        transceivers: Some(Box::new(crate::transceiver_agent::ModulesCli(
            transceivers_read,
        ))),
        link: Some(Box::new(crate::phy_agent::PhyCli(phy_read))),
        rate_limits: Some(Box::new(rate_limits.reader())),
    };

    // create router
    let router = Router::new(router, params, Some(cli_sources))?;
    let iftr_factory = router.get_iftabler_factory();
    let fibtr_factory = router.get_fibtr_factory();
    let atabler_factory = router.get_atabler_factory();

    let ingredients = PipelineIngredients {
        pdata,
        iftr_factory,
        fibtr_factory,
        atabler_factory,
        nattabler_factory,
        natallocator_factory,
        flow_filter_reader_factory,
        aclfiltertablesr_factory,
        rate_limits: rate_limits.reader(),
        portfw_factory,
        stats_w,
        pkt_stats: pkt_stats.clone(),
        flow_table: flow_table.clone(),
        timers,
        capture,
    };

    Ok(InternalSetup {
        router,
        pipeline: ingredients,
        flow_table,
        vpcmapw,
        nattablesw,
        natallocatorw,
        flow_filter_writer,
        aclfiltertablesw,
        rate_limits,
        stats,
        vpc_stats_store,
        portfw_w,
        lldp_neighbors,
        transceivers,
        phy,
        pkt_stats,
    })
}

#[cfg(test)]
mod tests {
    use super::expiry_budget;
    use concurrency::sync::Arc;
    use flow_entry::flow_table::{FlowTable, WorkerFlowTable};
    use net::flows::{FlowInfo, FlowInfoFlags};
    use net::{FlowKey, IpProtoKey, TcpProtoKey};
    use std::time::Duration;

    fn key(port: u16) -> FlowKey {
        FlowKey::new(
            None,
            net::flows::flow_key::FlowAddrs::V4 {
                src: "10.0.0.1".parse().unwrap(),
                dst: "10.0.0.2".parse().unwrap(),
            },
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: port.try_into().unwrap(),
                dst_port: 80.try_into().unwrap(),
            }),
        )
    }

    /// A worker whose every packet opens a flow that has already expired keeps up: the table
    /// holds what the wheel has not reached yet, and no more, rather than growing with every pass.
    #[test]
    fn expiry_keeps_up_with_a_flood_of_new_flows() {
        const BURST: usize = 64;
        const PASSES: usize = 200;
        // One pass a millisecond, against the standard wheel's 10 ms tick: a flow is not due
        // until the tick after its deadline, so up to two ticks' passes are held waiting for it.
        const PASS: Duration = Duration::from_millis(1);
        const HELD_PASSES: usize = 2 * 10;
        let table = Arc::new(FlowTable::new(2));
        let flows = WorkerFlowTable::new(table.clone());
        let start = clock::now();
        let expired = start + PASS;
        let mut now = start + Duration::from_secs(1);
        let mut behind = false;
        let mut port = 1u16;
        let mut most = 0;
        for _ in 0..PASSES {
            for _ in 0..BURST {
                let (forward, reverse) = FlowInfo::related_pair(
                    expired,
                    key(port),
                    FlowInfoFlags::INITIATOR,
                    key(port + 1),
                    FlowInfoFlags::default(),
                )
                .unwrap();
                flows.insert_pair_if_absent(&forward, &reverse).unwrap();
                port += 2;
            }
            behind = flows.expire(now, expiry_budget(BURST, 1, behind)).behind();
            most = most.max(table.live_len());
            now += PASS;
        }
        assert!(
            most <= HELD_PASSES * 2 * BURST,
            "{most} flows held over {PASSES} passes of {BURST} new pairs each"
        );
    }

    /// The budget is twice what a pass can receive, and a multiple of that while behind.
    #[test]
    fn the_budget_scales_with_bursts_and_backlog() {
        assert_eq!(expiry_budget(64, 1, false), 128);
        assert_eq!(expiry_budget(64, 3, false), 384);
        assert_eq!(expiry_budget(64, 0, false), 128);
        assert!(expiry_budget(64, 1, true) > expiry_budget(64, 1, false));
    }
}
