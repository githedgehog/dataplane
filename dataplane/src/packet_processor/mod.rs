// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod egress;
mod ingress;
mod ipforward;

use super::drivers::status::DriverStatusReader;
#[allow(unused)]
use super::packet_processor::egress::Egress;
use super::packet_processor::ingress::Ingress;
use super::packet_processor::ipforward::IpForwarder;

use concurrency::sync::Arc;

use acl_filter::{AclFilter, AclFilterContextReaderFactory, AclFilterContextWriter};
use flow_entry::flow_table::{FlowLookup, FlowTable};
use flow_filter::{FlowFilter, FlowFilterContextReaderFactory, FlowFilterContextWriter};

use nat::masquerade::{NatAllocatorReaderFactory, NatAllocatorWriter};
use nat::portfw::{PortForwarder, PortFwTableReaderFactory, PortFwTableWriter};
use nat::static_nat::NatTablesWriter;
use nat::static_nat::natrw::NatTablesReaderFactory;
use nat::{IcmpErrorHandler, Masquerade, StaticNat};
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
    pub pipeline: Arc<PipelineFactory>,
    pub flow_table: Arc<FlowTable>,
    pub vpcmapw: VpcMapWriter<VpcMapName>,
    pub nattablesw: NatTablesWriter,
    pub natallocatorw: NatAllocatorWriter,
    pub flow_filter_writer: FlowFilterContextWriter,
    pub aclfiltertablesw: AclFilterContextWriter,
    pub stats: StatsCollector,
    pub vpc_stats_store: Arc<VpcStatsStore>,
    pub portfw_w: PortFwTableWriter,
}

/// Everything a pipeline is built from, held so that one can be built again.
///
/// Each worker runs a pipeline of its own, and the buffer type is the driver's
/// to choose: the kernel driver reads into `TestBuffer`, the `AF_XDP` driver
/// into a buffer over a UMEM frame. None of what a stage is built from depends
/// on that choice, so the factory is not generic and [`build`](Self::build) is.
pub(crate) struct PipelineFactory {
    pdata: Arc<PipelineData>,
    pkt_stats: Arc<PacketStats>,
    stats_w: PacketStatsWriter,
    flow_table: Arc<FlowTable>,
    iftr_factory: IfTableReaderFactory,
    fibtr_factory: FibTableReaderFactory,
    atabler_factory: AtableReaderFactory,
    nattabler_factory: NatTablesReaderFactory,
    natallocator_factory: NatAllocatorReaderFactory,
    portfw_factory: PortFwTableReaderFactory,
    flow_filter_reader_factory: FlowFilterContextReaderFactory,
    aclfiltertablesr_factory: AclFilterContextReaderFactory,
}

impl PipelineFactory {
    /// The pipeline data shared by every pipeline built here, which management
    /// reads to report on and control the stages.
    pub(crate) fn data(&self) -> Arc<PipelineData> {
        self.pdata.clone()
    }

    /// A factory for pipelines over `Buf`, in the shape the drivers take.
    ///
    /// Each worker calls it to get a pipeline of its own, so it hands out a
    /// handle to this factory rather than a pipeline.
    pub(crate) fn builder<Buf: PacketBufferMut>(
        self: &Arc<Self>,
    ) -> Arc<dyn Send + Sync + Fn() -> DynPipeline<Buf>> {
        let factory = self.clone();
        Arc::new(move || factory.build())
    }

    /// Build a pipeline over `Buf`.
    ///
    /// The composition of the pipeline is hard-coded. Flow expiration is
    /// handled by per-flow tokio timers; no `ExpirationsNF` is needed.
    pub(crate) fn build<Buf: PacketBufferMut>(&self) -> DynPipeline<Buf> {
        // Build network functions
        let stage_ingress = Ingress::new("Ingress", self.iftr_factory.handle());
        let stage_egress = Egress::new(
            "Egress",
            self.iftr_factory.handle(),
            self.atabler_factory.handle(),
        );
        let iprouter1 = IpForwarder::new("IP-Forward-1", self.fibtr_factory.handle());
        let iprouter2 = IpForwarder::new("IP-Forward-2", self.fibtr_factory.handle());
        let static_nat = StaticNat::with_reader("static-NAT-1", self.nattabler_factory.handle());
        let masquerade = Masquerade::new(
            "masquerade",
            self.flow_table.clone(),
            self.natallocator_factory.handle(),
        );
        let pktdump = PacketDumper::new("pipeline-end", true, None);
        let stats_stage = Stats::new("stats", self.stats_w.clone());
        let flow_filter = FlowFilter::new("flow-filter", self.flow_filter_reader_factory.handle());
        let acl_filter = AclFilter::new("acl-filter", self.aclfiltertablesr_factory.handle());
        let icmp_error_handler = IcmpErrorHandler::new(self.flow_table.clone());
        let flow_lookup = FlowLookup::new("flow-lookup", self.flow_table.clone());
        let portfw = PortForwarder::new(
            "port-forwarder",
            self.portfw_factory.handle(),
            self.flow_table.clone(),
        );
        let pkt_stats_nf = PacketStatsNF::new(self.pkt_stats.clone());

        DynPipeline::new()
            .set_data(self.data())
            .add_stage(stage_ingress)
            .add_stage(iprouter1)
            .add_stage(icmp_error_handler)
            .add_stage(flow_lookup)
            .add_stage(flow_filter)
            .add_stage(acl_filter)
            .add_stage(static_nat)
            .add_stage(portfw)
            .add_stage(masquerade)
            .add_stage(iprouter2)
            .add_stage(stage_egress)
            .add_stage(pktdump)
            .add_stage(pkt_stats_nf)
            .add_stage(stats_stage)
    }
}

/// Start a router and provide the associated pipeline
pub(crate) fn start_router(
    router: &lifecycle::Subsystem,
    params: RouterParams,
    driver_status: DriverStatusReader,
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
    let nattablesw = NatTablesWriter::new();
    let natallocatorw = NatAllocatorWriter::new();
    let nattabler_factory = nattablesw.get_reader_factory();
    let natallocator_factory = natallocatorw.get_reader_factory();
    let portfw_w = PortFwTableWriter::new();
    let portfw_factory = portfw_w.reader().factory();
    let pdata = Arc::from(PipelineData::new(0));
    let pkt_stats = Arc::from(PacketStats::new());

    // collect readers and the like for cli
    let cli_sources = CliSources {
        flow_table: Some(Box::new(flow_table.clone())),
        flow_filter: Some(Box::new(flow_filter_reader_factory.handle().inner())),
        portfw_table: Some(Box::new(portfw_w.reader().inner())),
        nat_tables: Some(Box::new(nattabler_factory.handle().inner())),
        masquerade_state: Some(Box::new(natallocator_factory.handle().inner())),
        pkt_stats: Some(Box::new(pkt_stats.clone())),
        driver_status: Some(Box::new(driver_status)),
    };

    // create router
    let router = Router::new(router, params, Some(cli_sources))?;
    let iftr_factory = router.get_iftabler_factory();
    let fibtr_factory = router.get_fibtr_factory();
    let atabler_factory = router.get_atabler_factory();

    // create the pipeline factory
    let pipeline = PipelineFactory {
        pdata,
        pkt_stats,
        stats_w,
        flow_table: flow_table.clone(),
        iftr_factory,
        fibtr_factory,
        atabler_factory,
        nattabler_factory,
        natallocator_factory,
        portfw_factory,
        flow_filter_reader_factory,
        aclfiltertablesr_factory,
    };

    Ok(InternalSetup {
        router,
        pipeline: Arc::new(pipeline),
        flow_table,
        vpcmapw,
        nattablesw,
        natallocatorw,
        flow_filter_writer,
        aclfiltertablesw,
        stats,
        vpc_stats_store,
        portfw_w,
    })
}
