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
    /// Everything a pipeline is built from, but not a pipeline.
    ///
    /// The buffer type is the driver's choice, not the router's -- a DPDK driver runs the pipeline
    /// over `Mbuf`, the kernel driver over `TestBuffer` -- and it cannot be known here, because the
    /// mbuf case is branded with the lifetime of the queues it will be received on, which do not
    /// exist yet. Every stage in the pipeline is generic over the buffer anyway, so the choice
    /// costs nothing to defer: call [`PipelineIngredients::factory`] once the driver is known.
    pub pipeline: PipelineIngredients,
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

/// Everything the router hands the datapath, minus the choice of buffer.
///
/// Each field is a writer handle or reader factory shared with the management plane; a fresh
/// pipeline is built from them per worker, because a `DynPipeline` is not shareable between
/// threads and, over mbufs, is not even `Send`.
pub(crate) struct PipelineIngredients {
    pdata: Arc<PipelineData>,
    iftr_factory: IfTableReaderFactory,
    fibtr_factory: FibTableReaderFactory,
    atabler_factory: AtableReaderFactory,
    nattabler_factory: NatTablesReaderFactory,
    natallocator_factory: NatAllocatorReaderFactory,
    flow_filter_reader_factory: FlowFilterContextReaderFactory,
    aclfiltertablesr_factory: AclFilterContextReaderFactory,
    portfw_factory: PortFwTableReaderFactory,
    stats_w: PacketStatsWriter,
    pkt_stats: Arc<PacketStats>,
    flow_table: Arc<FlowTable>,
}

impl PipelineIngredients {
    /// The generation counter shared with the management plane.
    pub(crate) fn data(&self) -> Arc<PipelineData> {
        self.pdata.clone()
    }

    /// Turn the ingredients into a pipeline factory over a concrete buffer type.
    ///
    /// The buffer only appears in the returned type: every stage below is generic over it, so the
    /// composition is identical whether the driver hands the pipeline an `Mbuf` off a receive queue
    /// or an owned test buffer. `'nf` is whatever bounds that buffer -- `'static` for an owned one,
    /// and for an mbuf the borrow of the queues it is received on.
    ///
    /// The closure is `Send + Sync` while the pipeline it returns need not be, which is what lets
    /// one factory be shared across worker threads that each build their own.
    pub(crate) fn factory<'nf, Buf: PacketBufferMut + 'nf>(
        self,
    ) -> Arc<dyn Send + Sync + Fn() -> DynPipeline<'nf, Buf> + 'nf> {
        Arc::new(move || {
            // Build network functions
            let stage_ingress = Ingress::new("Ingress", self.iftr_factory.handle());
            let stage_egress = Egress::new(
                "Egress",
                self.iftr_factory.handle(),
                self.atabler_factory.handle(),
            );
            let iprouter1 = IpForwarder::new("IP-Forward-1", self.fibtr_factory.handle());
            let iprouter2 = IpForwarder::new("IP-Forward-2", self.fibtr_factory.handle());
            let static_nat =
                StaticNat::with_reader("static-NAT-1", self.nattabler_factory.handle());
            let masquerade = Masquerade::new(
                "masquerade",
                self.flow_table.clone(),
                self.natallocator_factory.handle(),
            );
            let pktdump = PacketDumper::new("pipeline-end", true, None);
            let stats_stage = Stats::new("stats", self.stats_w.clone());
            let flow_filter =
                FlowFilter::new("flow-filter", self.flow_filter_reader_factory.handle());
            let acl_filter = AclFilter::new("acl-filter", self.aclfiltertablesr_factory.handle());
            let icmp_error_handler = IcmpErrorHandler::new(self.flow_table.clone());
            let flow_lookup = FlowLookup::new("flow-lookup", self.flow_table.clone());
            let portfw = PortForwarder::new(
                "port-forwarder",
                self.portfw_factory.handle(),
                self.flow_table.clone(),
            );
            let pkt_stats_nf = PacketStatsNF::new(self.pkt_stats.clone());

            // Build the pipeline for a router. The composition of the pipeline (in stages) is
            // currently hard-coded. Flow expiration is handled by per-flow tokio timers; no
            // ExpirationsNF needed.
            DynPipeline::new()
                .set_data(self.pdata.clone())
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
        })
    }
}

/// Start a router and provide the ingredients for its pipeline
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

    let ingredients = PipelineIngredients {
        pdata,
        iftr_factory,
        fibtr_factory,
        atabler_factory,
        nattabler_factory,
        natallocator_factory,
        flow_filter_reader_factory,
        aclfiltertablesr_factory,
        portfw_factory,
        stats_w,
        pkt_stats,
        flow_table: flow_table.clone(),
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
        stats,
        vpc_stats_store,
        portfw_w,
    })
}
