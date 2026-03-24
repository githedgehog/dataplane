// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod egress;
mod ingress;
mod ipforward;

#[allow(unused)]
use super::packet_processor::egress::Egress;
use super::packet_processor::ingress::Ingress;
use super::packet_processor::ipforward::IpForwarder;

use concurrency::sync::Arc;

use flow_entry::flow_table::{FlowLookup, FlowTable};
use flow_filter::{FlowFilter, FlowFilterTableWriter};

use nat::portfw::{PortForwarder, PortFwTableWriter};
use nat::stateful::NatAllocatorWriter;
use nat::stateless::NatTablesWriter;
use nat::{IcmpErrorHandler, StatefulNat, StatelessNat};
use net::packet::PacketStats;

use net::buffer::PacketBufferMut;
use pipeline::sample_nfs::{PacketDumper, PacketStatsNF};
use pipeline::{DynPipeline, PipelineData};

use routing::{CliSources, Router, RouterError, RouterParams};

use vpcmap::map::VpcMapWriter;

use stats::{Stats, StatsCollector, VpcMapName, VpcStatsStore};

pub(crate) struct InternalSetup<Buf>
where
    Buf: PacketBufferMut,
{
    pub router: Router,
    pub pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Buf>>,
    pub flow_table: Arc<FlowTable>,
    pub vpcmapw: VpcMapWriter<VpcMapName>,
    pub nattablesw: NatTablesWriter,
    pub natallocatorw: NatAllocatorWriter,
    pub flowfiltertablesw: FlowFilterTableWriter,
    pub stats: StatsCollector,
    pub vpc_stats_store: Arc<VpcStatsStore>,
    pub portfw_w: PortFwTableWriter,
}

/// Start a router and provide the associated pipeline
pub(crate) fn start_router<Buf: PacketBufferMut>(
    params: RouterParams,
) -> Result<InternalSetup<Buf>, RouterError> {
    let vpcmapw = VpcMapWriter::<VpcMapName>::new();
    let vpc_stats_store: Arc<VpcStatsStore> = VpcStatsStore::new();

    // Build stats collector + writer, wiring the same store instance in
    // Also returns stats store handle for gRPC server access
    let (stats, stats_w, vpc_stats_store) =
        StatsCollector::new_with_store(vpcmapw.get_reader(), vpc_stats_store.clone());

    // create entities shared by management and data-path NFs
    let flow_table = Arc::new(FlowTable::default());
    let flowfiltertablesw = FlowFilterTableWriter::new();
    let flowfiltertablesr_factory = flowfiltertablesw.get_reader_factory();
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
        flow_filter: Some(Box::new(flowfiltertablesr_factory.handle().inner())),
        portfw_table: Some(Box::new(portfw_w.reader().inner())),
        nat_tables: Some(Box::new(nattabler_factory.handle().inner())),
        masquerade_state: Some(Box::new(natallocator_factory.handle().inner())),
        pkt_stats: Some(Box::new(pkt_stats.clone())),
    };

    // create router
    let router = Router::new(params, Some(cli_sources))?;
    let iftr_factory = router.get_iftabler_factory();
    let fibtr_factory = router.get_fibtr_factory();
    let atabler_factory = router.get_atabler_factory();

    // create pipeline builder
    let flow_table_clone = flow_table.clone();
    let pipeline_builder = move || {
        let pdata_clone = pdata.clone();

        // Build network functions
        let stage_ingress = Ingress::new("Ingress", iftr_factory.handle());
        let stage_egress = Egress::new("Egress", iftr_factory.handle(), atabler_factory.handle());
        let iprouter1 = IpForwarder::new("IP-Forward-1", fibtr_factory.handle());
        let iprouter2 = IpForwarder::new("IP-Forward-2", fibtr_factory.handle());
        let stateless_nat = StatelessNat::with_reader("stateless-NAT", nattabler_factory.handle());
        let stateful_nat = StatefulNat::new(
            "stateful-NAT",
            flow_table_clone.clone(),
            natallocator_factory.handle(),
        );
        let pktdump = PacketDumper::new("pipeline-end", true, None);
        let stats_stage = Stats::new("stats", stats_w.clone());
        let flow_filter = FlowFilter::new("flow-filter", flowfiltertablesr_factory.handle());
        let icmp_error_handler = IcmpErrorHandler::new(flow_table_clone.clone());
        let flow_lookup = FlowLookup::new("flow-lookup", flow_table_clone.clone());
        let portfw = PortForwarder::new(
            "port-forwarder",
            portfw_factory.handle(),
            flow_table_clone.clone(),
        );
        let pkt_stats_nf = PacketStatsNF::new(pkt_stats.clone());

        // Build the pipeline for a router. The composition of the pipeline (in stages) is currently
        // hard-coded. Flow expiration is handled by per-flow tokio timers; no ExpirationsNF needed.
        DynPipeline::new()
            .set_data(pdata_clone)
            .add_stage(stage_ingress)
            .add_stage(iprouter1)
            .add_stage(flow_lookup)
            .add_stage(flow_filter)
            .add_stage(icmp_error_handler)
            .add_stage(portfw)
            .add_stage(stateless_nat)
            .add_stage(stateful_nat)
            .add_stage(iprouter2)
            .add_stage(stage_egress)
            .add_stage(pktdump)
            .add_stage(pkt_stats_nf)
            .add_stage(stats_stage)
    };

    Ok(InternalSetup {
        router,
        pipeline: Arc::new(pipeline_builder),
        flow_table,
        vpcmapw,
        nattablesw,
        natallocatorw,
        flowfiltertablesw,
        stats,
        vpc_stats_store,
        portfw_w,
    })
}
