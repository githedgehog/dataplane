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

use pkt_meta::dst_vpcd_lookup::{DstVpcdLookup, VpcDiscTablesWriter};
use pkt_meta::flow_table::{ExpirationsNF, FlowTable, LookupNF};

use nat::stateful::NatAllocatorWriter;
use nat::stateless::NatTablesWriter;
use nat::{StatefulNat, StatelessNat};

use net::buffer::PacketBufferMut;
use pipeline::DynPipeline;
use pipeline::sample_nfs::PacketDumper;
use pkt_io::{PktIo, PktQueue};
use routing::{Router, RouterError, RouterParams};

use vpcmap::map::VpcMapWriter;

use stats::{Stats, StatsCollector, VpcMapName, VpcStatsStore};

pub(crate) struct InternalSetup<Buf>
where
    Buf: PacketBufferMut,
{
    pub router: Router,
    pub pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Buf>>,
    pub vpcmapw: VpcMapWriter<VpcMapName>,
    pub nattablew: NatTablesWriter,
    pub natallocatorw: NatAllocatorWriter,
    pub vpcdtablesw: VpcDiscTablesWriter,
    pub stats: StatsCollector,
    pub vpc_stats_store: Arc<VpcStatsStore>,
    pub puntq: PktQueue<Buf>,
    pub injectq: PktQueue<Buf>,
}

/// Start a router and provide the associated pipeline
pub(crate) fn start_router<Buf: PacketBufferMut>(
    params: RouterParams,
) -> Result<InternalSetup<Buf>, RouterError> {
    let nattablew = NatTablesWriter::new();
    let natallocatorw = NatAllocatorWriter::new();
    let vpcdtablesw = VpcDiscTablesWriter::new();
    let router = Router::new(params)?;
    let vpcmapw = VpcMapWriter::<VpcMapName>::new();

    // Allocate the shared VPC stats store (returns Arc<VpcStatsStore>)
    let vpc_stats_store: Arc<VpcStatsStore> = VpcStatsStore::new();

    // Build stats collector + writer, wiring the same store instance in
    // Also returns stats store handle for gRPC server access
    let (stats, writer, vpc_stats_store) =
        StatsCollector::new_with_store(vpcmapw.get_reader(), vpc_stats_store.clone());

    let flow_table = Arc::new(FlowTable::default());

    let iftr_factory = router.get_iftabler_factory();
    let fibtr_factory = router.get_fibtr_factory();
    let vpcdtablesr_factory = vpcdtablesw.get_reader_factory();
    let atabler_factory = router.get_atabler_factory();
    let nattabler_factory = nattablew.get_reader_factory();
    let natallocator_factory = natallocatorw.get_reader_factory();

    // build pkt io stages
    let pktio_ip: PktIo<Buf> = PktIo::new(0, 10_000usize).set_name("pkt-io-ip ");
    let pktio_egress: PktIo<Buf> = PktIo::new(10_000usize, 0).set_name("pkt-io-egress");

    // queues to expose
    let puntq = pktio_ip.get_puntq().unwrap_or_else(|| unreachable!());
    let injectq = pktio_egress.get_injectq().unwrap_or_else(|| unreachable!());

    let pipeline_builder = move || {
        // Build network functions
        let stage_ingress = Ingress::new("Ingress", iftr_factory.handle());
        let stage_egress = Egress::new("Egress", iftr_factory.handle(), atabler_factory.handle());
        let dst_vpcd_lookup = DstVpcdLookup::new("dst-vni-lookup", vpcdtablesr_factory.handle());
        let iprouter1 = IpForwarder::new("IP-Forward-1", fibtr_factory.handle());
        let iprouter2 = IpForwarder::new("IP-Forward-2", fibtr_factory.handle());
        let stateless_nat = StatelessNat::with_reader("stateless-NAT", nattabler_factory.handle());
        let stateful_nat = StatefulNat::with_reader("stateful-NAT", natallocator_factory.handle());
        let dumper1 = PacketDumper::new("pre-ingress", true, None);
        let dumper2 = PacketDumper::new("post-egress", true, None);
        let stats_stage = Stats::new("stats", writer.clone());
        let flow_lookup_nf = LookupNF::new(flow_table.clone());
        let flow_expirations_nf = ExpirationsNF::new(flow_table.clone());
        let pktio_ip_worker = pktio_ip.clone();
        let pktio_egress_worker = pktio_egress.clone();

        // Build the pipeline for a router. The composition of the pipeline (in stages) is currently
        // hard-coded. In any pipeline, the Stats and ExpirationsNF stages should go last
        DynPipeline::new()
            .add_stage(dumper1)
            .add_stage(stage_ingress)
            .add_stage(iprouter1)
            .add_stage(pktio_ip_worker)
            .add_stage(dst_vpcd_lookup)
            .add_stage(flow_lookup_nf)
            .add_stage(stateless_nat)
            .add_stage(stateful_nat)
            .add_stage(iprouter2)
            .add_stage(pktio_egress_worker)
            .add_stage(stage_egress)
            .add_stage(dumper2)
            .add_stage(flow_expirations_nf)
            .add_stage(stats_stage)
    };

    Ok(InternalSetup {
        router,
        pipeline: Arc::new(pipeline_builder),
        vpcmapw,
        nattablew,
        natallocatorw,
        vpcdtablesw,
        stats,
        vpc_stats_store,
        puntq,
        injectq,
    })
}
