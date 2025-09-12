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

use nat::StatelessNat;
use nat::stateful::NatAllocatorWriter;
use nat::stateless::NatTablesWriter;

use net::buffer::PacketBufferMut;
use pipeline::DynPipeline;
use pipeline::sample_nfs::PacketDumper;

use routing::{Router, RouterError, RouterParams};

use vpcmap::map::VpcMapWriter;

use stats::{Stats, StatsCollector, VpcMapName};
pub(crate) struct InternalSetup<Buf>
where
    Buf: PacketBufferMut,
{
    pub router: Router,
    pub pipeline: DynPipeline<Buf>,
    pub vpcmapw: VpcMapWriter<VpcMapName>,
    pub nattablew: NatTablesWriter,
    pub natallocatorw: NatAllocatorWriter,
    pub vpcdtablesw: VpcDiscTablesWriter,
    pub stats: StatsCollector,
}

/// Start a router and provide the associated pipeline
pub(crate) fn start_router<Buf: PacketBufferMut>(
    params: RouterParams,
) -> Result<InternalSetup<Buf>, RouterError> {
    let nattablew = NatTablesWriter::new();
    let natallocatorw = NatAllocatorWriter::new();
    let vpcdtablesw = VpcDiscTablesWriter::new();
    let router = Router::new(params)?;
    let iftr = router.get_iftabler();
    let fibtr = router.get_fibtr();
    let vpcmapw = VpcMapWriter::<VpcMapName>::new();
    let (stats, writer) = StatsCollector::new(vpcmapw.get_reader());
    let flow_table = Arc::new(FlowTable::default());

    // Build network functions

    let stage_ingress = Ingress::new("Ingress", iftr.clone());
    let stage_egress = Egress::new("Egress", iftr, router.get_atabler());
    let dst_vpcd_lookup = DstVpcdLookup::new("dst-vni-lookup", vpcdtablesw.get_reader());
    let iprouter1 = IpForwarder::new("IP-Forward-1", fibtr.clone());
    let iprouter2 = IpForwarder::new("IP-Forward-2", fibtr);
    let stateless_nat = StatelessNat::with_reader("stateless-NAT", nattablew.get_reader());
    let dumper1 = PacketDumper::new("pre-ingress", true, Some(PacketDumper::vxlan_or_icmp()));
    let dumper2 = PacketDumper::new("post-egress", true, Some(PacketDumper::vxlan_or_icmp()));
    let stats_stage = Stats::new("stats", writer);
    let flow_lookup_nf = LookupNF::new(flow_table.clone());
    let flow_expirations_nf = ExpirationsNF::new(flow_table);

    // Build the pipeline for a router. The composition of the pipeline (in stages) is currently
    // hard-coded.

    let pipeline = DynPipeline::new()
        .add_stage(dumper1)
        .add_stage(stage_ingress)
        .add_stage(iprouter1)
        .add_stage(dst_vpcd_lookup)
        .add_stage(flow_lookup_nf)
        .add_stage(stateless_nat)
        .add_stage(iprouter2)
        .add_stage(stats_stage)
        .add_stage(stage_egress)
        .add_stage(dumper2)
        .add_stage(flow_expirations_nf);

    Ok(InternalSetup {
        router,
        pipeline,
        vpcmapw,
        nattablew,
        natallocatorw,
        vpcdtablesw,
        stats,
    })
}
