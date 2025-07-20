// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod egress;
mod ingress;
mod ipforward;

#[allow(unused)]
use super::packet_processor::egress::Egress;
use super::packet_processor::ingress::Ingress;
use super::packet_processor::ipforward::IpForwarder;

use pkt_meta::dst_vni_lookup::{DstVniLookup, VniTablesReader, VniTablesWriter};

use nat::StatelessNat;
use nat::stateless::{NatTablesReader, NatTablesWriter};

use net::buffer::PacketBufferMut;
use pipeline::DynPipeline;
use pipeline::sample_nfs::PacketDumper;

use routing::atable::atablerw::AtableReader;
use routing::fib::fibtable::FibTableReader;
use routing::interfaces::iftablerw::IfTableReader;
use routing::{Router, RouterError, RouterParams};

use vpcmap::map::VpcMapReader;
use vpcmap::map::VpcMapWriter;

use stats::{PacketStatsReader, PipelineStats, VpcMapName};

/// Build the pipeline for a router. The composition of the pipeline (in stages)
/// is currently hard-coded.
fn setup_routing_pipeline<Buf: PacketBufferMut>(
    iftr: IfTableReader,
    fibtr: FibTableReader,
    atreader: AtableReader,
    vpcmap: VpcMapReader<VpcMapName>,
    nattablesr: NatTablesReader,
    vnitablesr: VniTablesReader,
) -> (DynPipeline<Buf>, PacketStatsReader) {
    let stage_ingress = Ingress::new("Ingress", iftr.clone());
    let stage_egress = Egress::new("Egress", iftr, atreader);
    let dst_vni_lookup = DstVniLookup::new("dst-vni-lookup", vnitablesr);
    let iprouter1 = IpForwarder::new("IP-Forward-1", fibtr.clone());
    let iprouter2 = IpForwarder::new("IP-Forward-2", fibtr);
    let stateless_nat = StatelessNat::with_reader("stateless-NAT", nattablesr);
    let dumper1 = PacketDumper::new("pre-ingress", true, Some(PacketDumper::vxlan_or_icmp()));
    let dumper2 = PacketDumper::new("post-egress", true, Some(PacketDumper::vxlan_or_icmp()));
    let stats = PipelineStats::new("stats", vpcmap);
    let stats_reader = stats.get_reader();

    let pipeline = DynPipeline::new()
        .add_stage(dumper1)
        .add_stage(stage_ingress)
        .add_stage(iprouter1)
        .add_stage(dst_vni_lookup)
        .add_stage(stateless_nat)
        .add_stage(iprouter2)
        .add_stage(stage_egress)
        .add_stage(dumper2)
        .add_stage(stats);
    (pipeline, stats_reader)
}

pub(crate) struct InternalSetup<Buf>
where
    Buf: PacketBufferMut,
{
    pub router: Router,
    pub pipeline: DynPipeline<Buf>,
    pub vpcmapw: VpcMapWriter<VpcMapName>,
    pub statsr: PacketStatsReader,
    pub nattable: NatTablesWriter,
    pub vnitablesw: VniTablesWriter,
}

/// Start a router and provide the associated pipeline
pub(crate) fn start_router<Buf: PacketBufferMut>(
    params: RouterParams,
) -> Result<InternalSetup<Buf>, RouterError> {
    let nattable = NatTablesWriter::new();
    let vnitablesw = VniTablesWriter::new();
    let router = Router::new(params)?;
    let vpcmapw = VpcMapWriter::<VpcMapName>::new();
    let (pipeline, statsr) = setup_routing_pipeline(
        router.get_iftabler(),
        router.get_fibtr(),
        router.get_atabler(),
        vpcmapw.get_reader(),
        nattable.get_reader(),
        vnitablesw.get_reader(),
    );
    Ok(InternalSetup {
        router,
        pipeline,
        vpcmapw,
        statsr,
        nattable,
        vnitablesw,
    })
}
