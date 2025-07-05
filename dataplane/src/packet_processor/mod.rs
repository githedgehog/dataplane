// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod egress;
mod ingress;
mod ipforward;

#[allow(unused)]
use super::packet_processor::egress::Egress;
use super::packet_processor::ingress::Ingress;
use super::packet_processor::ipforward::IpForwarder;

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
) -> (DynPipeline<Buf>, PacketStatsReader) {
    let stage_ingress = Ingress::new("Ingress", iftr.clone());
    let stage_egress = Egress::new("Egress", iftr, atreader);
    let iprouter1 = IpForwarder::new("IP-Forward-1", fibtr.clone());
    let iprouter2 = IpForwarder::new("IP-Forward-2", fibtr);
    let dumper1 = PacketDumper::new("pre-ingress", true, Some(PacketDumper::vxlan_or_icmp()));
    let dumper2 = PacketDumper::new("post-egress", true, Some(PacketDumper::vxlan_or_icmp()));
    let stats = PipelineStats::new("stats", vpcmap);
    let stats_reader = stats.get_reader();

    let pipeline = DynPipeline::new()
        .add_stage(dumper1)
        .add_stage(stage_ingress)
        .add_stage(iprouter1)
        .add_stage(iprouter2)
        .add_stage(stage_egress)
        .add_stage(dumper2)
        .add_stage(stats);
    (pipeline, stats_reader)
}

/// Start a router and provide the associated pipeline
#[allow(unused)]
pub fn start_router<Buf: PacketBufferMut>(
    params: RouterParams,
) -> Result<
    (
        Router,
        DynPipeline<Buf>,
        VpcMapWriter<VpcMapName>,
        PacketStatsReader,
    ),
    RouterError,
> {
    let router = Router::new(params)?;
    let vpcmapw = VpcMapWriter::<VpcMapName>::new();
    let (pipeline, statsr) = setup_routing_pipeline(
        router.get_iftabler(),
        router.get_fibtr(),
        router.get_atabler(),
        vpcmapw.get_reader(),
    );
    Ok((router, pipeline, vpcmapw, statsr))
}
