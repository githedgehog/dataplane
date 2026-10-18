// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Floods against control-plane probes.
//!
//! Each case floods the gateway while BGP and BFD probes from its neighbour run alongside, every
//! stream in wire mode: what a full receive ring refuses is dropped and counted, as a NIC would.
//!
//! On a ring cable the probes share the data queues with the flood -- a ring port steers nothing,
//! so control traffic is taken off the data path in software -- and a full queue drops probes as
//! readily as flood. What this harness can hold the dataplane to is what happens after the port:
//! a probe the port took is never lost, however the pipeline and the punt path are loaded, and
//! once the flood stops every probe gets through again. Whether probes are dropped at the port is
//! for hardware, where they have a queue of their own; here it is recorded, not judged.

use std::net::Ipv4Addr;

use config::external::overlay::vpcpeering::contract::LOCAL_VNI;
use std::time::Duration;

use flowgen::frame::{FrameSpec, Transport, Vxlan as GeneratedVxlan, tcp};
use flowgen::schedule::Schedule;
use flowgen::sender::{Clock, Stream, WhenFull};
use flowgen::space::{Addresses, FlowSpace, Order, Ports, SpaceSpec};
use flowgen_report::{Bound, Sample};

use super::harness::{
    Loopback, Side, TestCase, Traffic, await_software_classes, drive, fixture_gateway, over_cable,
};
use super::probes::{BFD, BGP, probes};
use crate::packet_processor::fixture::{GATEWAY_MAC, LOCAL_VTEP, PEER_MAC, PEER_VTEP};

/// Packets each probe session sends during a flood.
const PROBES_PER_SESSION: u64 = 500;

/// The probes' rate, per stream.
const PROBE_RATE: u64 = 4_000;

/// Flows each flood starts a round; every flood flow is new.
const FLOOD_WINDOW: u64 = 1_000;

/// Rounds each flood runs.
const FLOOD_ROUNDS: u64 = 60;

/// BGP and BFD probes from the neighbour, in wire mode.
fn victims() -> [(Side, Stream); 2] {
    let neighbour = (PEER_VTEP.parse().unwrap(), PEER_MAC.0);
    let gateway = (LOCAL_VTEP.parse().unwrap(), GATEWAY_MAC.0);
    let mut bfd = probes("bfd", Transport::Udp, neighbour, gateway, 49152, BFD);
    let mut bgp = probes(
        "bgp",
        Transport::Tcp {
            flags: tcp::ACK | tcp::PSH,
        },
        neighbour,
        gateway,
        40000,
        BGP,
    );
    for probe in [&mut bfd, &mut bgp] {
        probe.schedule = Schedule::steady(probe.schedule.window, PROBES_PER_SESSION);
        probe.rate_pps = Some(PROBE_RATE);
        probe.when_full = WhenFull::Drop;
    }
    [(Side::Far, bfd), (Side::Far, bgp)]
}

/// A flood of new flows, unpaced, in wire mode: from `sources` to `dst` (one address each of
/// `dsts`), port `dport`, in `transport`, tunnelled if `vxlan`.
fn flood(
    name: &str,
    sources: Addresses,
    dst: Addresses,
    dport: u16,
    transport: Transport,
    vxlan: Option<GeneratedVxlan>,
) -> Stream {
    let space = FlowSpace::new(SpaceSpec {
        src: sources,
        dst,
        sport: Ports {
            first: 1024,
            count: 64,
        },
        dport: Ports {
            first: dport,
            count: 1,
        },
        order: Order::Shuffled(0xf100d),
    })
    .unwrap();
    Stream {
        name: name.to_string(),
        space,
        schedule: Schedule {
            window: FLOOD_WINDOW,
            churn: FLOOD_WINDOW,
            rounds: FLOOD_ROUNDS,
        },
        frame: FrameSpec {
            src_mac: if vxlan.is_some() {
                [0x02, 0, 0, 0, 1, 1]
            } else {
                PEER_MAC.0
            },
            dst_mac: GATEWAY_MAC.0,
            vxlan,
            transport,
            payload_len: 32,
            ttl: 64,
        },
        rate_pps: None,
        when_full: WhenFull::Drop,
    }
}

/// A flood of TCP SYNs from the local VPC through the gateway's NAT to the remote one, every
/// SYN a new flow: the flood that saturates the new-flow path.
pub(super) fn syn_flood() -> Stream {
    flood(
        "syn",
        addresses("1.1.0.1", 1000),
        addresses("3.3.3.1", 4),
        443,
        Transport::Tcp { flags: tcp::SYN },
        Some(GeneratedVxlan {
            vni: LOCAL_VNI,
            src_mac: PEER_MAC.0,
            dst_mac: GATEWAY_MAC.0,
            src: PEER_VTEP.parse().unwrap(),
            dst: LOCAL_VTEP.parse().unwrap(),
        }),
    )
}

fn addresses(first: &str, count: u32) -> Addresses {
    Addresses {
        first: first.parse::<Ipv4Addr>().unwrap(),
        count,
    }
}

/// Check what a probe stream can be held to on a ring cable: every probe the port took reached
/// the kernel.
fn check_probes(case: &mut TestCase<'_>, totals: &Sample, name: &str) {
    let path = format!("generator.{name}.lost");
    case.expect_counter(
        format!("{name}.none-lost-after-the-port"),
        path.clone(),
        Bound::exactly(0),
        totals.counters.get(&path).copied(),
        vec![],
    )
    .expect("the report should take the check");
}

/// Floods of unrouted traffic, of traffic to the gateway's own address, and of TCP SYNs through
/// the gateway's NAT, each against BGP and BFD probes from its neighbour: a probe the port took is
/// never lost, and once each flood stops every probe gets through, none dropped anywhere.
#[test]
fn probes_the_port_takes_survive_floods() {
    over_cable(
        "probes_the_port_takes_survive_floods",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            await_software_classes(lb.far, lb.kernel);
            let floods = [
                flood(
                    "unrouted",
                    addresses("10.0.0.0", 1 << 16),
                    addresses("9.9.9.0", 256),
                    5000,
                    Transport::Udp,
                    None,
                ),
                flood(
                    "own-address",
                    addresses("10.1.0.0", 1 << 16),
                    addresses(LOCAL_VTEP, 1),
                    5000,
                    Transport::Udp,
                    None,
                ),
                syn_flood(),
            ];
            let mut run = 1;
            for aggressor in floods {
                let name = aggressor.name.clone();
                let mut case = lb
                    .report
                    .case(
                        format!("{name}-flood"),
                        serde_json::to_value(aggressor.schedule).unwrap(),
                    )
                    .expect("the report should take the case");
                let mut streams = victims().to_vec();
                streams.push((Side::Far, aggressor));
                let (ledgers, _, _) = drive(
                    lb.far,
                    lb.kernel,
                    lb.probe,
                    &mut case,
                    Traffic {
                        streams: &streams,
                        first_run: run,
                        agents: &mut [],
                        hold: Duration::ZERO,
                        clock: Clock::start(),
                    },
                );
                run += 3;
                let totals = ledgers.sample(Sample::new());
                for victim in ["bfd", "bgp"] {
                    check_probes(&mut case, &totals, victim);
                }
                case.finish()
                    .expect("the report should take the case's end");

                recover(lb, &name, run);
                run += 2;
            }
        },
    );
}

/// Once a flood named `name` is over, the probes get through, none dropped anywhere: sent as runs
/// `run` and `run + 1`.
fn recover(lb: &mut Loopback<'_, '_, '_, '_>, name: &str, run: u32) {
    let mut case = lb
        .report
        .case(format!("after-{name}-flood"), serde_json::json!({}))
        .expect("the report should take the case");
    let (ledgers, _, _) = drive(
        lb.far,
        lb.kernel,
        lb.probe,
        &mut case,
        Traffic {
            streams: &victims(),
            first_run: run,
            agents: &mut [],
            hold: Duration::ZERO,
            clock: Clock::start(),
        },
    );
    let totals = ledgers.sample(Sample::new());
    for victim in ["bfd", "bgp"] {
        check_probes(&mut case, &totals, victim);
        let path = format!("generator.{victim}.dropped_at_port");
        case.expect_counter(
            format!("{victim}.none-dropped-at-the-port"),
            path.clone(),
            Bound::exactly(0),
            totals.counters.get(&path).copied(),
            vec![],
        )
        .expect("the report should take the check");
    }
    case.finish()
        .expect("the report should take the case's end");
}
