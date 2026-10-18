// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control-plane probes: BGP- and BFD-shaped packets between a neighbour and the gateway, signed so
//! that each one's loss and latency through the dataplane's control path is measured.
//!
//! They are not sessions. Nothing answers them: what is measured is how the dataplane carries
//! control traffic -- recognised, punted on the control channel, injected back out -- and a
//! session's retransmissions would hide exactly the losses a probe counts.

use std::net::Ipv4Addr;

use std::time::Duration;

use flowgen::frame::{FrameSpec, Mac as GeneratedMac, Transport, tcp};
use flowgen::schedule::Schedule;
use flowgen::sender::{Clock, Returns, Stream, WhenFull};
use flowgen::space::{Addresses, FlowSpace, Order, Ports, SpaceSpec};
use flowgen_report::{Bound, Sample};

use super::harness::{
    Loopback, Side, Traffic, await_software_classes, check_all_back, drive, fixture_gateway,
    over_cable,
};
use crate::packet_processor::fixture::{GATEWAY_MAC, LOCAL_VTEP, PEER_MAC, PEER_VTEP};

/// The UDP port BFD control packets go to, single hop (RFC 5881).
pub(super) const BFD: u16 = 3784;

/// The TCP port BGP listens on (RFC 4271).
pub(super) const BGP: u16 = 179;

/// Probe packets per session.
const PER_SESSION: u64 = 250;

/// Concurrent sessions probed.
pub(super) const SESSIONS: u16 = 4;

/// A probe stream: `SESSIONS` sessions from `src` to `dst`, distinguished by source port from
/// `sport`, to `dport`, carried in `transport`, paced as a busy control plane might be.
pub(super) fn probes(
    name: &str,
    transport: Transport,
    (src, src_mac): (Ipv4Addr, GeneratedMac),
    (dst, dst_mac): (Ipv4Addr, GeneratedMac),
    sport: u16,
    dport: u16,
) -> Stream {
    let space = FlowSpace::new(SpaceSpec {
        src: Addresses {
            first: src,
            count: 1,
        },
        dst: Addresses {
            first: dst,
            count: 1,
        },
        sport: Ports {
            first: sport,
            count: SESSIONS,
        },
        dport: Ports {
            first: dport,
            count: 1,
        },
        order: Order::Sequential,
    })
    .unwrap();
    Stream {
        name: name.to_string(),
        space,
        schedule: Schedule::steady(u64::from(SESSIONS), PER_SESSION),
        frame: FrameSpec {
            src_mac,
            dst_mac,
            vxlan: None,
            transport,
            payload_len: 64,
            ttl: 255,
        },
        rate_pps: Some(20_000),
        when_full: WhenFull::Retry,
        returns: Returns::Everything,
    }
}

/// BGP- and BFD-shaped probes cross the dataplane's control path both ways, none lost: from the
/// neighbour they reach the kernel on the control channel and none on the data path's, and BFD
/// from the kernel reaches the neighbour.
#[test]
fn control_probes_cross_the_control_path_both_ways() {
    over_cable(
        "control_probes_cross_the_control_path_both_ways",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            await_software_classes(lb.far, lb.kernel);
            let neighbour = (PEER_VTEP.parse().unwrap(), PEER_MAC.0);
            let gateway = (LOCAL_VTEP.parse().unwrap(), GATEWAY_MAC.0);
            let cases = [
                (
                    Side::Far,
                    probes("bfd-in", Transport::Udp, neighbour, gateway, 49152, BFD),
                ),
                (
                    Side::Far,
                    probes(
                        "bgp-in",
                        Transport::Tcp {
                            flags: tcp::ACK | tcp::PSH,
                        },
                        neighbour,
                        gateway,
                        40000,
                        BGP,
                    ),
                ),
                (
                    Side::Kernel,
                    probes("bfd-out", Transport::Udp, gateway, neighbour, 49152, BFD),
                ),
            ];
            for (run, (side, stream)) in (1..).zip(cases) {
                let mut case = lb
                    .report
                    .case(
                        stream.name.clone(),
                        serde_json::json!({ "side": format!("{side:?}") }),
                    )
                    .expect("the report should take the case");
                let (ledgers, ending, punted) = drive(
                    lb.far,
                    lb.kernel,
                    lb.probe,
                    &mut case,
                    Traffic {
                        streams: &[(side, stream.clone())],
                        first_run: run,
                        agents: &mut [],
                        hold: Duration::ZERO,
                        clock: Clock::start(),
                    },
                );
                check_all_back(&mut case, &ledgers, ending);
                let lost_path = format!("generator.{}.lost", stream.name);
                let lost = ledgers
                    .sample(Sample::new())
                    .counters
                    .get(&lost_path)
                    .copied();
                let sent = u64::from(SESSIONS) * PER_SESSION;
                let (control, data) = match side {
                    // Probes into the port are punted, all of them on the control channel.
                    Side::Far => (sent, 0),
                    // Probes from the kernel leave by the port: nothing is punted.
                    Side::Kernel => (0, 0),
                };
                for (id, path, bound, observed) in [
                    ("none-lost", lost_path.as_str(), Bound::exactly(0), lost),
                    (
                        "control-channel",
                        "kernel.control",
                        Bound::exactly(control),
                        Some(punted.control),
                    ),
                    (
                        "data-channel",
                        "kernel.punted",
                        Bound::exactly(data),
                        Some(punted.data),
                    ),
                ] {
                    case.expect_counter(
                        id,
                        path,
                        bound,
                        observed,
                        ledgers.stray_evidence().to_vec(),
                    )
                    .expect("the report should take the check");
                }
                case.finish()
                    .expect("the report should take the case's end");
            }
        },
    );
}
