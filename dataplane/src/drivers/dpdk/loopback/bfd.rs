// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A BFD session across the dataplane: flowgen's BFD peer on the far end of the cable as the
//! neighbour, and another on the kernel's side of the port as the gateway's own BFD would be.
//!
//! Both ends are the same implementation, so this tests the dataplane's control path, not BFD
//! interoperability; that is for vlab, against the gateway's real BFD.

use std::time::Duration;

use flowgen::bfd::{CONTROL_PORT, Config, Peer, Session, State};
use flowgen::drive::Agent;
use flowgen::frame::Endpoints;
use flowgen::sender::Clock;
use flowgen_report::Bound;

use super::floods::syn_flood;
use super::harness::{
    FAR, KERNEL, Loopback, Side, TestCase, Traffic, await_software_classes, drive, fixture_gateway,
    over_cable,
};
use crate::packet_processor::fixture::{GATEWAY_MAC, LOCAL_VTEP, PEER_MAC, PEER_VTEP};

/// A common fast BFD configuration: 50 ms, three missed packets to fail.
fn config(discriminator: u32) -> Config {
    Config {
        discriminator,
        desired_min_tx_us: 50_000,
        required_min_rx_us: 50_000,
        detect_mult: 3,
    }
}

/// The neighbour's peer, on the far end of the cable, and the gateway's, on the kernel's side.
fn peers(clock: &Clock) -> (Peer, Peer) {
    let neighbour = Peer::new(
        "neighbour",
        FAR,
        Endpoints {
            src_mac: PEER_MAC.0,
            dst_mac: GATEWAY_MAC.0,
            src: (PEER_VTEP.parse().unwrap(), 49152),
            dst: (LOCAL_VTEP.parse().unwrap(), CONTROL_PORT),
        },
        Session::new(config(0x1111), clock.now_ns()),
    );
    let gateway = Peer::new(
        "gateway",
        KERNEL,
        Endpoints {
            src_mac: GATEWAY_MAC.0,
            dst_mac: PEER_MAC.0,
            src: (LOCAL_VTEP.parse().unwrap(), 49153),
            dst: (PEER_VTEP.parse().unwrap(), CONTROL_PORT),
        },
        Session::new(config(0x2222), clock.now_ns()),
    );
    (neighbour, gateway)
}

/// Each peer's flaps so far.
fn flaps(peers: [&Peer; 2]) -> [u64; 2] {
    peers.map(|peer| peer.session().log(u64::MAX).flaps)
}

/// Check each peer is Up and did not flap during the case, given its flaps when the case began.
fn check_steady(case: &mut TestCase<'_>, peers: [&Peer; 2], before: [u64; 2]) {
    for (peer, (name, before)) in peers
        .into_iter()
        .zip([("neighbour", before[0]), ("gateway", before[1])])
    {
        case.expect(
            format!("{name}.up"),
            "the session is Up",
            peer.session().state() == State::Up,
            vec![],
        )
        .expect("the report should take the check");
        let path = format!("bfd.{name}.flaps");
        case.expect_counter(
            format!("{name}.no-flaps"),
            path,
            Bound::exactly(0),
            Some(peer.session().log(u64::MAX).flaps - before),
            vec![],
        )
        .expect("the report should take the check");
    }
}

/// A BFD session through the dataplane comes up, stays up, and is up again after a SYN flood.
/// Whether it survives the flood itself is recorded, not judged: on a ring port BFD shares the
/// data queues with the flood, which hardware does not.
#[test]
fn a_bfd_session_across_the_dataplane_holds() {
    over_cable(
        "a_bfd_session_across_the_dataplane_holds",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            await_software_classes(lb.far, lb.kernel);
            let clock = Clock::start();
            let (mut neighbour, mut gateway) = peers(&clock);
            for (n, (name, flood)) in [
                ("steady", false),
                ("syn-flood", true),
                ("after-flood", false),
            ]
            .into_iter()
            .enumerate()
            {
                let mut case = lb
                    .report
                    .case(name, serde_json::json!({ "flood": flood }))
                    .expect("the report should take the case");
                let before = flaps([&neighbour, &gateway]);
                let streams = if flood {
                    vec![(Side::Far, syn_flood())]
                } else {
                    vec![]
                };
                let mut agents: [&mut dyn Agent; 2] = [&mut neighbour, &mut gateway];
                drive(
                    lb.far,
                    lb.kernel,
                    lb.probe,
                    &mut case,
                    Traffic {
                        streams: &streams,
                        first_run: u32::try_from(n).unwrap() + 1,
                        agents: &mut agents,
                        hold: Duration::from_secs(2),
                        clock,
                    },
                );
                if !flood {
                    check_steady(&mut case, [&neighbour, &gateway], before);
                }
                case.finish()
                    .expect("the report should take the case's end");
            }
        },
    );
}
