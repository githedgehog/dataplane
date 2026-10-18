// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Real TCP through the gateway: a smoltcp client in the local VPC and an echo server in the remote
//! one, both behind the peer VTEP on the far end of the cable. Every connection crosses the gateway
//! twice per round trip: masqueraded on the way out, translated back on the way in.

use std::net::Ipv4Addr;

use config::external::overlay::vpcpeering::contract::{LOCAL_VNI, REMOTE_VNI};
use flowgen::drive::{Agent, Ending};
use flowgen::frame::Vxlan;
use flowgen::sender::Clock;
use flowgen::tcp::{Addressing, Encap, Host, Role};
use flowgen_report::{Bound, Evidence, Sample};

use super::floods::syn_flood;
use super::harness::{
    FAR, Loopback, Side, TestCase, Traffic, await_software_classes, drive, expect, fixture_gateway,
    over_cable,
};
use crate::packet_processor::fixture::{GATEWAY_MAC, LOCAL_VTEP, PEER_MAC, PEER_VTEP};

/// Connections the client opens.
const CONNECTIONS: usize = 16;

/// Bytes each connection sends and expects echoed.
const BYTES: usize = 64 * 1024;

/// A VTEP-side tunnel into the gateway, in VPC `vni`.
fn tunnel(vni: u32) -> Vxlan {
    Vxlan {
        vni,
        src_mac: PEER_MAC.0,
        dst_mac: GATEWAY_MAC.0,
        src: PEER_VTEP.parse().unwrap(),
        dst: LOCAL_VTEP.parse().unwrap(),
    }
}

/// An echo server in the remote VPC and a client in the local one opening connections to it from
/// ports counting up from `first_port`.
fn hosts(clock: &Clock, first_port: u16) -> (Host, Host) {
    let server_address = Ipv4Addr::new(3, 3, 3, 1);
    let server = Host::new(
        "server",
        FAR,
        Addressing {
            address: server_address,
            prefix: 24,
            gateway: Ipv4Addr::new(3, 3, 3, 254),
        },
        Encap::Vxlan {
            tunnel: tunnel(REMOTE_VNI),
            mac: [0x02, 0, 0, 0, 3, 1],
            next_hop: GATEWAY_MAC.0,
        },
        Role::Echo {
            port: 80,
            connections: CONNECTIONS,
        },
        clock.now_ns(),
    );
    let client = Host::new(
        "client",
        FAR,
        Addressing {
            address: Ipv4Addr::new(1, 1, 0, 1),
            prefix: 16,
            gateway: Ipv4Addr::new(1, 1, 255, 254),
        },
        Encap::Vxlan {
            tunnel: tunnel(LOCAL_VNI),
            mac: [0x02, 0, 0, 0, 1, 1],
            next_hop: GATEWAY_MAC.0,
        },
        Role::Client {
            server: (server_address, 80),
            connections: CONNECTIONS,
            first_port,
            bytes: BYTES,
        },
        clock.now_ns(),
    );
    (client, server)
}

/// Sixteen TCP connections from the local VPC to an echo server in the remote one, through the
/// gateway's NAT, alone and then while a SYN flood saturates the gateway's new-flow path: every
/// connection is established, every byte comes back unmangled, and every connection is closed
/// cleanly by both ends. Under the flood the port drops what it has no room for, and TCP has to
/// recover it.
#[test]
fn tcp_connections_cross_the_gateway_intact() {
    over_cable(
        "tcp_connections_cross_the_gateway_intact",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            await_software_classes(lb.far, lb.kernel);
            let clock = Clock::start();
            for (n, (name, flood)) in [("echo", false), ("echo-under-syn-flood", true)]
                .into_iter()
                .enumerate()
            {
                let first_port = 50000 + 1000 * u16::try_from(n).unwrap();
                let (mut client, mut server) = hosts(&clock, first_port);
                let streams = if flood {
                    vec![(Side::Far, syn_flood())]
                } else {
                    vec![]
                };
                let mut case = lb
                    .report
                    .case(
                        name,
                        serde_json::json!({
                            "connections": CONNECTIONS,
                            "bytes": BYTES,
                            "flood": flood,
                        }),
                    )
                    .expect("the report should take the case");
                let ending = {
                    let mut agents: [&mut dyn Agent; 2] = [&mut client, &mut server];
                    let (_, ending, _) = drive(
                        lb.far,
                        lb.kernel,
                        lb.probe,
                        &mut case,
                        Traffic {
                            streams: &streams,
                            first_run: u32::try_from(n).unwrap() + 1,
                            agents: &mut agents,
                            hold: std::time::Duration::ZERO,
                            clock,
                        },
                    );
                    ending
                };
                check_connections(&mut case, &client, &clock, ending, flood);
                case.finish()
                    .expect("the report should take the case's end");
            }
        },
    );
}

/// Check every one of the client's connections came through whole and closed cleanly.
fn check_connections(
    case: &mut TestCase<'_>,
    client: &Host,
    clock: &Clock,
    ending: Ending,
    flood: bool,
) {
    // With a flood alongside, the run ends when the flood's last packets are in, not when the
    // connections are; what matters is that they finished.
    let finished = if flood {
        client.finished()
    } else {
        ending == Ending::AllBack
    };
    expect(
        case,
        "finished",
        "every connection finishes before the time allowed runs out",
        finished,
        || vec![Evidence::text(format!("{ending:?}"))],
    );
    let totals = client.sample(clock.now_ns(), Sample::new()).counters;
    let total = (CONNECTIONS * BYTES) as u64;
    for (id, what, bound) in [
        (
            "all-established",
            "established",
            Bound::exactly(CONNECTIONS as u64),
        ),
        ("all-closed", "closed", Bound::exactly(CONNECTIONS as u64)),
        ("none-reset", "reset", Bound::exactly(0)),
        ("every-byte-back", "bytes_received", Bound::exactly(total)),
        ("none-mangled", "bytes_mismatched", Bound::exactly(0)),
    ] {
        let path = format!("tcp.client.{what}");
        let observed = totals.get(&path).copied();
        case.expect_counter(id, path, bound, observed, vec![])
            .expect("the report should take the check");
    }
}
