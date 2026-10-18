// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A BGP session across the dataplane's control path: flowgen's BGP speaker over smoltcp on the far
//! end of the cable as the neighbour, connecting to another on the kernel's side of the port, where
//! the gateway's own BGP would listen.
//!
//! Both ends are the same implementation, so this tests the dataplane's control path, not BGP
//! interoperability; that is for vlab, against the gateway's FRR.

use std::net::Ipv4Addr;
use std::time::Duration;

use flowgen::bgp::{self, Config};
use flowgen::drive::Agent;
use flowgen::sender::Clock;
use flowgen::tcp::{Addressing, Encap, Host, Role};
use flowgen_report::{Bound, Sample};

use super::floods::syn_flood;
use super::harness::{
    FAR, KERNEL, Loopback, Side, TestCase, Traffic, await_software_classes, drive, fixture_gateway,
    over_cable,
};
use crate::packet_processor::fixture::{GATEWAY_MAC, LOCAL_VTEP, PEER_MAC, PEER_VTEP};

/// The shortest Hold Time BGP allows, so that keepalives come every second.
const HOLD_S: u16 = 3;

/// The neighbour, connecting from the far end, and the gateway, listening on the kernel's side.
fn speakers(clock: &Clock) -> (Host, Host) {
    let neighbour: Ipv4Addr = PEER_VTEP.parse().unwrap();
    let gateway: Ipv4Addr = LOCAL_VTEP.parse().unwrap();
    let speaker = |name, wire, address: Ipv4Addr, mac, next_hop, asn, peer_asn, peer| {
        let [a, b, c, _] = address.octets();
        Host::new(
            name,
            wire,
            Addressing {
                address,
                prefix: 24,
                gateway: Ipv4Addr::new(a, b, c, 254),
            },
            Encap::Ethernet { mac, next_hop },
            Role::Bgp {
                config: Config {
                    asn,
                    router_id: address,
                    hold_time_s: HOLD_S,
                    peer_asn: Some(peer_asn),
                },
                peer,
                first_port: 40000,
            },
            clock.now_ns(),
        )
    };
    (
        speaker(
            "neighbour",
            FAR,
            neighbour,
            PEER_MAC.0,
            GATEWAY_MAC.0,
            65001,
            65000,
            Some(gateway),
        ),
        speaker(
            "gateway",
            KERNEL,
            gateway,
            GATEWAY_MAC.0,
            PEER_MAC.0,
            65000,
            65001,
            None,
        ),
    )
}

/// A speaker's counter `what`, as of `now`.
fn counter(host: &Host, name: &str, what: &str, now: u64) -> u64 {
    host.sample(now, Sample::new()).counters[&format!("bgp.{name}.{what}")]
}

/// Check both speakers are Established and neither dropped out or let its Hold Timer expire
/// during the case, given their drops when it began.
fn check_steady(case: &mut TestCase<'_>, hosts: [(&Host, &str); 2], before: [u64; 2], now: u64) {
    for ((host, name), before) in hosts.into_iter().zip(before) {
        let state = host.sample(now, Sample::new()).gauges[&format!("bgp.{name}.state")];
        case.expect(
            format!("{name}.established"),
            "the session is Established",
            state == bgp::State::Established as u64,
            vec![],
        )
        .expect("the report should take the check");
        case.expect_counter(
            format!("{name}.no-drops"),
            format!("bgp.{name}.drops"),
            Bound::exactly(0),
            Some(counter(host, name, "drops", now) - before),
            vec![],
        )
        .expect("the report should take the check");
    }
}

/// A BGP session through the dataplane's control path reaches Established and holds, runs through
/// a SYN flood, and holds after it. During the flood it is recorded, not judged: on a ring port BGP
/// shares the data queues with the flood.
#[test]
fn a_bgp_session_across_the_dataplane_holds() {
    over_cable(
        "a_bgp_session_across_the_dataplane_holds",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            await_software_classes(lb.far, lb.kernel);
            let clock = Clock::start();
            let (mut neighbour, mut gateway) = speakers(&clock);
            for (n, (name, flood, hold)) in [
                ("steady", false, Duration::from_secs(5)),
                ("syn-flood", true, Duration::from_secs(3)),
                ("after-flood", false, Duration::from_secs(4)),
            ]
            .into_iter()
            .enumerate()
            {
                let mut case = lb
                    .report
                    .case(
                        name,
                        serde_json::json!({ "flood": flood, "hold_time_s": HOLD_S }),
                    )
                    .expect("the report should take the case");
                let now = clock.now_ns();
                let before = [
                    counter(&neighbour, "neighbour", "drops", now),
                    counter(&gateway, "gateway", "drops", now),
                ];
                let streams = if flood {
                    vec![(Side::Far, syn_flood())]
                } else {
                    vec![]
                };
                {
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
                            hold,
                            clock,
                        },
                    );
                }
                if !flood {
                    check_steady(
                        &mut case,
                        [(&neighbour, "neighbour"), (&gateway, "gateway")],
                        before,
                        clock.now_ns(),
                    );
                }
                case.finish()
                    .expect("the report should take the case's end");
            }
        },
    );
}
