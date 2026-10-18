// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use crate::frame::{ChecksumState, FrameSpec, Template, Vxlan, parse};
use crate::ledger::{Ledger, Outcome};
use crate::space::{Addresses, FlowSpace, Order, Ports, SpaceSpec, Tuple};

/// A small space from arbitrary sizes, its first address and port arbitrary but in range.
fn space((src, dst, sport, dport, key): (u8, u8, u8, u8, Option<u64>)) -> FlowSpace {
    let count = |n: u8| u32::from(n % 7) + 1;
    FlowSpace::new(SpaceSpec {
        src: Addresses {
            first: Ipv4Addr::new(10, 0, 0, src),
            count: count(src),
        },
        dst: Addresses {
            first: Ipv4Addr::new(10, 1, 0, dst),
            count: count(dst),
        },
        sport: Ports {
            first: 1000 + u16::from(sport),
            count: u16::from(sport % 11) + 1,
        },
        dport: Ports {
            first: u16::MAX - u16::from(dport % 9),
            count: u16::from(dport % 9) + 1,
        },
        order: key.map_or(Order::Sequential, Order::Shuffled),
    })
    .unwrap()
}

/// Every flow number names a different flow, inside the space's ranges, in either order.
#[test]
fn flow_numbers_name_distinct_flows_within_the_space() {
    bolero::check!()
        .with_type::<(u8, u8, u8, u8, Option<u64>)>()
        .for_each(|&params| {
            let space = space(params);
            let spec = *space.spec();
            let flows: BTreeSet<Tuple> = (0..space.len()).map(|n| space.flow(n)).collect();
            assert_eq!(
                flows.len() as u64,
                space.len(),
                "two numbers named one flow"
            );
            for flow in flows {
                let offset = |addr: Ipv4Addr, first: Ipv4Addr| u32::from(addr) - u32::from(first);
                assert!(offset(flow.src, spec.src.first) < spec.src.count);
                assert!(offset(flow.dst, spec.dst.first) < spec.dst.count);
                assert!(flow.sport - spec.sport.first < spec.sport.count);
                assert!(flow.dport - spec.dport.first < spec.dport.count);
            }
        });
}

#[test]
fn ranges_past_the_end_are_refused() {
    let mut spec = *space((0, 0, 0, 0, None)).spec();
    spec.dport = Ports {
        first: u16::MAX,
        count: 2,
    };
    assert!(FlowSpace::new(spec).is_err());
    spec.dport.count = 0;
    assert!(FlowSpace::new(spec).is_err());
}

fn spec(vxlan: bool, payload_len: u16) -> FrameSpec {
    FrameSpec {
        src_mac: [2, 0, 0, 0, 0, 1],
        dst_mac: [2, 0, 0, 0, 0, 2],
        vxlan: vxlan.then_some(Vxlan {
            vni: 0x00ab_cdef,
            src_mac: [2, 0, 0, 0, 0, 3],
            dst_mac: [2, 0, 0, 0, 0, 4],
            src: Ipv4Addr::new(192, 0, 2, 1),
            dst: Ipv4Addr::new(192, 0, 2, 2),
        }),
        payload_len,
        ttl: 64,
    }
}

/// A stamped frame reads back as what was stamped, with correct checksums, however many times it
/// was stamped before: the incremental checksum update agrees with computing it afresh.
#[test]
fn stamped_frames_read_back_as_stamped() {
    bolero::check!()
        .with_type::<(bool, u8, u16, Vec<(u64, u64)>)>()
        .for_each(|(vxlan, payload, sport, stamps)| {
            let tuple = Tuple {
                src: Ipv4Addr::new(1, 1, 0, 1),
                dst: Ipv4Addr::new(3, 3, 3, 1),
                sport: *sport,
                dport: 80,
            };
            let spec = spec(*vxlan, u16::from(*payload));
            let mut template = Template::new(&spec, 7, 42, &tuple);
            for &(seq, tx_ns) in stamps.iter().chain([&(0, 0)]) {
                template.stamp(seq, tx_ns);
                let got = parse(template.bytes()).unwrap();
                assert_eq!(got.tuple, tuple);
                assert_eq!(got.ip_checksum, ChecksumState::Valid);
                assert_eq!(got.udp_checksum, ChecksumState::Valid);
                assert!(got.payload_intact);
                let signature = got.signature.unwrap();
                assert_eq!((signature.run, signature.flow), (7, 42));
                assert_eq!((signature.seq, signature.tx_ns), (seq, tx_ns));
                assert_eq!(got.tunnel.map(|t| t.vni), spec.vxlan.map(|v| v.vni));
            }
        });
}

/// The dataplane's parser reads the generator's frames as the generator means them: two
/// independent implementations agree on what is on the wire.
#[test]
fn the_dataplane_reads_generated_frames_the_same_way() {
    use net::buffer::TestBuffer;
    use net::headers::TryVxlan;
    use net::packet::Packet;

    for vxlan in [false, true] {
        let tuple = Tuple {
            src: Ipv4Addr::new(1, 1, 0, 1),
            dst: Ipv4Addr::new(3, 3, 3, 1),
            sport: 1234,
            dport: 80,
        };
        let spec = spec(vxlan, 64);
        let template = Template::new(&spec, 1, 0, &tuple);
        let mut packet = Packet::new(TestBuffer::from_raw_data(template.bytes())).unwrap();
        if vxlan {
            assert_eq!(
                packet.try_vxlan().map(|v| v.vni().as_u32()),
                Some(0x00ab_cdef)
            );
            assert!(matches!(packet.vxlan_decap(), Some(Ok(_))));
        }
        assert_eq!(packet.ip_source(), Some(IpAddr::V4(tuple.src)));
        assert_eq!(packet.ip_destination(), Some(IpAddr::V4(tuple.dst)));
        assert_eq!(
            packet.transport_src_port().map(u16::from),
            Some(tuple.sport)
        );
        assert_eq!(
            packet.transport_dst_port().map(u16::from),
            Some(tuple.dport)
        );
        packet.get_done();
    }
}

fn frame(run: u32, flow: u64, seq: u64, tuple: Tuple) -> Vec<u8> {
    let mut template = Template::new(&spec(true, 64), run, flow, &tuple);
    template.stamp(seq, 1000);
    template.bytes().to_vec()
}

fn tuple(sport: u16) -> Tuple {
    Tuple {
        src: Ipv4Addr::new(1, 1, 0, 1),
        dst: Ipv4Addr::new(3, 3, 3, 1),
        sport,
        dport: 80,
    }
}

/// A ledger counts what was lost, what came back late, what was not ours, and flows whose
/// returning addresses changed.
#[test]
fn the_ledger_accounts_for_every_packet() {
    let mut ledger = Ledger::new(9, 3);
    for flow in [0, 1, 2, 0, 1, 2] {
        ledger.sent(flow);
    }
    // Flow 0 comes back twice, out of order; flow 1 once, then as a different tuple; flow 2 never.
    assert!(matches!(
        ledger.receive(&frame(9, 0, 1, tuple(10)), 2000),
        Outcome::Ours(_)
    ));
    assert!(matches!(
        ledger.receive(&frame(9, 0, 0, tuple(10)), 2000),
        Outcome::Ours(_)
    ));
    assert!(matches!(
        ledger.receive(&frame(9, 1, 0, tuple(11)), 2000),
        Outcome::Ours(_)
    ));
    assert!(matches!(
        ledger.receive(&frame(9, 1, 1, tuple(99)), 2000),
        Outcome::Ours(_)
    ));
    // Another run's packet, a flow the stream does not have, and garbage.
    assert_eq!(
        ledger.receive(&frame(8, 0, 0, tuple(10)), 2000),
        Outcome::Foreign
    );
    assert_eq!(
        ledger.receive(&frame(9, 7, 0, tuple(10)), 2000),
        Outcome::Foreign
    );
    assert_eq!(ledger.receive(&[0; 20], 2000), Outcome::Foreign);

    assert_eq!(ledger.total_sent(), 6);
    assert_eq!(ledger.total_received(), 4);
    assert_eq!(ledger.lost(), 2);
    assert_eq!(ledger.flows_returned(), 2);
    let sample = ledger.sample("s", flowgen_report::Sample::new());
    let counter = |name: &str| sample.counters[&format!("generator.s.{name}")];
    assert_eq!(counter("late"), 1);
    assert_eq!(counter("unstable"), 1);
    assert_eq!(counter("foreign"), 2);
    assert_eq!(counter("unknown_flow"), 1);
    assert_eq!(counter("bad_udp_checksum"), 0);
    // Every latency was 1000 ns, which is below 1024.
    assert_eq!(counter("latency_ns.lt_1024"), 4);
    assert_eq!(
        ledger.evidence().len(),
        4,
        "the unstable flow and the three strays"
    );
}

/// A frame whose checksum or payload was damaged in transit is counted as such.
#[test]
fn damage_is_noticed() {
    let mut ledger = Ledger::new(1, 1);
    ledger.sent(0);
    let mut damaged = frame(1, 0, 0, tuple(10));
    let last = damaged.len() - 1;
    damaged[last] ^= 0xff;
    ledger.receive(&damaged, 0);
    let sample = ledger.sample("s", flowgen_report::Sample::new());
    assert_eq!(sample.counters["generator.s.bad_udp_checksum"], 1);
    assert_eq!(sample.counters["generator.s.corrupt"], 1);
}

/// A schedule sends every flow it names, each flow's packets numbered from zero without gaps,
/// exactly `window` distinct flows a round, and each flow in consecutive rounds only.
#[test]
fn a_schedule_sends_each_flow_a_gapless_run_of_packets() {
    use crate::schedule::Schedule;
    use std::collections::BTreeMap;

    bolero::check!()
        .with_type::<(u8, u8, u8)>()
        .for_each(|&(window, churn, rounds)| {
            let window = u64::from(window % 32) + 1;
            let churn = u64::from(churn) % (window + 1);
            let rounds = u64::from(rounds % 16);
            let schedule = Schedule {
                window,
                churn,
                rounds,
            }
            .validate()
            .unwrap();

            // Each flow's sequence numbers and the rounds they were sent in.
            let mut flows: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
            for k in 0..schedule.packets() {
                let slot = schedule.slot(k).unwrap();
                flows
                    .entry(slot.flow)
                    .or_default()
                    .push((slot.seq, k / window));
            }
            assert!(schedule.slot(schedule.packets()).is_none());
            assert_eq!(flows.len() as u64, schedule.flows());
            assert_eq!(
                flows.keys().copied().collect::<Vec<_>>(),
                (0..schedule.flows()).collect::<Vec<_>>()
            );
            for (flow, sent) in &flows {
                let first_round = sent[0].1;
                for (i, &(seq, round)) in sent.iter().enumerate() {
                    assert_eq!(seq, i as u64, "flow {flow} skipped or repeated a packet");
                    assert_eq!(round, first_round + i as u64, "flow {flow} sat a round out");
                }
            }
            for round in 0..rounds {
                let distinct: BTreeSet<u64> = (round * window..(round + 1) * window)
                    .map(|k| schedule.slot(k).unwrap().flow)
                    .collect();
                assert_eq!(distinct.len() as u64, window);
            }
        });
}

#[test]
fn churn_beyond_the_window_is_refused() {
    let schedule = crate::schedule::Schedule {
        window: 4,
        churn: 5,
        rounds: 2,
    };
    assert!(schedule.validate().is_err());
}
