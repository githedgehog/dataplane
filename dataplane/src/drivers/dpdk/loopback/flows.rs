// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Traffic through the fixture gateway's production pipeline: one tunnelled frame, then streams of
//! many flows from the flowgen generator, steady and churning.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use config::external::overlay::vpcpeering::contract::{LOCAL_VNI, REMOTE_VNI};
use flowgen::frame::{FrameSpec, Vxlan as GeneratedVxlan};
use flowgen::ledger::{Ledger, Ledgers};
use flowgen::port::{Clock, Ending, Patience, Queues, Sender, Stream, run as generate};
use flowgen::schedule::Schedule;
use flowgen::space::{Addresses, FlowSpace, Order, Ports, SpaceSpec};
use flowgen_report::{Bound, Evidence, Sample};
use net::buffer::TestBuffer;
use net::headers::{TryEth, TryVxlan};
use net::packet::Packet;
use net::vxlan::Vxlan;

use super::harness::{
    FarEnd, Loopback, PATIENCE, Probe, TestCase, WORKERS, check_counters, expect, fixture_gateway,
    frame_evidence, over_cable,
};
use crate::drivers::cpbridge::DetachedPort;
use crate::packet_processor::fixture::{
    GATEWAY_MAC, LOCAL_VTEP, PEER_MAC, PEER_VTEP, inner, inside, tunnelled, vni,
};

/// A tunnelled frame crosses the cable, the production pipeline and the cable again: decapsulated,
/// masqueraded and sent back out to the peer VTEP in the remote VPC.
#[test]
fn a_tunnelled_frame_makes_a_round_trip_through_the_pipeline() {
    over_cable(
        "a_tunnelled_frame_makes_a_round_trip_through_the_pipeline",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            let mut case = lb
                .report
                .case("round-trip", serde_json::json!({}))
                .expect("the report should take the case");
            round_trip(lb.far, lb.kernel, &mut case);
            check_counters(
                &mut case,
                lb.probe,
                &[
                    ("one-frame-in", "port.loop0.rx_packets", Bound::exactly(1)),
                    ("one-frame-out", "port.loop0.tx_packets", Bound::exactly(1)),
                    ("none-missed", "port.loop0.rx_missed", Bound::exactly(0)),
                ],
            );
            case.finish()
                .expect("the report should take the case's end");
        },
    );
}

/// Send one tunnelled frame and check what comes back.
fn round_trip(far: &mut FarEnd<'_>, kernel: &mut DetachedPort, case: &mut TestCase<'_>) {
    let sent = tunnelled(&inner());
    far.send(0, sent.serialize().unwrap().as_ref());

    // A worker transmits on its own queue, and only worker 0 receives on queue 0.
    let frame = far.receive(0);
    let Some(frame) = frame else {
        expect(
            case,
            "came-back",
            "the frame comes back out of the gateway",
            false,
            Vec::new,
        );
        return;
    };
    let evidence = || vec![Evidence::frame("came back", &frame)];
    let Ok(back) = Packet::new(TestBuffer::from_raw_data(&frame)) else {
        expect(
            case,
            "parses",
            "what the gateway sends parses",
            false,
            evidence,
        );
        return;
    };
    expect(
        case,
        "next-hop",
        "addressed from this gateway to the resolved next hop",
        back.try_eth()
            .map(|eth| (eth.source().inner(), eth.destination().inner()))
            == Some((GATEWAY_MAC, PEER_MAC)),
        evidence,
    );
    expect(
        case,
        "vteps",
        "from this gateway's VTEP to the peer's",
        back.ip_source() == LOCAL_VTEP.parse().ok()
            && back.ip_destination() == PEER_VTEP.parse().ok(),
        evidence,
    );
    expect(
        case,
        "remote-vni",
        "encapsulated towards the remote VPC",
        back.try_vxlan().map(Vxlan::vni) == Some(vni(REMOTE_VNI)),
        evidence,
    );
    let carried = inside(&back);
    let masqueraded = carried.as_ref().is_some_and(|carried| {
        matches!(carried.ip_source(), Some(IpAddr::V4(source)) if source.octets()[..2] == [2, 2])
            && carried.ip_destination() == "3.3.3.1".parse().ok()
    });
    expect(
        case,
        "masqueraded",
        "carrying the inner packet masqueraded into 2.2.0.0/16, to 3.3.3.1",
        masqueraded,
        evidence,
    );
    let stray = kernel.punted.try_recv().ok();
    expect(
        case,
        "not-punted",
        "a forwarded frame does not also reach the kernel",
        stray.is_none(),
        || frame_evidence("punted", stray.as_deref()),
    );
}

/// How often a stream's progress is sampled into the report: often, since these streams take
/// tens of milliseconds.
const SAMPLE_EVERY: Duration = Duration::from_millis(5);

/// Send `streams` at once, stream `i` as run `first_run + i`, and sample their progress, and the
/// dataplane's counts since they began, into `case` as they go. Returns their ledgers and how the
/// run ended.
fn drive(
    far: &mut FarEnd<'_>,
    probe: &mut Probe<'_, '_>,
    case: &mut TestCase<'_>,
    streams: &[Stream],
    first_run: u32,
) -> (Ledgers, Ending) {
    let data_queues = usize::from(WORKERS);
    let mut ledgers = Ledgers::new();
    let mut senders: Vec<Sender> = (first_run..)
        .zip(streams)
        .map(|(run, stream)| {
            let flows = usize::try_from(stream.schedule.flows()).expect("the flows fit in memory");
            ledgers.add(&stream.name, run, flows);
            Sender::new(stream.clone(), run, data_queues)
        })
        .collect();
    let clock = Clock::start();
    let baseline = probe.sample();
    let FarEnd { pool, rx, tx } = far;
    let mut queues = Queues {
        tx: &mut tx[..data_queues],
        rx,
        pool,
    };
    let ending = generate(
        &mut senders,
        &mut queues,
        &mut ledgers,
        &clock,
        Patience {
            quiet: Duration::from_secs(1),
            limit: PATIENCE,
        },
        SAMPLE_EVERY,
        |ledgers| {
            let sample = ledgers
                .sample(Sample::new())
                .merge(probe.sample().since(&baseline));
            case.sample(sample)
                .expect("the report should take the sample");
        },
    );
    (ledgers, ending)
}

/// Check that everything every stream sent came back, and that no frame came back from nowhere.
fn check_all_back(case: &mut TestCase<'_>, ledgers: &Ledgers, ending: Ending) {
    expect(
        case,
        "all-back",
        "everything sent comes back before the time allowed runs out",
        ending == Ending::AllBack,
        || vec![Evidence::text(format!("{ending:?}"))],
    );
    let stray = ledgers.sample(Sample::new()).counters["generator.stray"];
    case.expect_counter(
        "none-stray",
        "generator.stray",
        Bound::exactly(0),
        Some(stray),
        ledgers.stray_evidence().to_vec(),
    )
    .expect("the report should take the check");
}

/// Check everything about one driven stream: it all came back, unharmed, each flow masqueraded
/// into the pool the same way every time and no two flows alike. Check ids are prefixed with the
/// stream's name.
fn check_stream(case: &mut TestCase<'_>, stream: &Stream, ledgers: &Ledgers) {
    let ledger = ledgers
        .get(&stream.name)
        .expect("every driven stream has a ledger");
    check_ledger(case, stream, ledger);
    check_translations(case, stream, ledger);
}

/// A stream of `schedule`'s flows from the local VPC to the remote one, tunnelled from the peer
/// VTEP, to destination port `dport`.
fn local_to_remote(name: &str, schedule: Schedule, dport: u16) -> Stream {
    let space = FlowSpace::new(SpaceSpec {
        src: Addresses {
            first: "1.1.0.1".parse().unwrap(),
            count: 1000,
        },
        dst: Addresses {
            first: "3.3.3.1".parse().unwrap(),
            count: 4,
        },
        sport: Ports {
            first: 1024,
            count: 8,
        },
        dport: Ports {
            first: dport,
            count: 1,
        },
        order: Order::Shuffled(0x5eed),
    })
    .unwrap();
    Stream {
        name: name.to_string(),
        space,
        schedule: schedule.validate().unwrap(),
        frame: FrameSpec {
            src_mac: [0x02, 0, 0, 0, 1, 1],
            // The gateway takes inner frames addressed to its VTEP's MAC.
            dst_mac: GATEWAY_MAC.0,
            vxlan: Some(GeneratedVxlan {
                vni: LOCAL_VNI,
                src_mac: PEER_MAC.0,
                dst_mac: GATEWAY_MAC.0,
                src: PEER_VTEP.parse().unwrap(),
                dst: LOCAL_VTEP.parse().unwrap(),
            }),
            payload_len: 64,
            ttl: 64,
        },
        rate_pps: None,
    }
}

/// Two thousand flows, four packets each, from the local VPC through the fixture gateway: every
/// packet comes back, masqueraded into the pool, each flow the same way every time and no two
/// flows the same way.
#[test]
fn many_flows_come_back_masqueraded_and_distinct() {
    over_cable(
        "many_flows_come_back_masqueraded_and_distinct",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            let stream = local_to_remote("flows", Schedule::steady(2000, 4), 80);
            let mut case = lb
                .report
                .case("steady", serde_json::to_value(stream.schedule).unwrap())
                .expect("the report should take the case");
            let (ledgers, ending) = drive(
                lb.far,
                lb.probe,
                &mut case,
                std::slice::from_ref(&stream),
                1,
            );
            check_all_back(&mut case, &ledgers, ending);
            check_stream(&mut case, &stream, &ledgers);
            check_counters(
                &mut case,
                lb.probe,
                &[("none-missed", "port.loop0.rx_missed", Bound::exactly(0))],
            );
            case.finish()
                .expect("the report should take the case's end");
        },
    );
}

/// Churn: a window of 500 flows sliding on by none, a tenth, half, and all of itself each round,
/// one case each, against one gateway. However fast flows come and go, every packet comes back,
/// translated, stably, and no two flows alike.
#[test]
fn churning_flows_come_back_masqueraded_and_distinct() {
    over_cable(
        "churning_flows_come_back_masqueraded_and_distinct",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            for (n, churn) in [0u16, 50, 250, 500].into_iter().enumerate() {
                let schedule = Schedule {
                    window: 500,
                    churn: u64::from(churn),
                    rounds: 8,
                };
                // Each case to a port of its own, so that no case's flows are an earlier case's.
                let stream = local_to_remote("flows", schedule, 8000 + churn);
                let mut case = lb
                    .report
                    .case(
                        format!("churn-{churn}"),
                        serde_json::to_value(schedule).unwrap(),
                    )
                    .expect("the report should take the case");
                let run = u32::try_from(n).unwrap() + 1;
                let (ledgers, ending) = drive(
                    lb.far,
                    lb.probe,
                    &mut case,
                    std::slice::from_ref(&stream),
                    run,
                );
                check_all_back(&mut case, &ledgers, ending);
                check_stream(&mut case, &stream, &ledgers);
                case.finish()
                    .expect("the report should take the case's end");
            }
        },
    );
}

/// Check the ledger's counters: everything sent, and back, unharmed and translated stably.
fn check_ledger(case: &mut TestCase<'_>, stream: &Stream, ledger: &Ledger) {
    let totals = ledger.sample(&stream.name, Sample::new()).counters;
    for (id, counter, bound) in [
        (
            "all-sent",
            "sent",
            Bound::exactly(stream.schedule.packets()),
        ),
        ("none-lost", "lost", Bound::exactly(0)),
        (
            "every-flow-back",
            "flows_returned",
            Bound::exactly(stream.schedule.flows()),
        ),
        ("none-foreign", "foreign", Bound::exactly(0)),
        ("no-bad-ip-checksums", "bad_ip_checksum", Bound::exactly(0)),
        (
            "no-bad-udp-checksums",
            "bad_udp_checksum",
            Bound::exactly(0),
        ),
        ("none-corrupt", "corrupt", Bound::exactly(0)),
        ("stable-translations", "unstable", Bound::exactly(0)),
    ] {
        let path = format!("generator.{}.{counter}", stream.name);
        let id = format!("{}.{id}", stream.name);
        let observed = totals.get(&path).copied();
        let evidence = if observed.is_some_and(|n| bound.admits(n)) {
            Vec::new()
        } else {
            ledger.evidence().to_vec()
        };
        case.expect_counter(id, path, bound, observed, evidence)
            .expect("the report should take the check");
    }
}

/// Check how each flow came back: masqueraded into 2.2.0.0/16, to the same destination, in the
/// remote VPC's VNI, and as no other flow did.
fn check_translations(case: &mut TestCase<'_>, stream: &Stream, ledger: &Ledger) {
    let mut wrong = Vec::new();
    let mut seen = HashMap::new();
    let mut collisions = Vec::new();
    for n in 0..stream.schedule.flows() {
        let sent = stream.space.flow(n);
        let Some(back) = usize::try_from(n).ok().and_then(|n| ledger.returned_as(n)) else {
            continue;
        };
        let translated = back.tuple.src.octets()[..2] == [2, 2]
            && back.tuple.dst == sent.dst
            && back.tuple.dport == sent.dport
            && back.tunnel.map(|(vni, _, _)| vni) == Some(REMOTE_VNI);
        if !translated {
            wrong.push(Evidence::text(format!(
                "flow {n}: sent as {sent:?}, came back as {back:?}"
            )));
        }
        if let Some(other) = seen.insert(back.tuple, n) {
            collisions.push(Evidence::text(format!(
                "flows {other} and {n} both came back as {:?}",
                back.tuple
            )));
        }
    }
    let ok = wrong.is_empty();
    expect(
        case,
        &format!("{}.masqueraded", stream.name),
        "every flow comes back from 2.2.0.0/16, to its own destination, in the remote VPC",
        ok,
        || wrong,
    );
    let ok = collisions.is_empty();
    expect(
        case,
        &format!("{}.distinct-translations", stream.name),
        "no two flows come back with the same addresses and ports",
        ok,
        || collisions,
    );
}

/// Two streams through the gateway at once -- a steady one, and one churning half its flows a
/// round -- each accounted for apart: both come back whole, translated, stably, and no frame comes
/// back that neither sent.
#[test]
fn two_streams_at_once_are_each_accounted_for() {
    over_cable(
        "two_streams_at_once_are_each_accounted_for",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            let streams = [
                local_to_remote("steady", Schedule::steady(500, 8), 80),
                local_to_remote(
                    "churning",
                    Schedule {
                        window: 500,
                        churn: 250,
                        rounds: 8,
                    },
                    9000,
                ),
            ];
            let mut case = lb
                .report
                .case("together", serde_json::json!({}))
                .expect("the report should take the case");
            let (ledgers, ending) = drive(lb.far, lb.probe, &mut case, &streams, 1);
            check_all_back(&mut case, &ledgers, ending);
            for stream in &streams {
                check_stream(&mut case, stream, &ledgers);
            }
            case.finish()
                .expect("the report should take the case's end");
        },
    );
}
