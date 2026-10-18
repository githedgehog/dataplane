// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use crate::frame::{ChecksumState, FrameSpec, Template, Transport, Vxlan, parse, tcp};
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
    spec_carrying(vxlan, payload_len, Transport::Udp)
}

fn spec_carrying(vxlan: bool, payload_len: u16, transport: Transport) -> FrameSpec {
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
        transport,
        payload_len,
        ttl: 64,
        mutation: None,
        vlan: None,
    }
}

/// A stamped frame reads back as what was stamped, with correct checksums, however many times it
/// was stamped before: the incremental checksum update agrees with computing it afresh. Tagged or
/// not, tunnelled or not.
#[test]
fn stamped_frames_read_back_as_stamped() {
    bolero::check!()
        .with_type::<(bool, Option<u8>, u8, u16, Option<u16>, Vec<(u64, u64)>)>()
        .for_each(|(vxlan, flags, payload, sport, vlan, stamps)| {
            let tuple = Tuple {
                src: Ipv4Addr::new(1, 1, 0, 1),
                dst: Ipv4Addr::new(3, 3, 3, 1),
                sport: *sport,
                dport: 80,
            };
            let transport = flags.map_or(Transport::Udp, |flags| Transport::Tcp { flags });
            let mut spec = spec_carrying(*vxlan, u16::from(*payload), transport);
            spec.vlan = vlan.map(|vid| vid & 0x0fff);
            let mut template = Template::new(&spec, 7, 42, &tuple);
            for &(seq, tx_ns) in stamps.iter().chain([&(0, 0)]) {
                template.stamp(seq, tx_ns);
                let got = parse(template.bytes()).unwrap();
                assert_eq!(got.tuple, tuple);
                assert_eq!(got.ip_checksum, ChecksumState::Valid);
                assert_eq!(got.l4_checksum, ChecksumState::Valid);
                assert_eq!(got.tcp_flags, *flags);
                assert!(got.payload_intact);
                let signature = got.signature.unwrap();
                assert_eq!((signature.run, signature.flow), (7, 42));
                assert_eq!((signature.seq, signature.tx_ns), (seq, tx_ns));
                assert_eq!(got.tunnel.map(|t| t.vni), spec.vxlan.map(|v| v.vni));
                assert_eq!(got.vlan, spec.vlan);
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

    for (vxlan, transport) in [
        (false, Transport::Udp),
        (true, Transport::Udp),
        (false, Transport::Tcp { flags: tcp::SYN }),
        (
            true,
            Transport::Tcp {
                flags: tcp::ACK | tcp::PSH,
            },
        ),
    ] {
        let tuple = Tuple {
            src: Ipv4Addr::new(1, 1, 0, 1),
            dst: Ipv4Addr::new(3, 3, 3, 1),
            sport: 1234,
            dport: 80,
        };
        let spec = spec_carrying(vxlan, 64, transport);
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
    assert_eq!(counter("bad_l4_checksum"), 0);
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
    assert_eq!(sample.counters["generator.s.bad_l4_checksum"], 1);
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

/// Frames from several streams are each counted by their own stream's ledger, and frames from no
/// stream by none.
#[test]
fn ledgers_count_each_stream_apart() {
    use crate::ledger::Ledgers;

    let mut ledgers = Ledgers::new();
    ledgers.add("victim", 1, 2);
    ledgers.add("aggressor", 2, 1);
    ledgers.for_run(1).unwrap().sent(0);
    ledgers.for_run(1).unwrap().sent(1);
    ledgers.for_run(2).unwrap().sent(0);

    ledgers.receive(&frame(1, 0, 0, tuple(10)), 0);
    ledgers.receive(&frame(1, 1, 0, tuple(11)), 0);
    ledgers.receive(&frame(3, 0, 0, tuple(12)), 0);
    ledgers.receive(&[0; 8], 0);

    assert_eq!(ledgers.get("victim").unwrap().total_received(), 2);
    assert_eq!(ledgers.get("aggressor").unwrap().total_received(), 0);
    assert!(
        !ledgers.all_back(),
        "the aggressor's packet never came back"
    );
    let sample = ledgers.sample(flowgen_report::Sample::new());
    assert_eq!(sample.counters["generator.stray"], 2);
    assert_eq!(sample.counters["generator.victim.lost"], 0);
    assert_eq!(sample.counters["generator.aggressor.lost"], 1);
    assert_eq!(ledgers.stray_evidence().len(), 2);
}

#[test]
#[should_panic(expected = "would share its name or run")]
fn streams_cannot_share_a_run() {
    let mut ledgers = crate::ledger::Ledgers::new();
    ledgers.add("a", 1, 1);
    ledgers.add("b", 1, 1);
}

/// A stream that drops what a full port refuses counts it as dropped there, not sent and not lost,
/// and goes on; one that retries offers it again.
#[test]
fn a_full_port_drops_or_defers_as_the_stream_says() {
    use crate::schedule::Schedule;
    use crate::sender::{Sender, Stream, WhenFull};

    for when_full in [WhenFull::Drop, WhenFull::Retry] {
        let stream = Stream {
            name: "s".to_string(),
            space: space((1, 1, 1, 1, None)),
            schedule: Schedule::steady(1, 4),
            frame: spec(false, 64),
            rate_pps: None,
            when_full,
            returns: crate::sender::Returns::Everything,
        };
        let mut ledger = Ledger::new(1, 1);
        let mut sender = Sender::new(stream, 1, 1);
        let first = sender.plan(ledger.total_offered());
        assert_eq!(first.len(), 4);
        // The port takes the first two and has no room for the rest.
        sender.accepted(first[0], &mut ledger);
        sender.accepted(first[1], &mut ledger);
        sender.refused(&first[2..], &mut ledger);
        let again = sender.plan(ledger.total_offered());
        let sample = ledger.sample("s", flowgen_report::Sample::new());
        assert_eq!(sample.counters["generator.s.sent"], 2);
        assert_eq!(
            sample.counters["generator.s.lost"], 2,
            "sent and never received"
        );
        match when_full {
            WhenFull::Drop => {
                assert_eq!(sample.counters["generator.s.dropped_at_port"], 2);
                assert!(again.is_empty() && sender.done());
            }
            WhenFull::Retry => {
                assert_eq!(sample.counters["generator.s.dropped_at_port"], 0);
                assert_eq!(again, first[2..].to_vec());
            }
        }
    }
}

/// A wire that hands back whatever is sent on it, or swallows it.
struct Mirror {
    swallow: bool,
    pending: Vec<Vec<u8>>,
}

impl crate::drive::Wire for Mirror {
    fn send(
        &mut self,
        sender: &mut crate::sender::Sender,
        ledger: &mut Ledger,
        clock: &crate::sender::Clock,
    ) -> usize {
        let slots = sender.plan(ledger.total_offered());
        for &slot in &slots {
            let (frame, _) = sender.stamp(slot, clock.now_ns());
            if !self.swallow {
                self.pending.push(frame.to_vec());
            }
            sender.accepted(slot, ledger);
        }
        slots.len()
    }

    fn send_frame(&mut self, frame: &[u8]) -> bool {
        self.pending.push(frame.to_vec());
        true
    }

    fn receive(&mut self, deliver: &mut dyn FnMut(&[u8])) -> usize {
        let n = self.pending.len();
        for frame in self.pending.drain(..) {
            deliver(&frame);
        }
        n
    }
}

/// A stream that should have nothing back ends its run once the quiet period has passed after its
/// last packet, and whatever does come back is counted as received: it escaped.
#[test]
fn a_stream_expecting_nothing_waits_out_the_quiet_and_counts_escapes() {
    use std::time::Duration;

    use crate::drive::{Ending, Load, Patience, run};
    use crate::ledger::Ledgers;
    use crate::schedule::Schedule;
    use crate::sender::{Clock, Returns, Sender, Stream, WhenFull};

    let quiet = Duration::from_millis(50);
    for swallow in [true, false] {
        let stream = Stream {
            name: "dropped".to_string(),
            space: space((1, 1, 1, 1, None)),
            schedule: Schedule::steady(1, 4),
            frame: spec(false, 64),
            rate_pps: None,
            when_full: WhenFull::Retry,
            returns: Returns::Nothing,
        };
        let mut ledgers = Ledgers::new();
        ledgers.add_stream(&stream, 1);
        assert!(ledgers.awaits_silence());
        let mut senders = [(0, Sender::new(stream, 1, 1))];
        let mut wire = Mirror {
            swallow,
            pending: Vec::new(),
        };
        let started = clock::now();
        let ending = run(
            &mut Load {
                senders: &mut senders,
                agents: &mut [],
            },
            &mut [&mut wire],
            &mut ledgers,
            &Clock::start(),
            Patience {
                quiet,
                limit: Duration::from_secs(10),
                hold: Duration::ZERO,
            },
            Duration::from_secs(1),
            |_| {},
        );
        assert_eq!(ending, Ending::AllBack);
        assert!(
            clock::elapsed(started) >= quiet,
            "the run waited for silence"
        );
        let sample = ledgers.sample(flowgen_report::Sample::new());
        assert_eq!(sample.counters["generator.dropped.sent"], 4);
        let escaped = if swallow { 0 } else { 4 };
        assert_eq!(sample.counters["generator.dropped.received"], escaped);
    }
}

/// One of every kind of change, chosen by `kind`, its values drawn from `a` and `b`.
fn change(kind: u8, a: u16, b: u32) -> crate::mutate::Change {
    use crate::mutate::Change;

    let mac = {
        let [b0, b1, b2, b3] = b.to_be_bytes();
        let [a0, a1] = a.to_be_bytes();
        [b0, b1, b2, b3, a0, a1]
    };
    let addr = Ipv4Addr::from(b);
    let [lo, _] = a.to_le_bytes();
    let delta = i16::from_le_bytes(a.to_le_bytes());
    match kind % 26 {
        0 => Change::SourceMac { mac },
        1 => Change::DestinationMac { mac },
        2 => Change::EtherType { ethertype: a },
        3 => Change::VlanTag { vid: a },
        4 => Change::Truncate { len: a % 200 },
        5 => Change::Padding { bytes: a % 64 },
        6 => Change::IpVersion { version: lo },
        7 => Change::HeaderLength { words: lo },
        8 => Change::TotalLength { delta },
        9 => Change::IpOptions { words: lo % 11 },
        10 => Change::IpChecksum,
        11 => Change::Ttl { ttl: lo },
        12 => Change::Protocol { protocol: lo },
        13 => Change::SourceIp { addr },
        14 => Change::DestinationIp { addr },
        15 => Change::Fragment {
            more: a & 1 == 1,
            offset: a >> 1,
        },
        16 => Change::L4Checksum,
        17 => Change::UdpChecksumZero,
        18 => Change::UdpLength { delta },
        19 => Change::TcpDataOffset { words: lo },
        20 => Change::TcpFlags { flags: lo },
        21 => Change::SourcePort { port: a },
        22 => Change::DestinationPort { port: a },
        23 => Change::VxlanFlags { flags: lo },
        24 => Change::VxlanReserved,
        _ => Change::Vni { vni: b },
    }
}

/// `spec`, mutated in `layer` by `change`.
fn mutated(
    vxlan: bool,
    transport: Transport,
    layer: crate::mutate::Layer,
    change: crate::mutate::Change,
) -> FrameSpec {
    let mut spec = spec_carrying(vxlan, 64, transport);
    spec.mutation = Some(crate::mutate::Mutation { layer, change });
    spec
}

/// Whether the IPv4 header at the start of `header` has a correct checksum.
fn ipv4_header_verifies(header: &[u8]) -> bool {
    let words = usize::from(header[0] & 0x0f) * 4;
    crate::checksum::finish(crate::checksum::sum(0, &header[..words])) == 0
}

/// Any mutation a stream's frames can take builds and stamps without fault; the tunnel around a
/// mutated packet stays sound, its lengths agreeing with what it carries; and a mutation that
/// leaves the signature whole leaves it readable where it was stamped.
#[test]
fn any_mutation_builds_and_stamps_and_keeps_its_tunnel_sound() {
    use crate::mutate::{Layer, Mutation};

    bolero::check!()
        .with_type::<(bool, bool, bool, u8, u16, u32, Vec<u64>)>()
        .for_each(|(vxlan, tcp_transport, outer, kind, a, b, stamps)| {
            let transport = if *tcp_transport {
                Transport::Tcp { flags: tcp::ACK }
            } else {
                Transport::Udp
            };
            let layer = if *outer { Layer::Outer } else { Layer::Inner };
            let change = change(*kind, *a, *b);
            let spec = mutated(*vxlan, transport, layer, change);
            let mutation = Mutation { layer, change };
            if mutation.check(&spec).is_err() {
                return;
            }
            let mut template = Template::new(&spec, 3, 5, &tuple(1000));
            for &seq in stamps.iter().chain([&9]) {
                template.stamp(seq, seq);
            }
            let bytes = template.bytes();
            let cut = matches!(change, crate::mutate::Change::Truncate { .. });
            if *vxlan && layer == Layer::Inner && !cut {
                let outer_len = u16::from_be_bytes([bytes[16], bytes[17]]);
                let udp_len = u16::from_be_bytes([bytes[38], bytes[39]]);
                assert_eq!(usize::from(outer_len), bytes.len() - 14);
                assert_eq!(usize::from(udp_len), bytes.len() - 34);
                assert!(ipv4_header_verifies(&bytes[14..]));
            }
            if let Ok(got) = parse(bytes)
                && let Some(signature) = got.signature
                && signature.run == 3
            {
                assert_eq!((signature.seq, signature.tx_ns), (9, 9));
            }
        });
}

/// Each change breaks what it says it does, and leaves every checksum it does not concern right.
#[test]
#[allow(clippy::too_many_lines)] // one short check per kind of change
fn a_mutation_breaks_only_what_it_says() {
    use crate::mutate::{Change, Layer};

    let udp = Transport::Udp;
    let multicast = Ipv4Addr::new(224, 0, 0, 5);
    for vxlan in [false, true] {
        let read = |layer: Layer, change: Change, transport: Transport| {
            let spec = mutated(vxlan, transport, layer, change);
            let mut template = Template::new(&spec, 1, 0, &tuple(1000));
            template.stamp(3, 4);
            template.stamp(5, 6);
            let bytes = template.bytes().to_vec();
            (parse(&bytes), bytes)
        };
        let sound = |got: &crate::frame::Received| {
            got.ip_checksum == ChecksumState::Valid
                && got.l4_checksum == ChecksumState::Valid
                && got.payload_intact
                && got.signature.is_some_and(|s| (s.seq, s.tx_ns) == (5, 6))
        };

        let (got, _) = read(Layer::Inner, Change::Ttl { ttl: 0 }, udp);
        let got = got.unwrap();
        assert!(sound(&got) && got.ttl == 0);

        let (got, _) = read(Layer::Inner, Change::SourceIp { addr: multicast }, udp);
        let got = got.unwrap();
        assert!(sound(&got) && got.tuple.src == multicast, "{got:?}");

        let (got, _) = read(Layer::Inner, Change::SourcePort { port: 0 }, udp);
        let got = got.unwrap();
        assert!(sound(&got) && got.tuple.sport == 0);

        let (got, _) = read(
            Layer::Inner,
            Change::SourceMac {
                mac: [1, 0, 0x5e, 0, 0, 5],
            },
            udp,
        );
        let got = got.unwrap();
        assert!(sound(&got) && got.src_mac == [1, 0, 0x5e, 0, 0, 5]);

        let (got, _) = read(Layer::Inner, Change::IpChecksum, udp);
        let got = got.unwrap();
        assert_eq!(got.ip_checksum, ChecksumState::Invalid);
        assert_eq!(got.l4_checksum, ChecksumState::Valid);

        for transport in [udp, Transport::Tcp { flags: tcp::SYN }] {
            let (got, _) = read(Layer::Inner, Change::L4Checksum, transport);
            let got = got.unwrap();
            assert_eq!(got.ip_checksum, ChecksumState::Valid);
            assert_eq!(
                got.l4_checksum,
                ChecksumState::Invalid,
                "stays wrong when stamped"
            );
        }

        let (got, _) = read(Layer::Inner, Change::UdpChecksumZero, udp);
        assert_eq!(
            got.unwrap().l4_checksum,
            ChecksumState::Absent,
            "stays absent when stamped"
        );

        let (got, bytes) = read(Layer::Inner, Change::IpOptions { words: 3 }, udp);
        let got = got.unwrap();
        assert!(sound(&got), "{got:?}");
        let ip = if vxlan { 50 + 14 } else { 14 };
        assert_eq!(bytes[ip] & 0x0f, 8, "five words and three of options");

        let (got, bytes) = read(Layer::Inner, Change::Padding { bytes: 10 }, udp);
        assert!(sound(&got.unwrap()));
        let plain = Template::new(&spec(vxlan, 64), 1, 0, &tuple(1000));
        assert_eq!(bytes.len(), plain.bytes().len() + 10);

        let (got, _) = read(
            Layer::Inner,
            Change::Fragment {
                more: true,
                offset: 0,
            },
            udp,
        );
        assert_eq!(got.unwrap_err(), crate::frame::ParseError::Fragment);

        let (got, _) = read(
            Layer::Inner,
            Change::TcpFlags {
                flags: tcp::SYN | tcp::FIN,
            },
            Transport::Tcp { flags: tcp::SYN },
        );
        let got = got.unwrap();
        assert!(sound(&got) && got.tcp_flags == Some(tcp::SYN | tcp::FIN));

        let (got, _) = read(Layer::Inner, Change::Truncate { len: 40 }, udp);
        assert!(got.is_err(), "cut short of its transport header");

        if vxlan {
            let (got, bytes) = read(Layer::Outer, Change::Vni { vni: 77 }, udp);
            let got = got.unwrap();
            assert!(sound(&got) && got.tunnel.unwrap().vni == 77);
            assert!(ipv4_header_verifies(&bytes[14..]));

            let (got, bytes) = read(Layer::Outer, Change::SourceIp { addr: multicast }, udp);
            let got = got.unwrap();
            assert!(sound(&got) && got.tunnel.unwrap().src == multicast);
            assert!(ipv4_header_verifies(&bytes[14..]));

            let (got, bytes) = read(Layer::Outer, Change::IpChecksum, udp);
            assert!(sound(&got.unwrap()), "the packet inside is untouched");
            assert!(!ipv4_header_verifies(&bytes[14..]));

            // The reader takes a tag wherever it is, so the frame still reads, signature and all.
            let (got, bytes) = read(Layer::Inner, Change::VlanTag { vid: 7 }, udp);
            assert!(got.unwrap().signature.is_some());
            assert_eq!(&bytes[50 + 12..50 + 16], &[0x81, 0x00, 0x00, 0x07]);
        }
    }
}

/// A mutation is refused for frames without the header it changes.
#[test]
fn a_mutation_needs_the_header_it_changes() {
    use crate::mutate::{Change, Layer, Mutation, MutationError};

    let bare = spec(false, 64);
    let tunnelled = spec(true, 64);
    let tcp_spec = spec_carrying(false, 64, Transport::Tcp { flags: tcp::SYN });
    let m = |layer, change| Mutation { layer, change };
    assert_eq!(
        m(Layer::Outer, Change::IpChecksum).check(&bare),
        Err(MutationError::NoTunnel)
    );
    assert_eq!(
        m(Layer::Inner, Change::Vni { vni: 1 }).check(&tunnelled),
        Err(MutationError::NotVxlan)
    );
    assert_eq!(
        m(Layer::Inner, Change::UdpChecksumZero).check(&tcp_spec),
        Err(MutationError::WrongTransport)
    );
    assert_eq!(
        m(Layer::Inner, Change::TcpFlags { flags: 0 }).check(&bare),
        Err(MutationError::WrongTransport)
    );
    assert_eq!(
        m(Layer::Inner, Change::IpOptions { words: 11 }).check(&bare),
        Err(MutationError::TooManyOptions)
    );
    assert_eq!(
        m(Layer::Outer, Change::Vni { vni: 1 }).check(&tunnelled),
        Ok(())
    );
}
