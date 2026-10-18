// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The flowgen catalog of hostile frames, through the fixture gateway: each entry's frames, one
//! case each, and whether they met the fate the catalog expects.

use std::time::Duration;

use flowgen::catalog::{Base, CATALOG, Counted, Entry, Fate, Standing};
use flowgen::frame::{Transport, tcp};
use flowgen::ledger::Ledgers;
use flowgen::schedule::Schedule;
use flowgen::sender::{Clock, Returns};
use flowgen_report::{Evidence, Sample};

use super::flows::local_to_remote;
use super::harness::{
    Loopback, Punted, Side, TestCase, Traffic, drive_quietly, fixture_gateway, over_cable, settle,
};

/// Packets each entry sends: one flow's worth.
const PACKETS: u64 = 4;

/// How long after an entry's last packet to wait for any that would come back.
const QUIET: Duration = Duration::from_millis(100);

/// Where the gateway's telemetry is read from.
const TELEMETRY: &str = "dataplane";

/// Reasons a packet can finish for that are not drops.
const NOT_DROPS: [&str; 2] = ["Delivered", "Local"];

/// Every entry of the catalog, each in a case of its own: its frames sent from the far end of the
/// cable, and what became of them judged against what the catalog expects -- or, where the catalog
/// says the expectation is unsettled, recorded without being judged.
#[test]
fn the_catalog_of_hostile_frames_meets_its_fates() {
    over_cable(
        "the_catalog_of_hostile_frames_meets_its_fates",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            for (n, entry) in CATALOG.iter().enumerate() {
                let run = u32::try_from(n).unwrap() + 1;
                send_entry(lb, entry, run);
            }
        },
    );
}

/// Send `entry`'s frames as run `run`, in a case of its own, and judge what became of them.
fn send_entry(lb: &mut Loopback<'_, '_, '_, '_>, entry: &Entry, run: u32) {
    // Each entry's flow to a port of its own, so that no entry finds another's flow state.
    let dport = 20_000 + u16::try_from(run).unwrap();
    let mut stream = local_to_remote(entry.id, Schedule::steady(1, PACKETS), dport);
    stream.frame.transport = match entry.base {
        Base::Udp => Transport::Udp,
        Base::TcpSyn => Transport::Tcp { flags: tcp::SYN },
    };
    stream.frame.mutation = Some(entry.mutation);
    stream.returns = match entry.expect.fate {
        Fate::Forwarded => Returns::Everything,
        Fate::Dropped { .. } => Returns::Nothing,
    };
    let mut case = lb
        .report
        .case(entry.id, serde_json::to_value(entry).unwrap())
        .expect("the report should take the case");
    let before = settle(lb.probe);
    let (ledgers, _, punted) = drive_quietly(
        lb.far,
        lb.kernel,
        lb.probe,
        &mut case,
        Traffic {
            streams: &[(Side::Far, stream)],
            first_run: run,
            agents: &mut [],
            hold: Duration::ZERO,
            clock: Clock::start(),
        },
        QUIET,
    );
    let counted = settle(lb.probe).since(&before);
    case.sample(counted.clone())
        .expect("the report should take the sample");
    judge(&mut case, entry, &ledgers, punted, &counted);
    case.finish()
        .expect("the report should take the case's end");
}

/// What became of an entry's frames.
#[derive(Debug)]
struct Seen {
    /// Sent.
    sent: u64,
    /// Forwarded back out of the port: frames of the stream's, readable or not.
    forwarded: u64,
    /// Counted by the gateway as dropped.
    dropped: u64,
    /// Handed to the kernel.
    punted: u64,
    /// Frames back out of the port that are not the stream's: the gateway's answers.
    answers: u64,
}

/// Judge what became of `entry`'s frames, given its stream's `ledgers`, what was `punted`, and what
/// the gateway `counted` while they were sent.
fn judge(
    case: &mut TestCase<'_>,
    entry: &Entry,
    ledgers: &Ledgers,
    punted: Punted,
    counted: &Sample,
) {
    let ledger = ledgers
        .get(entry.id)
        .expect("the entry's stream has a ledger");
    let drops = format!("{TELEMETRY}.pipeline_packets.reason=");
    let unparsed = format!("{TELEMETRY}.worker_parse_errors.");
    let sum = |keep: &dyn Fn(&str) -> bool| -> u64 {
        counted
            .counters
            .iter()
            .filter(|(path, _)| keep(path))
            .map(|(_, n)| n)
            .sum()
    };
    let is_drop = |path: &str| {
        path.strip_prefix(&drops)
            .is_some_and(|reason| !NOT_DROPS.contains(&reason))
            || path.starts_with(&unparsed)
    };
    let punted = punted.control + punted.data;
    // Whatever reached the kernel was read by the ledgers too, as the stream's or as stray.
    let back = ledger.total_received();
    let stray = ledgers.sample(Sample::new()).counters["generator.stray"];
    let answered = matches!(entry.expect.fate, Fate::Dropped { answered: true, .. });
    // An answer is a frame of the gateway's own; anything else back is the stream's, if mangled.
    let (forwarded, answers) = if answered {
        (back, stray)
    } else {
        ((back + stray).saturating_sub(punted), 0)
    };
    let seen = Seen {
        sent: ledger.total_sent(),
        forwarded,
        dropped: sum(&is_drop),
        punted,
        answers,
    };

    let (description, held) = match entry.expect.fate {
        Fate::Forwarded => (
            "every frame is forwarded, and none dropped or handed to the kernel".to_string(),
            seen.forwarded == seen.sent && seen.dropped == 0 && seen.punted == 0,
        ),
        Fate::Dropped {
            counted: by,
            answered,
        } => {
            let (by_counter, what) = match by {
                None => (true, "a drop counter".to_string()),
                Some(Counted::Reason(reason)) => (
                    counted.counters.get(&format!("{drops}{reason}")) == Some(&seen.sent),
                    format!("pipeline_packets.reason={reason}"),
                ),
                Some(Counted::Unparsed) => (
                    sum(&|path| path.starts_with(&unparsed)) == seen.sent,
                    "worker_parse_errors".to_string(),
                ),
            };
            let how = if answered {
                "each answered with an ICMP error"
            } else {
                "silently"
            };
            (
                format!(
                    "every frame is dropped, {how}, and counted as dropped, by {what}; none is \
                     forwarded or handed to the kernel"
                ),
                seen.forwarded == 0
                    && seen.punted == 0
                    && seen.dropped == seen.sent
                    && by_counter
                    && seen.answers == if answered { seen.sent } else { 0 },
            )
        }
    };
    let evidence = || {
        let mut evidence = vec![Evidence::text(format!("{seen:?}"))];
        evidence.extend(ledgers.stray_evidence().iter().cloned());
        evidence.extend(ledger.evidence().iter().cloned());
        evidence
    };
    let status = match entry.expect.standing {
        Standing::Settled => {
            let evidence = if held { Vec::new() } else { evidence() };
            case.expect("fate", description, held, evidence)
        }
        Standing::Undecided(why) => case.unsettled("fate", description, held, why, evidence()),
        // A divergence mended is an entry to settle, not one to go on skipping.
        Standing::Diverges(_) if held => case.expect(
            "fate",
            format!("{description} -- the gateway now does; settle the entry"),
            false,
            evidence(),
        ),
        Standing::Diverges(instead) => case.unsettled(
            "fate",
            description,
            held,
            format!("a known divergence: {instead}"),
            evidence(),
        ),
    };
    status.expect("the report should take the check");
}

/// How many arbitrary mutations [`arbitrary_mutations_are_all_accounted_for`] sends:
/// `$FLOWGEN_ARBITRARY`, or 256, a fraction of a second's worth.
fn arbitrary() -> usize {
    std::env::var("FLOWGEN_ARBITRARY")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(256)
}

/// The seed for the arbitrary mutations: `$FLOWGEN_SEED`, or a fixed one, so that a failure can be
/// run again as it was.
fn seed() -> u64 {
    std::env::var("FLOWGEN_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(0x00f1_0e9e)
}

/// Watches every frame the gateway sends out of the port for what it must never send, whatever it
/// was sent: a frame not from its own MAC address, or not in a tunnel of its own making, or with a
/// group address as the source of the frame inside. Claims nothing, so the streams' ledgers count
/// every frame too.
#[derive(Default)]
struct Watch {
    seen: u64,
    bad: u64,
    evidence: Vec<Evidence>,
}

impl Watch {
    /// What is wrong with `frame`, if anything.
    fn fault(frame: &[u8]) -> Option<&'static str> {
        use crate::packet_processor::fixture::{GATEWAY_MAC, LOCAL_VTEP, PEER_MAC};

        if frame.get(6..12) != Some(&GATEWAY_MAC.0[..]) {
            return Some("not from the gateway's MAC address");
        }
        if frame.get(0..6) != Some(&PEER_MAC.0[..]) {
            return Some("not to the next hop's MAC address");
        }
        let Some((_, ip)) = flowgen::frame::ipv4_packet(frame) else {
            return Some("not IPv4");
        };
        let header = &ip[..usize::from(ip[0] & 0x0f) * 4];
        let mut sum: u32 = header
            .chunks(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        if sum != 0xffff {
            return Some("a wrong tunnel IPv4 header checksum");
        }
        if ip[12..16] != LOCAL_VTEP.parse::<std::net::Ipv4Addr>().unwrap().octets() {
            return Some("not from the gateway's VTEP");
        }
        let Some((_, inner)) = flowgen::frame::decapsulate(frame) else {
            return Some("not VXLAN");
        };
        if inner.get(6).is_none_or(|first| first & 1 == 1) {
            return Some("the frame inside is from a group MAC address, or has none");
        }
        None
    }
}

impl flowgen::drive::Agent for Watch {
    fn wire(&self) -> usize {
        super::harness::FAR
    }

    fn transmit(&mut self, _: u64) -> Option<Vec<u8>> {
        None
    }

    fn receive(&mut self, frame: &[u8], _: u64) -> bool {
        self.seen += 1;
        if let Some(fault) = Self::fault(frame) {
            self.bad += 1;
            if self.evidence.len() < flowgen_report::MAX_EVIDENCE {
                self.evidence.push(Evidence::frame(fault, frame));
            }
        }
        false
    }

    fn sample(&self, _: u64, sample: Sample) -> Sample {
        sample
            .counter("watch.seen", self.seen)
            .counter("watch.bad", self.bad)
    }
}

/// Arbitrary mutations from a seeded sequence, [`arbitrary`] of them, each a stream of one flow
/// sent all at once: whatever the gateway makes of them, it accounts for every frame -- forwarded,
/// dropped, or handed to the kernel -- sends nothing out it should not, and forwards ordinary
/// traffic as well afterwards as before.
#[test]
fn arbitrary_mutations_are_all_accounted_for() {
    use flowgen::mutate::Mutations;

    over_cable(
        "arbitrary_mutations_are_all_accounted_for",
        fixture_gateway,
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            let seed = seed();
            let streams: Vec<(Side, flowgen::sender::Stream)> = Mutations::seeded(seed)
                .enumerate()
                .filter_map(|(n, mutation)| {
                    // Each mutation's flow to a port of its own, wrapping past the last.
                    let dport = 30_000 + u16::try_from(n % 30_000).unwrap();
                    let name = format!("m{n}");
                    let mut stream = local_to_remote(&name, Schedule::steady(1, 2), dport);
                    if n % 4 == 0 {
                        stream.frame.transport = Transport::Tcp { flags: tcp::SYN };
                    }
                    mutation.check(&stream.frame).ok()?;
                    stream.frame.mutation = Some(mutation);
                    stream.returns = Returns::Nothing;
                    Some((Side::Far, stream))
                })
                .take(arbitrary())
                .collect();
            let mutations: Vec<_> = streams
                .iter()
                .map(|(_, s)| serde_json::json!({ "stream": s.name, "mutation": s.frame.mutation }))
                .collect();
            let mut case = lb
                .report
                .case(
                    "arbitrary",
                    serde_json::json!({ "seed": seed, "mutations": mutations }),
                )
                .expect("the report should take the case");
            let mut watch = Watch::default();
            let before = settle(lb.probe);
            let (ledgers, _, punted) = drive_quietly(
                lb.far,
                lb.kernel,
                lb.probe,
                &mut case,
                Traffic {
                    streams: &streams,
                    first_run: 1,
                    agents: &mut [&mut watch],
                    hold: Duration::ZERO,
                    clock: Clock::start(),
                },
                QUIET,
            );
            let counted = settle(lb.probe).since(&before);
            case.sample(counted.clone())
                .expect("the report should take the sample");
            account(&mut case, &ledgers, punted, &counted, &watch);
            case.finish()
                .expect("the report should take the case's end");

            still_forwarding(lb, u32::try_from(streams.len()).unwrap() + 1);
        },
    );
}

/// Check that every frame `ledgers` sent is accounted for, and that `watch` saw nothing amiss.
fn account(
    case: &mut TestCase<'_>,
    ledgers: &Ledgers,
    punted: Punted,
    counted: &Sample,
    watch: &Watch,
) {
    let totals = ledgers.sample(Sample::new()).counters;
    let total = |counter: &str| -> u64 {
        totals
            .iter()
            .filter(|(path, _)| path.ends_with(&format!(".{counter}")))
            .map(|(_, n)| n)
            .sum()
    };
    let sent = total("sent");
    let punted = punted.control + punted.data;
    let forwarded = (total("received") + totals["generator.stray"]).saturating_sub(punted);
    let sum = |prefix: &str| -> u64 {
        counted
            .counters
            .iter()
            .filter(|(path, _)| path.starts_with(&format!("{TELEMETRY}.{prefix}")))
            .map(|(_, n)| n)
            .sum()
    };
    let drops = format!("{TELEMETRY}.pipeline_packets.reason=");
    let by_pipeline: u64 = counted
        .counters
        .iter()
        .filter(|(path, _)| {
            path.strip_prefix(&drops)
                .is_some_and(|reason| !NOT_DROPS.contains(&reason))
        })
        .map(|(_, n)| n)
        .sum();
    // So many frames at once can fill the far end's receive queues and the kernel's channel: the
    // workers count what they could not hand on, and that is accounted for too.
    let unparsed = sum("worker_parse_errors.");
    let untransmitted = sum("worker_tx_drops.");
    let unpunted = sum("worker_punt_drops.");
    let accounted = forwarded + by_pipeline + unparsed + untransmitted + punted + unpunted;
    let evidence = || {
        vec![Evidence::text(format!(
            "sent {sent}: forwarded {forwarded}; dropped by the pipeline {by_pipeline}, \
             unparsed {unparsed}, not transmitted {untransmitted}; handed to the kernel \
             {punted}, not handed to it {unpunted}"
        ))]
    };
    case.expect(
        "all-accounted-for",
        "every frame sent is forwarded, handed to the kernel, or counted as dropped, once",
        accounted == sent,
        if accounted == sent {
            Vec::new()
        } else {
            evidence()
        },
    )
    .expect("the report should take the check");
    case.expect(
        "nothing-amiss-out",
        "every frame out of the port is from the gateway, in a tunnel of its own, carrying a frame \
         from a unicast address",
        watch.bad == 0,
        watch.evidence.clone(),
    )
    .expect("the report should take the check");
}

/// Check that ordinary traffic still goes through, sent as run `run`: sixteen flows, two packets
/// each, all back.
fn still_forwarding(lb: &mut Loopback<'_, '_, '_, '_>, run: u32) {
    let stream = local_to_remote("after", Schedule::steady(16, 2), 40_000);
    let mut case = lb
        .report
        .case("still-forwarding", serde_json::json!({}))
        .expect("the report should take the case");
    let (ledgers, ending, _) = drive_quietly(
        lb.far,
        lb.kernel,
        lb.probe,
        &mut case,
        Traffic {
            streams: &[(Side::Far, stream)],
            first_run: run,
            agents: &mut [],
            hold: Duration::ZERO,
            clock: Clock::start(),
        },
        QUIET,
    );
    super::harness::check_all_back(&mut case, &ledgers, ending);
    case.finish()
        .expect("the report should take the case's end");
}
