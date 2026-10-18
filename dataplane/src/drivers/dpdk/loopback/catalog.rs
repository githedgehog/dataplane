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
