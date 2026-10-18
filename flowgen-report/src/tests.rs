// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bolero::TypeGenerator;

use crate::{
    Bound, Build, Environment, Evidence, Header, ReadError, Report, Sample, Status, Tally, read,
};

fn header() -> Header {
    Header::new(
        Build {
            name: "test".to_string(),
            version: "0".to_string(),
            commit: None,
        },
        Environment::default(),
        serde_json::json!({"flows": 1}),
    )
}

/// One thing a run's writer might do.
#[derive(Debug, Clone, Copy, TypeGenerator)]
enum Op {
    /// End the open case, if any, and begin another.
    Begin,
    /// Sample counter `path % 4` at `total`.
    Sample { path: u8, total: u64 },
    /// Check a counter against a bound it is or is not within, or one never measured.
    Counter { observed: Option<u8>, max: u8 },
    /// Check a condition.
    Condition { holds: bool, evidence: u8 },
    /// End the open case, explicitly rather than by dropping it.
    Finish,
}

/// What the ops should come to, worked out without the writer or the reader.
#[derive(Default)]
struct Expected {
    cases: Vec<(Tally, Vec<Sample>)>,
}

/// Write `ops` as a run, and work out what reading it back should give.
fn write(ops: &[Op]) -> (Vec<u8>, Expected) {
    let mut out = Vec::new();
    let mut expected = Expected::default();
    let mut report = Report::new(&mut out, header()).unwrap();
    let mut checks = 0usize;
    // Ops before the first `Begin` have no case to go to.
    for segment in ops.split(|op| matches!(op, Op::Begin)).skip(1) {
        let name = format!("case-{}", expected.cases.len());
        let mut case = report.case(name, serde_json::json!({})).unwrap();
        expected.cases.push(Default::default());
        let (tally, samples) = expected.cases.last_mut().unwrap();
        for op in segment {
            match *op {
                Op::Begin => unreachable!("segments are split on `Begin`"),
                Op::Finish => break,
                Op::Sample { path, total } => {
                    let sample = Sample::new().counter(format!("path.{}", path % 4), total);
                    case.sample(sample.clone()).unwrap();
                    samples.push(sample);
                }
                Op::Counter { observed, max } => {
                    let status = match observed {
                        Some(n) if n <= max => Status::Pass,
                        Some(_) => Status::Fail,
                        None => Status::Error,
                    };
                    checks += 1;
                    let got = case
                        .expect_counter(
                            format!("check-{checks}"),
                            "path.0",
                            Bound::at_most(u64::from(max)),
                            observed.map(u64::from),
                            vec![],
                        )
                        .unwrap();
                    assert_eq!(got, status);
                    tally.count(status);
                }
                Op::Condition { holds, evidence } => {
                    checks += 1;
                    let evidence = (0..evidence % 40)
                        .map(|n| Evidence::frame(format!("frame {n}"), &[n, 0xff]))
                        .collect();
                    case.expect(format!("check-{checks}"), "it holds", holds, evidence)
                        .unwrap();
                    tally.count(if holds { Status::Pass } else { Status::Fail });
                }
            }
        }
        // Finished or merely dropped, a case ends as its checks came out.
        if segment.iter().any(|op| matches!(op, Op::Finish)) {
            case.finish().unwrap();
        }
    }
    report.finish().unwrap();
    (out, expected)
}

/// Whatever a run writes reads back as it was written: every sample, every check, and each
/// case's and the run's outcome as the worst of what they hold.
#[test]
fn a_report_reads_back_as_it_was_written() {
    bolero::check!()
        .with_type::<Vec<Op>>()
        .for_each(|ops: &Vec<Op>| {
            let (bytes, expected) = write(ops);
            let run = read(bytes.as_slice()).unwrap();

            assert_eq!(run.cases.len(), expected.cases.len());
            let mut total = Tally::default();
            let mut worst = Status::Pass;
            for (case, (tally, samples)) in run.cases.iter().zip(&expected.cases) {
                let end = case.end.as_ref().expect("every case ends");
                assert_eq!(end.checks, *tally);
                assert_eq!(case.status(), tally.status());
                let written: Vec<_> = case.samples.iter().map(|s| s.counters.clone()).collect();
                let meant: Vec<_> = samples.iter().map(|s| s.counters.clone()).collect();
                assert_eq!(written, meant);
                for check in &case.checks {
                    assert!(check.evidence.len() <= crate::record::MAX_EVIDENCE);
                }
                total.pass += tally.pass;
                total.fail += tally.fail;
                total.error += tally.error;
                worst = worst.max(tally.status());
            }
            assert_eq!(run.end.as_ref().map(|end| end.checks), Some(total));
            assert_eq!(run.status(), worst);
        });
}

/// A report cut off anywhere -- the writer killed partway through -- still reads, as a run that
/// crashed, unless not even its header survived or nothing but the final newline is missing.
#[test]
fn a_report_cut_short_reads_as_a_crash() {
    bolero::check!()
        .with_type::<(Vec<Op>, u16)>()
        .for_each(|(ops, cut): &(Vec<Op>, u16)| {
            let (bytes, _) = write(ops);
            let cut = usize::from(*cut) % bytes.len();
            // A record survives a cut that leaves all of it but its newline.
            let header_end = bytes.iter().position(|&b| b == b'\n').unwrap();
            match read(&bytes[..cut]) {
                Ok(run) => {
                    assert!(cut >= header_end, "read a header that was cut short");
                    if cut == bytes.len() - 1 {
                        // Only the last newline is gone; the end record is whole.
                        assert_eq!(run.status(), read(bytes.as_slice()).unwrap().status());
                    } else {
                        assert_eq!(run.status(), Status::Crashed);
                    }
                }
                Err(ReadError::NoHeader) => assert!(cut < header_end),
                Err(e) => panic!("a report cut at {cut} of {} did not read: {e}", bytes.len()),
            }
        });
}

#[test]
fn evidence_past_the_cap_is_counted_not_kept() {
    let mut out = Vec::new();
    let mut report = Report::new(&mut out, header()).unwrap();
    let mut case = report.case("c", serde_json::json!({})).unwrap();
    let evidence = (0..40).map(|n| Evidence::text(format!("{n}"))).collect();
    case.expect("lots", "it holds", false, evidence).unwrap();
    case.finish().unwrap();
    report.finish().unwrap();

    let run = read(out.as_slice()).unwrap();
    let check = &run.case("c").unwrap().checks[0];
    assert_eq!(check.evidence.len(), crate::record::MAX_EVIDENCE);
    assert_eq!(
        check.evidence_dropped,
        40 - crate::record::MAX_EVIDENCE as u64
    );
}

/// A panic partway through a case leaves the case and the run crashed, with what came before.
#[test]
fn a_panic_leaves_a_crashed_run() {
    let mut out = Vec::new();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut report = Report::new(&mut out, header()).unwrap();
        let mut case = report.case("c", serde_json::json!({})).unwrap();
        case.sample(Sample::new().counter("port.p.rx_packets", 7))
            .unwrap();
        panic!("the dataplane fell over");
    }));
    assert!(panicked.is_err());

    let run = read(out.as_slice()).unwrap();
    assert_eq!(run.status(), Status::Crashed);
    assert_eq!(
        run.end.as_ref().unwrap().reason.as_deref(),
        Some("the run panicked")
    );
    let case = run.case("c").unwrap();
    assert_eq!(case.status(), Status::Crashed);
    assert_eq!(
        case.last_sample().unwrap().counters["port.p.rx_packets"],
        7,
        "what was measured before the panic is kept"
    );
}

#[test]
fn names_do_not_repeat() {
    let mut report = Report::new(Vec::new(), header()).unwrap();
    let mut case = report.case("c", serde_json::json!({})).unwrap();
    case.expect("x", "it holds", true, vec![]).unwrap();
    assert!(case.expect("x", "it holds", true, vec![]).is_err());
    case.finish().unwrap();
    assert!(report.case("c", serde_json::json!({})).is_err());
}

#[test]
fn records_out_of_place_are_refused() {
    let header = serde_json::to_string(&crate::Record::Header(header())).unwrap();
    let sample = r#"{"type":"sample","case":"nowhere","t_ns":0}"#;
    let input = format!("{header}\n{sample}\n");
    assert!(matches!(
        read(input.as_bytes()),
        Err(ReadError::OutOfPlace { line: 2, .. })
    ));

    let mut old = crate::Record::Header(self::header());
    if let crate::Record::Header(h) = &mut old {
        h.schema = crate::SCHEMA + 1;
    }
    let input = format!("{}\n", serde_json::to_string(&old).unwrap());
    assert!(matches!(
        read(input.as_bytes()),
        Err(ReadError::Schema { .. })
    ));

    let input = format!("{header}\nnot json\n{sample}\n");
    assert!(matches!(
        read(input.as_bytes()),
        Err(ReadError::Json { line: 2, .. })
    ));
}

#[test]
fn bounds_are_inclusive_and_open_where_unset() {
    assert!(Bound::exactly(3).admits(3));
    assert!(!Bound::exactly(3).admits(4));
    assert!(Bound::at_least(3).admits(u64::MAX));
    assert!(!Bound::at_least(3).admits(2));
    assert!(Bound::at_most(3).admits(0));
    assert!(Bound::default().admits(42));
}
