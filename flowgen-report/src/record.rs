// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The records a report is made of.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

/// The version of the record format this crate writes and reads.
///
/// Raised for any change a reader of the previous version would misread; additions that a reader
/// can ignore do not raise it.
pub const SCHEMA: u32 = 2;

/// The most evidence one check keeps. More is counted in [`Check::evidence_dropped`] and not kept,
/// so that a run dropping a million packets does not leave a million-line report.
pub const MAX_EVIDENCE: usize = 16;

/// One line of a report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Record {
    /// What ran. Always the first record.
    Header(Header),
    /// A case begins.
    CaseStart(CaseStart),
    /// What a case measured, so far.
    Sample(Sample),
    /// What a case was expected to do, and whether it did.
    Check(Check),
    /// A case is over.
    CaseEnd(CaseEnd),
    /// The run is over. Always the last record of a run that finished.
    End(End),
}

/// What ran, where, and with what.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Header {
    /// The record format, [`SCHEMA`] when written by this crate.
    pub schema: u32,
    /// The tool that wrote the report.
    pub tool: Build,
    /// The dataplane under test, if the tool knows which.
    pub dataplane: Option<Build>,
    /// Where it ran.
    pub environment: Environment,
    /// The scenario, as it ran: whatever was asked for, with every default filled in.
    pub scenario: serde_json::Value,
    /// The seed every random choice in the run derives from, so that it can be replayed.
    pub seed: Option<u64>,
    /// When the run started, in milliseconds since the Unix epoch.
    pub started_unix_ms: u64,
}

impl Header {
    /// A header for a run starting now, of the current [`SCHEMA`].
    #[must_use]
    pub fn new(tool: Build, environment: Environment, scenario: serde_json::Value) -> Header {
        let started_unix_ms = clock::system_now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        Header {
            schema: SCHEMA,
            tool,
            dataplane: None,
            environment,
            scenario,
            seed: None,
            started_unix_ms,
        }
    }
}

/// A program, and the source it was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Build {
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// The commit it was built from, if known.
    pub commit: Option<String>,
}

/// Where a run ran: enough to tell whether two runs' numbers can be compared.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Environment {
    /// The host's name.
    pub host: Option<String>,
    /// CPUs the run could use.
    pub cpus: Option<usize>,
    /// Data workers.
    pub workers: Option<u16>,
    /// The ports traffic crossed.
    pub ports: Vec<Port>,
    /// The arguments the EAL was started with.
    pub eal_args: Vec<String>,
}

/// One port traffic crossed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    /// The name counters are reported under (`port.<name>.*`).
    pub name: String,
    /// The PMD driving it, such as `net_ring` or `mlx5_pci`.
    pub driver: Option<String>,
    /// The device: a bus address, or the name of a virtual device.
    pub device: Option<String>,
}

/// A case begins.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseStart {
    /// The case's name, unique within the run.
    pub case: String,
    /// What distinguishes this case from the run's others: the sweep's values at this point.
    pub params: serde_json::Value,
    /// When it began, in nanoseconds since the run started.
    pub t_ns: u64,
}

/// What a case measured, from its start until [`Sample::t_ns`].
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Sample {
    /// The case.
    pub case: String,
    /// When, in nanoseconds since the run started.
    pub t_ns: u64,
    /// Totals since the case began, by path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counters: BTreeMap<String, u64>,
    /// Values at this instant, by path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gauges: BTreeMap<String, u64>,
}

impl Sample {
    /// An empty sample; the case and time are filled in when it is written.
    #[must_use]
    pub fn new() -> Sample {
        Sample::default()
    }

    /// With the counter at `path` at `total`.
    #[must_use]
    pub fn counter(mut self, path: impl Into<String>, total: u64) -> Sample {
        self.counters.insert(path.into(), total);
        self
    }

    /// With the gauge at `path` at `value`.
    #[must_use]
    pub fn gauge(mut self, path: impl Into<String>, value: u64) -> Sample {
        self.gauges.insert(path.into(), value);
        self
    }

    /// With every counter and gauge of `other` too; `other`'s win where both have one.
    #[must_use]
    pub fn merge(mut self, other: Sample) -> Sample {
        self.counters.extend(other.counters);
        self.gauges.extend(other.gauges);
        self
    }

    /// Counters since `baseline` was taken: each less its value there, or as it is if `baseline`
    /// has none. Gauges are instantaneous and left as they are.
    #[must_use]
    pub fn since(mut self, baseline: &Sample) -> Sample {
        for (path, total) in &mut self.counters {
            if let Some(before) = baseline.counters.get(path) {
                *total = total.saturating_sub(*before);
            }
        }
        self
    }
}

/// How a check, a case or a run came out, from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// As expected.
    Pass,
    /// Not judged: what to expect is not yet settled. What happened is recorded, in
    /// [`Check::unsettled`], and a case or run is not the worse for it.
    Skip,
    /// Not as expected.
    Fail,
    /// Could not be judged: what was to be checked was never measured.
    Error,
    /// Stopped before it finished.
    Crashed,
}

/// What a case was expected to do, and whether it did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Check {
    /// The case.
    pub case: String,
    /// The check's name, unique within the case.
    pub id: String,
    /// What was expected.
    pub expected: Expectation,
    /// The value it was judged on, for a counter.
    pub observed: Option<u64>,
    /// How it came out.
    pub status: Status,
    /// What shows why, when it failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Evidence beyond [`MAX_EVIDENCE`], counted and not kept.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub evidence_dropped: u64,
    /// Why the check was not judged, if it is [`Status::Skip`], and how it would have come out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsettled: Option<Unsettled>,
}

/// An expectation not yet settled: why, and whether what happened met it as it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unsettled {
    /// What is unsettled about it.
    pub why: String,
    /// Whether what happened met the expectation as written.
    pub held: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's `skip_serializing_if` passes a reference
fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// What a check expected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expectation {
    /// The counter at `path` ends the case within `bound`.
    Counter {
        /// The counter.
        path: String,
        /// Where it should be.
        bound: Bound,
    },
    /// Something judged in code, which the report describes rather than models.
    Condition {
        /// What should hold.
        description: String,
    },
}

/// An inclusive range, open where a limit is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Bound {
    /// The least allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u64>,
    /// The most allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
}

impl Bound {
    /// Exactly `n`.
    #[must_use]
    pub fn exactly(n: u64) -> Bound {
        Bound {
            min: Some(n),
            max: Some(n),
        }
    }

    /// At least `n`.
    #[must_use]
    pub fn at_least(n: u64) -> Bound {
        Bound {
            min: Some(n),
            max: None,
        }
    }

    /// At most `n`.
    #[must_use]
    pub fn at_most(n: u64) -> Bound {
        Bound {
            min: None,
            max: Some(n),
        }
    }

    /// Whether `n` is within the bound.
    #[must_use]
    pub fn admits(&self, n: u64) -> bool {
        self.min.is_none_or(|min| n >= min) && self.max.is_none_or(|max| n <= max)
    }
}

/// Something that shows why a check failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// A frame.
    Frame {
        /// What it is, in a line.
        summary: String,
        /// The whole frame, as lowercase hex.
        hex: String,
        /// The generator's flow it belongs to, if it carried a signature.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flow: Option<u64>,
        /// Its sequence number in that flow.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<u64>,
    },
    /// Anything else, as text: a log line, a backtrace, a table's contents.
    Text {
        /// The text.
        text: String,
    },
}

impl Evidence {
    /// The frame `bytes`, described by `summary`.
    #[must_use]
    pub fn frame(summary: impl Into<String>, bytes: &[u8]) -> Evidence {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            // Writing to a `String` cannot fail.
            let _ = write!(hex, "{byte:02x}");
        }
        Evidence::Frame {
            summary: summary.into(),
            hex,
            flow: None,
            seq: None,
        }
    }

    /// `text`.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Evidence {
        Evidence::Text { text: text.into() }
    }
}

/// How many checks came out each way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Tally {
    /// Passed.
    pub pass: u64,
    /// Not judged: unsettled.
    #[serde(default)]
    pub skip: u64,
    /// Failed.
    pub fail: u64,
    /// Could not be judged.
    pub error: u64,
}

impl Tally {
    /// Count one check that came out `status`.
    pub fn count(&mut self, status: Status) {
        match status {
            Status::Pass => self.pass += 1,
            Status::Skip => self.skip += 1,
            Status::Fail => self.fail += 1,
            Status::Error | Status::Crashed => self.error += 1,
        }
    }

    /// The worst way any counted check came out, unsettled ones aside; [`Status::Pass`] if none
    /// was counted.
    #[must_use]
    pub fn status(&self) -> Status {
        if self.error > 0 {
            Status::Error
        } else if self.fail > 0 {
            Status::Fail
        } else {
            Status::Pass
        }
    }
}

/// A case is over.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseEnd {
    /// The case.
    pub case: String,
    /// How it came out: the worst of its checks, or [`Status::Crashed`] if it did not finish.
    pub status: Status,
    /// Its checks.
    pub checks: Tally,
    /// When it ended, in nanoseconds since the run started.
    pub t_ns: u64,
}

/// The run is over.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct End {
    /// How it came out: the worst of its cases, or [`Status::Crashed`] if it did not finish.
    pub status: Status,
    /// Every case's checks.
    pub checks: Tally,
    /// How long it ran, in nanoseconds.
    pub t_ns: u64,
    /// Why it crashed, if it did and the reason is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
