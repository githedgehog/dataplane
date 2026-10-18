// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Writing a report as a run goes.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::Instant;

use crate::record::{
    Bound, CaseEnd, CaseStart, Check, End, Evidence, Expectation, Header, MAX_EVIDENCE, Record,
    Sample, Status, Tally, Unsettled,
};

/// A report being written.
///
/// Every record is flushed as it is written, so whatever stops the run leaves the report readable
/// up to that point. A report dropped unfinished -- by a panic, say -- ends itself with
/// [`Status::Crashed`].
pub struct Report<W: Write> {
    /// Where records go; `None` once the run has ended.
    out: Option<W>,
    started: Instant,
    /// Every case's checks.
    checks: Tally,
    /// The worst way any case came out.
    worst: Status,
    /// Every case's name, which must not repeat.
    cases: BTreeSet<String>,
}

impl Report<BufWriter<File>> {
    /// Start a report in a new file at `path`, overwriting any there.
    ///
    /// # Errors
    ///
    /// If the file cannot be created or the header written.
    pub fn create(path: impl AsRef<Path>, header: Header) -> io::Result<Self> {
        Report::new(BufWriter::new(File::create(path)?), header)
    }
}

impl<W: Write> Report<W> {
    /// Start a report written to `out`, beginning with `header`.
    ///
    /// # Errors
    ///
    /// If the header cannot be written.
    pub fn new(out: W, header: Header) -> io::Result<Self> {
        let mut report = Report {
            out: Some(out),
            started: clock::now(),
            checks: Tally::default(),
            worst: Status::Pass,
            cases: BTreeSet::new(),
        };
        report.write(&Record::Header(header))?;
        Ok(report)
    }

    /// Begin a case named `name`, distinguished from the run's others by `params`.
    ///
    /// # Errors
    ///
    /// If a case of that name was already begun, or the record cannot be written.
    pub fn case(
        &mut self,
        name: impl Into<String>,
        params: serde_json::Value,
    ) -> io::Result<Case<'_, W>> {
        let name = name.into();
        if !self.cases.insert(name.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a case named {name:?} was already begun"),
            ));
        }
        let t_ns = self.now();
        self.write(&Record::CaseStart(CaseStart {
            case: name.clone(),
            params,
            t_ns,
        }))?;
        Ok(Case {
            report: self,
            name,
            checks: Tally::default(),
            ids: BTreeSet::new(),
            ended: false,
        })
    }

    /// End the run, and say how it came out: the worst of its cases.
    ///
    /// # Errors
    ///
    /// If the record cannot be written.
    pub fn finish(mut self) -> io::Result<Status> {
        let status = self.worst;
        self.end(status, None)?;
        Ok(status)
    }

    /// Nanoseconds since the run started.
    fn now(&self) -> u64 {
        u64::try_from(clock::elapsed(self.started).as_nanos()).unwrap_or(u64::MAX)
    }

    /// Write the [`End`] record and stop writing.
    fn end(&mut self, status: Status, reason: Option<String>) -> io::Result<()> {
        let record = Record::End(End {
            status,
            checks: self.checks,
            t_ns: self.now(),
            reason,
        });
        let written = self.write(&record);
        self.out = None;
        written
    }

    /// Write `record` as one line, and flush it.
    fn write(&mut self, record: &Record) -> io::Result<()> {
        let Some(out) = self.out.as_mut() else {
            return Err(io::Error::other("the run has already ended"));
        };
        serde_json::to_writer(&mut *out, record)?;
        out.write_all(b"\n")?;
        out.flush()
    }
}

impl<W: Write> Drop for Report<W> {
    fn drop(&mut self) {
        if self.out.is_some() {
            let reason = if std::thread::panicking() {
                "the run panicked"
            } else {
                "the report was dropped without being finished"
            };
            // Nothing is left to report a failure to.
            let _ = self.end(Status::Crashed, Some(reason.to_string()));
        }
    }
}

/// A case being written.
///
/// A case dropped unfinished ends itself: with [`Status::Crashed`] if a panic is dropping it, as
/// its checks came out otherwise.
pub struct Case<'r, W: Write> {
    report: &'r mut Report<W>,
    name: String,
    checks: Tally,
    /// Every check's id, which must not repeat within the case.
    ids: BTreeSet<String>,
    ended: bool,
}

impl<W: Write> Case<'_, W> {
    /// Record what the case has measured so far.
    ///
    /// # Errors
    ///
    /// If the record cannot be written.
    pub fn sample(&mut self, mut sample: Sample) -> io::Result<()> {
        sample.case.clone_from(&self.name);
        sample.t_ns = self.report.now();
        self.report.write(&Record::Sample(sample))
    }

    /// Check that the counter at `path` ended within `bound`, given that it was `observed`; a
    /// counter never measured cannot be judged, and is an [`Status::Error`].
    ///
    /// # Errors
    ///
    /// If the id was already used in this case, or the record cannot be written.
    pub fn expect_counter(
        &mut self,
        id: impl Into<String>,
        path: impl Into<String>,
        bound: Bound,
        observed: Option<u64>,
        evidence: Vec<Evidence>,
    ) -> io::Result<Status> {
        let status = match observed {
            Some(n) if bound.admits(n) => Status::Pass,
            Some(_) => Status::Fail,
            None => Status::Error,
        };
        let expected = Expectation::Counter {
            path: path.into(),
            bound,
        };
        self.check(id.into(), expected, observed, status, evidence, None)
    }

    /// As [`expect_counter`](Self::expect_counter), for an expectation not yet settled, for the
    /// reason `why`: recorded as [`Status::Skip`], with whether it held, and judged no further.
    /// A counter never measured is still an [`Status::Error`]: nothing was learned.
    ///
    /// # Errors
    ///
    /// If the id was already used in this case, or the record cannot be written.
    pub fn unsettled_counter(
        &mut self,
        id: impl Into<String>,
        path: impl Into<String>,
        bound: Bound,
        observed: Option<u64>,
        why: impl Into<String>,
        evidence: Vec<Evidence>,
    ) -> io::Result<Status> {
        let (status, unsettled) = match observed {
            Some(n) => (
                Status::Skip,
                Some(Unsettled {
                    why: why.into(),
                    held: bound.admits(n),
                }),
            ),
            None => (Status::Error, None),
        };
        let expected = Expectation::Counter {
            path: path.into(),
            bound,
        };
        self.check(id.into(), expected, observed, status, evidence, unsettled)
    }

    /// Check that what `description` says `holds`.
    ///
    /// # Errors
    ///
    /// If the id was already used in this case, or the record cannot be written.
    pub fn expect(
        &mut self,
        id: impl Into<String>,
        description: impl Into<String>,
        holds: bool,
        evidence: Vec<Evidence>,
    ) -> io::Result<Status> {
        let status = if holds { Status::Pass } else { Status::Fail };
        let expected = Expectation::Condition {
            description: description.into(),
        };
        self.check(id.into(), expected, None, status, evidence, None)
    }

    /// As [`expect`](Self::expect), for an expectation not yet settled, for the reason `why`:
    /// recorded as [`Status::Skip`], with whether it held, and judged no further.
    ///
    /// # Errors
    ///
    /// If the id was already used in this case, or the record cannot be written.
    pub fn unsettled(
        &mut self,
        id: impl Into<String>,
        description: impl Into<String>,
        holds: bool,
        why: impl Into<String>,
        evidence: Vec<Evidence>,
    ) -> io::Result<Status> {
        let expected = Expectation::Condition {
            description: description.into(),
        };
        let unsettled = Unsettled {
            why: why.into(),
            held: holds,
        };
        self.check(
            id.into(),
            expected,
            None,
            Status::Skip,
            evidence,
            Some(unsettled),
        )
    }

    /// End the case, and say how it came out: the worst of its checks.
    ///
    /// # Errors
    ///
    /// If the record cannot be written.
    pub fn finish(mut self) -> io::Result<Status> {
        let status = self.checks.status();
        self.end(status)?;
        Ok(status)
    }

    fn check(
        &mut self,
        id: String,
        expected: Expectation,
        observed: Option<u64>,
        status: Status,
        mut evidence: Vec<Evidence>,
        unsettled: Option<Unsettled>,
    ) -> io::Result<Status> {
        if !self.ids.insert(id.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("case {:?} already has a check named {id:?}", self.name),
            ));
        }
        let evidence_dropped = evidence.len().saturating_sub(MAX_EVIDENCE) as u64;
        evidence.truncate(MAX_EVIDENCE);
        self.checks.count(status);
        self.report.checks.count(status);
        self.report.write(&Record::Check(Check {
            case: self.name.clone(),
            id,
            expected,
            observed,
            status,
            evidence,
            evidence_dropped,
            unsettled,
        }))?;
        Ok(status)
    }

    fn end(&mut self, status: Status) -> io::Result<()> {
        self.ended = true;
        self.report.worst = self.report.worst.max(status);
        let t_ns = self.report.now();
        self.report.write(&Record::CaseEnd(CaseEnd {
            case: self.name.clone(),
            status,
            checks: self.checks,
            t_ns,
        }))
    }
}

impl<W: Write> Drop for Case<'_, W> {
    fn drop(&mut self) {
        if !self.ended {
            let status = if std::thread::panicking() {
                Status::Crashed
            } else {
                self.checks.status()
            };
            // Nothing is left to report a failure to; the run's end will say it crashed.
            let _ = self.end(status);
        }
    }
}
