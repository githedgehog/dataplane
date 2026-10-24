// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reading a report back.

use std::io::{self, BufRead};

use crate::record::{CaseEnd, CaseStart, Check, End, Header, Record, SCHEMA, Sample, Status};

/// A report, read back.
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    /// What ran.
    pub header: Header,
    /// Its cases, in the order they began.
    pub cases: Vec<CaseRun>,
    /// How it ended; `None` if it never did.
    pub end: Option<End>,
}

/// One case of a report, read back.
#[derive(Debug, Clone, PartialEq)]
pub struct CaseRun {
    /// How it began.
    pub start: CaseStart,
    /// What it measured, in order.
    pub samples: Vec<Sample>,
    /// What was expected of it.
    pub checks: Vec<Check>,
    /// How it ended; `None` if it never did.
    pub end: Option<CaseEnd>,
}

impl Run {
    /// How the run came out; [`Status::Crashed`] if the report never says it ended.
    #[must_use]
    pub fn status(&self) -> Status {
        self.end.as_ref().map_or(Status::Crashed, |end| end.status)
    }

    /// The case named `name`.
    #[must_use]
    pub fn case(&self, name: &str) -> Option<&CaseRun> {
        self.cases.iter().find(|case| case.start.case == name)
    }
}

impl CaseRun {
    /// How the case came out; [`Status::Crashed`] if the report never says it ended.
    #[must_use]
    pub fn status(&self) -> Status {
        self.end.as_ref().map_or(Status::Crashed, |end| end.status)
    }

    /// The case's last sample, which holds its final totals.
    #[must_use]
    pub fn last_sample(&self) -> Option<&Sample> {
        self.samples.last()
    }
}

/// Why a report could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The report could not be read at all.
    #[error("could not read the report: {0}")]
    Io(#[from] io::Error),
    /// A line is not a record.
    #[error("line {line} is not a report record: {source}")]
    Json {
        /// The line, counting from 1.
        line: usize,
        /// What is wrong with it.
        #[source]
        source: serde_json::Error,
    },
    /// The report does not begin with a header.
    #[error("the report does not begin with a header")]
    NoHeader,
    /// The report is in a format this reader does not know.
    #[error("the report is schema {found}; this reader reads schema {SCHEMA}")]
    Schema {
        /// The report's schema.
        found: u32,
    },
    /// A record is out of place: a second header, a record for a case that never began or has
    /// ended, or anything after the end.
    #[error("line {line}: {what}")]
    OutOfPlace {
        /// The line, counting from 1.
        line: usize,
        /// What is out of place.
        what: String,
    },
}

/// Read a report.
///
/// A last line cut short -- the writer killed partway through it -- is ignored, as the report of
/// a run that never finished; anything else malformed is an error.
///
/// # Errors
///
/// If the report cannot be read, or is malformed: see [`ReadError`].
pub fn read(mut input: impl BufRead) -> Result<Run, ReadError> {
    let mut run: Option<Run> = None;
    let mut buf = String::new();
    let mut line = 0;
    loop {
        buf.clear();
        if input.read_line(&mut buf)? == 0 {
            break;
        }
        line += 1;
        let complete = buf.ends_with('\n');
        let text = buf.trim();
        if text.is_empty() {
            continue;
        }
        let record = match serde_json::from_str::<Record>(text) {
            Ok(record) => record,
            // A writer stopped mid-line leaves a last line without its newline.
            Err(_) if !complete => break,
            Err(source) => return Err(ReadError::Json { line, source }),
        };
        match run.as_mut() {
            None => run = Some(begin(record)?),
            Some(run) => place(run, record, line)?,
        }
    }
    run.ok_or(ReadError::NoHeader)
}

/// The run a report's first record begins.
fn begin(record: Record) -> Result<Run, ReadError> {
    let Record::Header(header) = record else {
        return Err(ReadError::NoHeader);
    };
    if header.schema != SCHEMA {
        return Err(ReadError::Schema {
            found: header.schema,
        });
    }
    Ok(Run {
        header,
        cases: Vec::new(),
        end: None,
    })
}

/// Add `record`, from line `line`, to `run`.
fn place(run: &mut Run, record: Record, line: usize) -> Result<(), ReadError> {
    let out_of_place = |what: String| ReadError::OutOfPlace { line, what };
    if run.end.is_some() {
        return Err(out_of_place("a record after the run's end".to_string()));
    }
    let open = |run: &mut Run, case: &str| -> Result<usize, ReadError> {
        match run.cases.iter().position(|c| c.start.case == case) {
            Some(at) if run.cases[at].end.is_none() => Ok(at),
            Some(_) => Err(out_of_place(format!(
                "a record for case {case:?}, which has ended"
            ))),
            None => Err(out_of_place(format!(
                "a record for case {case:?}, which never began"
            ))),
        }
    };
    match record {
        Record::Header(_) => return Err(out_of_place("a second header".to_string())),
        Record::CaseStart(start) => {
            if run.case(&start.case).is_some() {
                return Err(out_of_place(format!("case {:?} begun twice", start.case)));
            }
            run.cases.push(CaseRun {
                start,
                samples: Vec::new(),
                checks: Vec::new(),
                end: None,
            });
        }
        Record::Sample(sample) => {
            let at = open(run, &sample.case)?;
            run.cases[at].samples.push(sample);
        }
        Record::Check(check) => {
            let at = open(run, &check.case)?;
            run.cases[at].checks.push(check);
        }
        Record::CaseEnd(end) => {
            let at = open(run, &end.case)?;
            run.cases[at].end = Some(end);
        }
        Record::End(end) => run.end = Some(end),
    }
    Ok(())
}
