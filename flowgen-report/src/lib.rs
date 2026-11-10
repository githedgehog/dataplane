// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! The report a traffic-generation run leaves behind: what ran, what was measured, and what was
//! expected of it.
//!
//! A report is [JSON Lines]: one [`Record`] per line, appended as the run goes and flushed as each
//! is written. A run that crashes, hangs or is killed still leaves everything up to that point,
//! and a report without an [`End`] record is one whose run did not finish -- [`Run::status`] says
//! so rather than passing what it has.
//!
//! The records, in the order a run writes them:
//!
//! - one [`Header`]: the tool, the environment, the scenario as it ran, and the seed;
//! - per case (one point of a scenario, such as one flow count in a sweep): a [`CaseStart`], any
//!   number of [`Sample`]s and [`Check`]s, and a [`CaseEnd`];
//! - one [`End`].
//!
//! [`Report`] writes them and [`read`] reads them back into a [`Run`].
//!
//! # Counter paths
//!
//! Samples and checks name what they measure by a dotted path, so that anything reading a report
//! can tabulate and plot it without knowing what each counter means. The paths in use:
//!
//! | Path | Meaning |
//! |---|---|
//! | `port.<port>.<counter>` | the device's own counters (`rx_packets`, `rx_missed`, ...) |
//! | `worker.<worker>.<port>.<counter>` | a worker's counters for one of its ports |
//! | `done.<reason>` | packets the pipeline finished with, by reason |
//! | `punt.<port>.<channel>` | frames handed to the kernel, by channel |
//! | `generator.<stream>.<counter>` | what the generator sent and saw come back |
//!
//! Counters are cumulative: a sample holds totals since the case began, never deltas, so a missed
//! sample costs resolution and nothing else. Gauges (a table's size, say) are instantaneous.
//! Units are in the name: `_ns`, `_bytes`, `_pps`.
//!
//! [JSON Lines]: https://jsonlines.org/

mod read;
mod record;
mod write;

pub use read::{CaseRun, ReadError, Run, read};
pub use record::{
    Bound, Build, CaseEnd, CaseStart, Check, End, Environment, Evidence, Expectation, Header,
    MAX_EVIDENCE, Port, Record, SCHEMA, Sample, Status, Tally, Unsettled,
};
pub use write::{Case, Report};

#[cfg(test)]
mod tests;
