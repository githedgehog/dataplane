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

//! `flowgen`: run a traffic-generation scenario against a gateway on a real (or virtual) port, and
//! leave a report of what happened.
//!
//! ```text
//! flowgen run scenario.yaml --report run.jsonl [--eal ARG]...
//! flowgen check scenario.yaml
//! ```
//!
//! The exit status is the report's verdict: 0 if every check passed, 1 if any failed, 2 if any
//! could not be judged or the run crashed, 3 if the run could not start.

mod run;
mod scenario;
mod scrape;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use flowgen_report::Status;

use crate::scenario::Scenario;

/// Run traffic-generation scenarios against a gateway.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a scenario and write its report.
    Run {
        /// The scenario, as YAML.
        scenario: PathBuf,
        /// Where to write the report (JSON Lines).
        #[arg(long, default_value = "flowgen-report.jsonl")]
        report: PathBuf,
        /// More EAL arguments, after the scenario's; repeat for each.
        #[arg(long = "eal", allow_hyphen_values = true)]
        eal: Vec<String>,
    },
    /// Check a scenario, and print it as it would run, defaults filled in.
    Check {
        /// The scenario, as YAML.
        scenario: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check { scenario } => match Scenario::load(&scenario) {
            Ok(scenario) => match scenario.to_yaml() {
                Ok(text) => {
                    print!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("flowgen: {e}");
                    ExitCode::from(3)
                }
            },
            Err(e) => {
                eprintln!("flowgen: {e}");
                ExitCode::from(3)
            }
        },
        Command::Run {
            scenario,
            report,
            eal,
        } => {
            let loaded = match Scenario::load(&scenario) {
                Ok(loaded) => loaded,
                Err(e) => {
                    eprintln!("flowgen: {e}");
                    return ExitCode::from(3);
                }
            };
            match run::run(&loaded, &report, &eal) {
                Ok(status) => {
                    eprintln!("flowgen: {status:?}; the report is {}", report.display());
                    ExitCode::from(match status {
                        Status::Pass => 0,
                        Status::Fail => 1,
                        Status::Error | Status::Crashed => 2,
                    })
                }
                Err(e) => {
                    eprintln!("flowgen: {e}");
                    ExitCode::from(3)
                }
            }
        }
    }
}
