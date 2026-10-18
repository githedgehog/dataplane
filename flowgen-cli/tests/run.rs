// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The `flowgen` binary, run as it would be: on the example loopback scenarios, and on one whose
//! expectations cannot be met.

use std::path::{Path, PathBuf};
use std::process::Command;

use flowgen_report::Status;

/// Run `flowgen run` on `scenario` with a hugepage-free EAL; its exit code and its report.
fn run(scenario: &Path, report: &Path) -> (i32, flowgen_report::Run) {
    let status = Command::new(
        std::env::var_os("NEXTEST_BIN_EXE_flowgen")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_flowgen").into()),
    )
    .args(["run"])
    .arg(scenario)
    .arg("--report")
    .arg(report)
    .args(["--eal=--no-huge", "--eal=-m", "--eal=512"])
    .status()
    .expect("flowgen should start");
    let file = std::fs::File::open(report).expect("flowgen should leave a report");
    let read = flowgen_report::read(std::io::BufReader::new(file)).expect("the report should read");
    (status.code().unwrap_or(-1), read)
}

fn example(name: &str) -> PathBuf {
    Path::new(
        &std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string()),
    )
    .join("scenarios")
    .join(name)
}

fn report_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("flowgen-{}-{name}.jsonl", std::process::id()))
}

#[test]
fn the_loopback_scenario_passes() {
    let (code, run) = run(&example("loopback.yaml"), &report_path("loopback"));
    assert_eq!(run.status(), Status::Pass, "{run:#?}");
    assert_eq!(code, 0);
}

#[test]
fn the_agents_hold_their_sessions_on_a_loop() {
    let (code, run) = run(&example("loopback-agents.yaml"), &report_path("agents"));
    let failed: Vec<_> = run
        .cases
        .iter()
        .flat_map(|case| &case.checks)
        .filter(|check| check.status != Status::Pass)
        .collect();
    assert!(failed.is_empty(), "{failed:#?}");
    assert_eq!(code, 0);
}

#[test]
fn an_unmet_expectation_fails_the_run() {
    let text = std::fs::read_to_string(example("loopback.yaml"))
        .unwrap()
        .replace(
            "path: generator.flows.lost, exactly: 0",
            "path: generator.flows.lost, exactly: 1",
        );
    let scenario = report_path("unmet-scenario").with_extension("yaml");
    std::fs::write(&scenario, text).unwrap();
    let (code, run) = run(&scenario, &report_path("unmet"));
    assert_eq!(run.status(), Status::Fail);
    assert_eq!(code, 1);
}
