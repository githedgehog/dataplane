// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Run a stand-in for `mstlink`: a script that prints a captured answer, or hangs.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use dataplane_mstlink::{Query, RunError, Runner};

/// Run `attempt` until it stops failing with "text file busy".
///
/// Tests run in parallel threads. A thread that forks while another still has its freshly written
/// script open for writing hands the child that descriptor until the child execs, and executing
/// the script meanwhile fails with `ETXTBSY`: a race in writing and running a script, not in
/// running `mstlink`.
async fn unbusy<T, F, Fut>(attempt: F) -> Result<T, RunError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, RunError>>,
{
    loop {
        match attempt().await {
            Err(RunError::Spawn(e)) if e.raw_os_error() == Some(ETXTBSY) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            result => return result,
        }
    }
}

/// Linux's errno for "text file busy".
const ETXTBSY: i32 = 26;

/// A script in a fresh directory that records its arguments and runs `body`.
fn stand_in(name: &str, body: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("mstlink-stand-in-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let args = dir.join("args");
    let script = dir.join("mstlink");
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho \"$@\" > '{}'\n{body}\n", args.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (script, args)
}

#[tokio::test]
async fn a_report_is_read_from_the_program() {
    let fixture = format!(
        "{}/tests/fixtures/qsfp112-400g/port.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let (script, args) = stand_in("report", &format!("cat '{fixture}'; exit 0"));
    let runner = Runner::default().program(&script);
    let report = unbusy(|| runner.port("0000:02:00.0")).await.unwrap();
    assert_eq!(report.operational.speed.as_deref(), Some("400G"));
    let asked = std::fs::read_to_string(args).unwrap();
    assert_eq!(asked.trim(), Query::Port.args("0000:02:00.0").join(" "));
}

#[tokio::test]
async fn a_failure_explained_on_stdout_is_reported_whatever_the_exit_status() {
    let fixture = format!(
        "{}/tests/fixtures/sfp-10g/fec-histogram.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let (script, _) = stand_in("failure", &format!("cat '{fixture}'; exit 1"));
    let runner = Runner::default().program(&script);
    let error = unbusy(|| runner.fec_histogram("0000:02:00.0"))
        .await
        .unwrap_err();
    assert!(matches!(error, RunError::Parse(_)), "{error:?}");
}

#[tokio::test]
async fn a_hung_run_is_killed() {
    let (script, _) = stand_in("hang", "exec sleep 30");
    let started = std::time::Instant::now();
    let runner = Runner::default()
        .program(&script)
        .timeout(Duration::from_millis(200));
    let error = unbusy(|| runner.pcie("0000:02:00.0")).await.unwrap_err();
    assert!(matches!(error, RunError::Timeout(_)), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn a_missing_program_says_so() {
    let error = Runner::default()
        .program("/nonexistent/mstlink")
        .port("0000:02:00.0")
        .await
        .unwrap_err();
    let RunError::Spawn(error) = error else {
        panic!("{error:?}")
    };
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}
