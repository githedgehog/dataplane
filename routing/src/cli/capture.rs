// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! CLI handling for packet capture.

use crate::routingdb::RoutingDb;
use capture::{CaptureDirectory, CaptureNames, CaptureRequest, CaptureStatus, Directions};
use cli::cliproto::{CaptureDirection, CliAction, CliError, CliRequest, CliResponse};
use concurrency::sync::Arc;
use config::ValidatedGwConfig;
use net::packet::VpcDiscriminant;
use std::fmt::Write;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::time::Duration;

const DEFAULT_PACKETS: NonZeroU64 = NonZeroU64::new(10_000).unwrap();
const DEFAULT_SECONDS: u32 = 60;
const DEFAULT_SAMPLE: NonZeroU32 = NonZeroU32::MIN;
/// Records waiting for the writer before further ones are dropped; about 1.5 MB at the record's size.
const QUEUE_DEPTH: NonZeroUsize = NonZeroUsize::new(4096).unwrap();

/// Handle a capture request (`capture start`, `capture stop`, `show capture`).
pub(crate) fn handle(
    request: CliRequest,
    db: &RoutingDb,
    gwconfig: Option<&Arc<ValidatedGwConfig>>,
    captures: Option<&CaptureDirectory>,
) -> Result<CliResponse, CliError> {
    let Some(captures) = captures else {
        return Err(CliError::NotSupported(
            "packet capture is not available".to_owned(),
        ));
    };
    let output = match request.action {
        CliAction::CaptureStart => start(&request, db, gwconfig, captures)?,
        CliAction::CaptureStop => match captures.stop() {
            Some((report, path)) => format!("\n {report}\n file: {}", path.display()),
            None => "\n no capture is running".to_owned(),
        },
        CliAction::ShowCapture => status(captures),
        _ => unreachable!("only capture actions are routed here"),
    };
    Ok(CliResponse::from_request_ok(request, output))
}

fn start(
    request: &CliRequest,
    db: &RoutingDb,
    gwconfig: Option<&Arc<ValidatedGwConfig>>,
    captures: &CaptureDirectory,
) -> Result<String, CliError> {
    let args = &request.args;
    // The CLI client rejects zeroes; these guard against a client that does not.
    let positive = |what: &str| CliError::Capture(format!("{what} must be at least 1"));
    let directions = match args.capture_direction.unwrap_or(CaptureDirection::Both) {
        CaptureDirection::Ingress => Directions::Ingress,
        CaptureDirection::Egress => Directions::Egress,
        CaptureDirection::Both => Directions::Both,
    };
    let packets = match args.capture_packets {
        Some(packets) => NonZeroU64::new(packets).ok_or_else(|| positive("packets"))?,
        None => DEFAULT_PACKETS,
    };
    let seconds = match args.capture_seconds {
        Some(0) => return Err(positive("seconds")),
        Some(seconds) => seconds,
        None => DEFAULT_SECONDS,
    };
    let sample_one_in = match args.capture_sample {
        Some(sample) => NonZeroU32::new(sample).ok_or_else(|| positive("sample"))?,
        None => DEFAULT_SAMPLE,
    };
    let capture = CaptureRequest {
        directions,
        sample_one_in,
        packets,
        duration: Duration::from_secs(u64::from(seconds)),
        queue_depth: QUEUE_DEPTH,
    };
    let path = captures
        .start(capture, names(db, gwconfig))
        .map_err(|error| CliError::Capture(error.to_string()))?;
    Ok(format!(
        "\n capturing {directions:?} traffic, one packet in {sample_one_in}, \
         until {packets} packets or {seconds}s\n file: {}",
        path.display()
    ))
}

/// Names for the interfaces the router knows and the VPCs the applied config defines.
fn names(db: &RoutingDb, gwconfig: Option<&Arc<ValidatedGwConfig>>) -> CaptureNames {
    let mut names = CaptureNames::default();
    if let Some(iftable) = db.iftw.enter() {
        for interface in iftable.values() {
            names = names.with_interface(interface.ifindex, interface.name.to_string());
        }
    }
    if let Some(config) = gwconfig {
        for vpc in config.external().overlay().vpc_table().values() {
            names = names.with_vpc(VpcDiscriminant::VNI(vpc.vni()), vpc.name());
        }
    }
    names
}

fn status(captures: &CaptureDirectory) -> String {
    let (status, path) = captures.status();
    let mut out = String::from("\n ");
    let _ = match status {
        CaptureStatus::Idle => write!(out, "no capture has run"),
        CaptureStatus::Running { admitted, dropped } => {
            write!(
                out,
                "capture running: admitted={admitted} dropped={dropped}"
            )
        }
        CaptureStatus::Finished(report) => write!(out, "{report}"),
    };
    if let Some(path) = path {
        let _ = write!(out, "\n file: {}", path.display());
    }
    let _ = write!(out, "\n directory: {}", captures.dir().display());
    out
}
