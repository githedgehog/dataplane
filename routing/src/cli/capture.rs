// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! CLI handling for packet capture.

use crate::routingdb::RoutingDb;
use capture::{
    CaptureDirectory, CaptureFilter, CaptureNames, CaptureRequest, CaptureStatus, CaptureTarget,
    VpcMatch,
};
use cli::cliproto::{CaptureVpc, CliAction, CliError, CliRequest, CliResponse};
use concurrency::sync::Arc;
use config::ValidatedGwConfig;
use net::packet::VpcDiscriminant;
use net::vxlan::Vni;
use std::fmt::Write;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::time::Duration;

const DEFAULT_PACKETS: NonZeroU64 = NonZeroU64::new(10_000).unwrap();
const DEFAULT_SECONDS: u32 = 60;
const DEFAULT_SAMPLE: NonZeroU32 = NonZeroU32::MIN;
/// Records waiting for the writer before further ones are dropped.
const QUEUE_DEPTH: NonZeroUsize = NonZeroUsize::new(4096).unwrap();
/// Bytes kept of each frame by default: the outer and inner headers of a VXLAN packet, no payload. A
/// full queue of these is about 1 MiB.
const DEFAULT_SNAPLEN: NonZeroU32 = NonZeroU32::new(256).unwrap();

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
    let known = vpcs(gwconfig);
    let resolve = |vpc: &CaptureVpc| resolve_vpc(vpc, &known);
    let (filter, described) = match (&args.capture_ingress, &args.capture_egress) {
        (None, None) => (CaptureFilter::Everything, "all traffic".to_owned()),
        (Some(from), None) => (
            CaptureFilter::Ingress(resolve(from)?),
            format!("ingress from {from}"),
        ),
        (None, Some(to)) => (
            CaptureFilter::Egress(resolve(to)?),
            format!("egress to {to}"),
        ),
        // Only egress knows both ends, so a conversation is captured there.
        (Some(from), Some(to)) => (
            CaptureFilter::Conversation {
                from: resolve(from)?,
                to: resolve(to)?,
            },
            format!("egress from {from} to {to}"),
        ),
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
    // Zero asks for whole frames.
    let snaplen = match args.capture_snaplen {
        Some(snaplen) => NonZeroU32::new(snaplen),
        None => Some(DEFAULT_SNAPLEN),
    };
    let target = match (&args.capture_file, &args.capture_dir) {
        (Some(_), Some(_)) => {
            return Err(CliError::Capture("give file= or dir=, not both".to_owned()));
        }
        (Some(file), None) => CaptureTarget::File(file.into()),
        (None, Some(dir)) => CaptureTarget::Dir(dir.into()),
        (None, None) => CaptureTarget::Default,
    };
    let capture = CaptureRequest {
        filter,
        sample_one_in,
        packets,
        duration: Duration::from_secs(u64::from(seconds)),
        queue_depth: QUEUE_DEPTH,
        snaplen,
    };
    let path = captures
        .start(capture, names(db, gwconfig), target)
        .map_err(|error| CliError::Capture(error.to_string()))?;
    let kept = snaplen.map_or_else(
        || "whole frames".to_owned(),
        |snaplen| format!("{snaplen} bytes of each frame"),
    );
    Ok(format!(
        "\n capturing {described}, one packet in {sample_one_in}, {kept}, \
         until {packets} packets or {seconds}s\n file: {}",
        path.display()
    ))
}

/// Resolve a VPC name against the applied configuration.
fn resolve_vpc(vpc: &CaptureVpc, known: &[(String, Vni)]) -> Result<VpcMatch, CliError> {
    let name = match vpc {
        CaptureVpc::Any => return Ok(VpcMatch::Any),
        CaptureVpc::Named(name) => name,
    };
    if let Some((_, vni)) = known.iter().find(|(candidate, _)| candidate == name) {
        return Ok(VpcMatch::Vpc(VpcDiscriminant::VNI(*vni)));
    }
    let known = if known.is_empty() {
        "none".to_owned()
    } else {
        known
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(CliError::Capture(format!(
        "unknown VPC '{name}' (known: {known})"
    )))
}

/// The VPCs the applied configuration defines, by name.
fn vpcs(gwconfig: Option<&Arc<ValidatedGwConfig>>) -> Vec<(String, Vni)> {
    gwconfig
        .iter()
        .flat_map(|config| config.external().overlay().vpc_table().values())
        .map(|vpc| (vpc.name().to_owned(), vpc.vni()))
        .collect()
}

/// Names for the interfaces the router knows and the VPCs the applied config defines.
fn names(db: &RoutingDb, gwconfig: Option<&Arc<ValidatedGwConfig>>) -> CaptureNames {
    let mut names = CaptureNames::default();
    if let Some(iftable) = db.iftw.enter() {
        for interface in iftable.values() {
            names = names.with_interface(interface.ifindex, interface.name.to_string());
        }
    }
    for (name, vni) in vpcs(gwconfig) {
        names = names.with_vpc(VpcDiscriminant::VNI(vni), name);
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
    let _ = match captures.default_dir() {
        Some(dir) => write!(out, "\n default directory: {}", dir.display()),
        None => write!(
            out,
            "\n default directory: none (start the dataplane with --capture-dir, or give file= or \
             dir=)"
        ),
    };
    out
}

#[cfg(test)]
mod tests {
    use super::resolve_vpc;
    use capture::VpcMatch;
    use cli::cliproto::{CaptureVpc, CliError};
    use net::packet::VpcDiscriminant;
    use net::vxlan::Vni;

    fn known() -> Vec<(String, Vni)> {
        vec![
            ("vpc-1".to_owned(), Vni::new_checked(3000).unwrap()),
            ("vpc-2".to_owned(), Vni::new_checked(4000).unwrap()),
        ]
    }

    #[test]
    fn a_vpc_name_resolves_to_its_vni() {
        let resolved = resolve_vpc(&CaptureVpc::Named("vpc-2".to_owned()), &known()).unwrap();
        let vni = Vni::new_checked(4000).unwrap();
        assert_eq!(resolved, VpcMatch::Vpc(VpcDiscriminant::VNI(vni)));
        assert_eq!(resolve_vpc(&CaptureVpc::Any, &[]).unwrap(), VpcMatch::Any);
    }

    #[test]
    fn an_unknown_vpc_is_refused_with_the_known_ones() {
        let refused = resolve_vpc(&CaptureVpc::Named("vpc-9".to_owned()), &known());
        assert!(
            matches!(&refused, Err(CliError::Capture(why)) if why == "unknown VPC 'vpc-9' (known: vpc-1, vpc-2)"),
            "{refused:?}"
        );
    }
}
