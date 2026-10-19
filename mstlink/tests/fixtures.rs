// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Parse `mstlink --json` output captured from a BlueField-3 (firmware 32.50.1002, mstflint 4.37)
//! with two very different links: 400G over CMIS QSFP112 optics (PAM4, RS-FEC) and 10G over SFP+
//! modules through QSFP-to-SFP adapters (NRZ, no FEC).

#![allow(clippy::unwrap_used, clippy::float_cmp, clippy::panic)]

use dataplane_mstlink::{FecHistogram, ParseError, Pcie, PortReport};

/// The crate's directory, read at run time rather than with `env!`: test archives built in the nix
/// sandbox run on the host, where the build path does not exist. nextest's `--workspace-remap` (and
/// plain `cargo test`) set it to where the sources are.
fn manifest_dir() -> String {
    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string())
}

fn fixture(link: &str, file: &str) -> String {
    let path = format!("{}/tests/fixtures/{link}/{file}", manifest_dir());
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn a_400g_pam4_port() {
    let report = PortReport::parse(&fixture("qsfp112-400g", "port.json")).unwrap();
    let operational = &report.operational;
    assert_eq!(operational.state.as_deref(), Some("Active"));
    assert_eq!(operational.speed.as_deref(), Some("400G"));
    assert_eq!(operational.width.as_deref(), Some("4x"));
    assert_eq!(
        operational.fec.as_deref(),
        Some("Standard_RS-FEC - (544,514)")
    );
    assert_eq!(report.troubleshooting.status_opcode, Some(0));
    assert_eq!(
        report.troubleshooting.recommendation.as_deref(),
        Some("No issue was observed")
    );
    assert_eq!(report.troubleshooting.group_opcode, None, "N/A is absent");

    let counters = report.counters.unwrap();
    assert_eq!(counters.raw_ber, Some(5e-11));
    assert_eq!(counters.effective_ber, Some(15e-255));
    assert_eq!(
        counters.raw_ber_per_lane,
        [Some(3e-11), Some(1e-10), Some(4e-12), Some(2e-11)]
    );
    assert_eq!(
        counters.raw_errors_per_lane,
        [Some(377_636), Some(1_623_516), Some(48_684), Some(274_751)]
    );
    assert_eq!(counters.link_down, Some(0));
    assert_eq!(counters.minutes_since_clear, Some(1984.2));

    let eye = report.eye.unwrap();
    assert_eq!(eye.fom_mode.as_deref(), Some("SLRG_FOM_MODE_EYEO"));
    assert_eq!(eye.lanes.len(), 4);
    let lane1 = eye.lanes[1];
    assert_eq!(lane1.lane, 1);
    assert_eq!((lane1.initial_fom, lane1.last_fom), (Some(68), Some(68)));
    assert_eq!(
        (lane1.upper_grade, lane1.mid_grade, lane1.lower_grade),
        (Some(67), Some(59), Some(71))
    );
}

#[test]
fn a_10g_nrz_port() {
    let report = PortReport::parse(&fixture("sfp-10g", "port.json")).unwrap();
    assert_eq!(report.operational.speed.as_deref(), Some("10G"));
    assert_eq!(report.operational.fec.as_deref(), Some("No FEC"));
    let counters = report.counters.unwrap();
    assert_eq!(counters.raw_ber_per_lane.len(), 1);
    let eye = report.eye.unwrap();
    let [lane] = eye.lanes.as_slice() else {
        panic!("an SFP has one lane")
    };
    assert!(lane.last_fom.is_some());
    assert_eq!(lane.upper_grade, None, "NRZ has no PAM4 grades");
}

#[test]
fn a_fec_histogram() {
    let histogram = FecHistogram::parse(&fixture("qsfp112-400g", "fec-histogram.json")).unwrap();
    assert_eq!(histogram.bins.len(), 16);
    assert_eq!(histogram.bins[0], ("[0]".to_string(), 9_303_007_741_342));
    assert_eq!(histogram.bins[1], ("[1]".to_string(), 1_613_216));
    assert_eq!(
        histogram.bins[10].0, "[10]",
        "bins in numeric, not lexical, order"
    );
}

#[test]
fn no_fec_is_a_failure_mstlink_explains() {
    let error = FecHistogram::parse(&fixture("sfp-10g", "fec-histogram.json")).unwrap_err();
    let ParseError::Failed { code, message } = error else {
        panic!("{error:?}")
    };
    assert_eq!(code, 1);
    assert!(message.contains("No histogram info available"), "{message}");
}

#[test]
fn a_pcie_link_trained_down() {
    for link in ["qsfp112-400g", "sfp-10g"] {
        let pcie = Pcie::parse(&fixture(link, "pcie.json")).unwrap();
        assert_eq!(
            (pcie.generation_active, pcie.generation_enabled),
            (Some(5), Some(5))
        );
        assert_eq!((pcie.width_active, pcie.width_enabled), (Some(8), Some(16)));
        assert_eq!(pcie.crc_errors_tlp, Some(0));
        assert_eq!(pcie.tx_errors, Some(2));
    }
}

#[test]
fn an_unknown_device_is_coloured_text() {
    let output = "\u{1b}[31m \n-E- Failed to open device: \"0000:99:00.0\", No such file or \
                  directory\n\u{1b}[0m \n";
    let error = PortReport::parse(output).unwrap_err();
    let ParseError::NotJson { text } = error else {
        panic!("{error:?}")
    };
    assert_eq!(
        text,
        "-E- Failed to open device: \"0000:99:00.0\", No such file or directory"
    );
}

#[test]
fn arbitrary_output_never_panics() {
    bolero::check!().with_type::<String>().for_each(|output| {
        let _ = PortReport::parse(output);
        let _ = FecHistogram::parse(output);
        let _ = Pcie::parse(output);
    });
}
