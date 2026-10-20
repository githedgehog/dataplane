// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Init validates the launch configuration before touching any device or namespace.

use std::process::Command;

/// A command running `dataplane-init`, in the emulator `scripts/test-runner.sh` names when the
/// tests run under one.
///
/// nextest exports the binary's runtime location, remapped when tests run from an archive; the
/// compile-time path only exists in the tree that built it.
fn init_command() -> Command {
    let binary: std::path::PathBuf = std::env::var_os("NEXTEST_BIN_EXE_dataplane-init")
        .map_or_else(|| env!("CARGO_BIN_EXE_dataplane-init").into(), Into::into);
    match std::env::var_os("DATAPLANE_TEST_EMULATOR") {
        Some(emulator) => {
            let mut command = Command::new(emulator);
            command.arg(binary);
            command
        }
        None => Command::new(binary),
    }
}

#[test]
fn invalid_launch_configuration_fails_before_device_preparation() {
    for (args, expected) in [
        (vec![], "Must specify driver"),
        (vec!["--driver", "dpdk"], "No network interfaces"),
        (vec!["--driver", "kernel"], "No network interfaces"),
        (
            vec!["--driver", "dpdk", "--interface", "eth0=kernel@eth0"],
            "DPDK driver does not support",
        ),
        (
            vec!["--driver", "dpdk", "--interface", "eth0"],
            "must specify a PCI address",
        ),
    ] {
        let output = init_command().args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let log = String::from_utf8_lossy(&output.stdout);
        assert!(
            log.contains("invalid command line arguments"),
            "{args:?}: {log}"
        );
        assert!(log.contains(expected), "{args:?}: {log}");
        assert!(!log.contains("scanning hardware"), "{args:?}: {log}");
    }
}
