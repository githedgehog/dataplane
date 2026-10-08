// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(not(feature = "loom"))]

use std::process::Command;

/// nextest exports the binary's runtime location, remapped when tests run from an archive; the
/// compile-time path only exists in the tree that built it.
fn dataplane_binary() -> std::path::PathBuf {
    std::env::var_os("NEXTEST_BIN_EXE_dataplane")
        .map_or_else(|| env!("CARGO_BIN_EXE_dataplane").into(), Into::into)
}

#[test]
fn informational_commands_need_no_launch_configuration() {
    for flag in [
        "--help",
        "--version",
        "--show-tracing-tags",
        "--show-tracing-targets",
        "--tracing-config-generate",
    ] {
        let output = Command::new(dataplane_binary()).arg(flag).output().unwrap();
        assert!(
            output.status.success(),
            "{flag}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "{flag}");
        assert!(output.stderr.is_empty(), "{flag}");
    }
}

#[test]
fn launch_without_init_is_refused() {
    for args in [
        vec![],
        vec!["--driver", "kernel", "--interface", "eth0=kernel@eth0"],
        vec!["--driver", "dpdk", "--interface", "eth0=pci@0000:01:00.0"],
    ] {
        let output = Command::new(dataplane_binary())
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("must be launched by dataplane-init"),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains("EAL:"), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}
