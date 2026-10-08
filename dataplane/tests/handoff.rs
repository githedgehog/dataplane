// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(not(feature = "loom"))]

use args::{AsFinalizedMemFile, CmdArgs, LaunchConfiguration, Parser};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

/// nextest exports the binary's runtime location, remapped when tests run from an archive; the
/// compile-time path only exists in the tree that built it.
fn dataplane_binary() -> std::path::PathBuf {
    std::env::var_os("NEXTEST_BIN_EXE_dataplane")
        .map_or_else(|| env!("CARGO_BIN_EXE_dataplane").into(), Into::into)
}

#[test]
fn invalid_host_namespace_fails_before_eal() {
    for (path, expected) in [
        (None, "incomplete launch configuration handoff"),
        (Some("/proc/self/status"), "Invalid host namespace handoff:"),
        (
            Some("/proc/thread-self/ns/mnt"),
            "Invalid host namespace handoff:",
        ),
    ] {
        let config = LaunchConfiguration::try_from(CmdArgs::parse_from([
            "dataplane-init",
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@eth0",
        ]))
        .unwrap();
        let mut config = config.finalize();
        let hash = config.integrity_check().finalize().to_owned_fd();
        let config = config.to_owned_fd();
        let datapath = File::open("/proc/thread-self/ns/net").unwrap();
        let namespace = path.map(|path| File::open(path).unwrap());

        // Keep sources above every destination so dup2 cannot overwrite a source.
        let duplicate = |fd: &dyn AsFd| -> OwnedFd {
            let raw =
                nix::fcntl::fcntl(fd.as_fd(), nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(100)).unwrap();
            // SAFETY: fcntl returned a new descriptor owned exclusively by this value.
            unsafe { OwnedFd::from_raw_fd(raw) }
        };
        let mappings = [
            (
                LaunchConfiguration::STANDARD_INTEGRITY_CHECK_FD,
                Some(duplicate(&hash)),
            ),
            (
                LaunchConfiguration::STANDARD_CONFIG_FD,
                Some(duplicate(&config)),
            ),
            (
                LaunchConfiguration::STANDARD_NETNS_FD,
                Some(duplicate(&datapath)),
            ),
            (
                LaunchConfiguration::STANDARD_HOST_NETNS_FD,
                namespace.as_ref().map(|fd| duplicate(fd)),
            ),
        ];
        let mut command = Command::new(dataplane_binary());
        // SAFETY: only async-signal-safe close/dup2 calls run after fork; sources remain live.
        unsafe {
            command.pre_exec(move || {
                for (target, source) in &mappings {
                    if let Some(source) = source {
                        if nix::libc::dup2(source.as_raw_fd(), *target) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                    } else {
                        nix::libc::close(*target);
                    }
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{path:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{path:?}: {stderr}");
        assert!(!stderr.contains("EAL:"), "{path:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{path:?}");
    }
}
