// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Exercise fixed descriptor numbers in child processes so tests cannot affect each other.

use dataplane_args::{AsFinalizedMemFile, CmdArgs, LaunchConfiguration, Parser};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

const CHILD_MODE: &str = "DATAPLANE_HANDOFF_TEST";
const CONFIG_FD: RawFd = LaunchConfiguration::STANDARD_CONFIG_FD;
const HASH_FD: RawFd = LaunchConfiguration::STANDARD_INTEGRITY_CHECK_FD;
const NETNS_FD: RawFd = LaunchConfiguration::STANDARD_NETNS_FD;
const HOST_NETNS_FD: RawFd = LaunchConfiguration::STANDARD_HOST_NETNS_FD;

/// Each mode names the descriptors the parent supplies, in the order hash, config, datapath
/// namespace, host namespace.
const MODES: [(&str, [bool; 4]); 8] = [
    ("absent", [false, false, false, false]),
    ("config_only", [false, true, false, false]),
    ("hash_only", [true, false, false, false]),
    ("netns_only", [false, false, true, false]),
    ("host_netns_only", [false, false, false, true]),
    ("missing_namespace", [true, true, false, true]),
    ("missing_host_namespace", [true, true, true, false]),
    ("complete", [true, true, true, true]),
];

#[test]
fn handoff_protocol() {
    for driver in ["dpdk", "kernel"] {
        for (mode, supplied) in MODES {
            run_child(driver, mode, supplied);
        }
    }
}

fn run_child(driver: &str, mode: &str, supplied: [bool; 4]) {
    let interface = if driver == "kernel" {
        "eth0=kernel@eth0"
    } else {
        "eth0=pci@0000:01:00.0"
    };
    let argv = [
        "dataplane-init",
        "--driver",
        driver,
        "--interface",
        interface,
    ];
    let config = LaunchConfiguration::try_from(CmdArgs::try_parse_from(argv).unwrap()).unwrap();
    let mut config = config.finalize();
    let hash = config.integrity_check().finalize().to_owned_fd();
    let config = config.to_owned_fd();
    let netns = File::open("/proc/thread-self/ns/net").unwrap();
    // Keep sources above every destination so dup2 ordering cannot overwrite a source.
    let duplicate = |fd: &dyn AsFd| -> OwnedFd {
        let raw =
            nix::fcntl::fcntl(fd.as_fd(), nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(100)).unwrap();
        // SAFETY: fcntl returned a new descriptor owned exclusively by this value.
        unsafe { std::os::fd::FromRawFd::from_raw_fd(raw) }
    };
    let sources = [
        duplicate(&hash),
        duplicate(&config),
        duplicate(&netns),
        duplicate(&netns),
    ];
    let mapping = [HASH_FD, CONFIG_FD, NETNS_FD, HOST_NETNS_FD]
        .into_iter()
        .zip(supplied)
        .collect::<Vec<_>>();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "handoff_child",
        "--nocapture",
        "--test-threads=1",
    ]);
    command.env(CHILD_MODE, mode);
    // SAFETY: the closure only calls async-signal-safe close/dup2 after fork.
    // Source descriptors remain live until the child finishes spawning.
    unsafe {
        command.pre_exec(move || {
            for ((target, supplied), source) in mapping.iter().zip(&sources) {
                if *supplied {
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
    assert!(
        output.status.success(),
        "{driver} {mode}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn handoff_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    match mode.as_str() {
        "absent" => assert!(!LaunchConfiguration::was_inherited().unwrap()),
        "config_only"
        | "hash_only"
        | "netns_only"
        | "host_netns_only"
        | "missing_namespace"
        | "missing_host_namespace" => {
            assert!(LaunchConfiguration::was_inherited().is_err());
        }
        "complete" => {
            assert!(LaunchConfiguration::was_inherited().unwrap());
            // SAFETY: the parent supplied these descriptors exclusively for this handoff.
            let _config = unsafe { LaunchConfiguration::inherit() };
            // SAFETY: the parent reserved FD 50 for this handoff; no Rust value owns it yet.
            let fd = unsafe { LaunchConfiguration::inherit_netns() }.unwrap();
            // SAFETY: the parent reserved FD 60 for this handoff; no Rust value owns it yet.
            let host_fd = unsafe { LaunchConfiguration::inherit_host_netns() }.unwrap();
            for fd in [&fd, &host_fd] {
                let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).unwrap();
                assert_ne!(flags & nix::fcntl::FdFlag::FD_CLOEXEC.bits(), 0);
            }
            drop((fd, host_fd));
            assert!(!LaunchConfiguration::was_inherited().unwrap());
        }
        other => unreachable!("unknown handoff mode {other}"),
    }
}
