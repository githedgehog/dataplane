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

#[test]
fn handoff_protocol() {
    for mode in [
        "absent",
        "config_only",
        "hash_only",
        "kernel_unused_fd",
        "dpdk_unused_fd",
        "dpdk_namespace",
        "dpdk_missing_namespace",
    ] {
        let driver = if mode == "kernel_unused_fd" {
            "kernel"
        } else {
            "dpdk"
        };
        let interface = if driver == "kernel" {
            "eth0=kernel@eth0"
        } else {
            "eth0=pci@0000:01:00.0"
        };
        let mut argv = vec![
            "dataplane-init",
            "--driver",
            driver,
            "--interface",
            interface,
        ];
        if matches!(mode, "dpdk_namespace" | "dpdk_missing_namespace") {
            argv.push("--datapath-netns");
        }
        let config = LaunchConfiguration::try_from(CmdArgs::try_parse_from(argv).unwrap()).unwrap();
        let mut config = config.finalize();
        let hash = config.integrity_check().finalize().to_owned_fd();
        let config = config.to_owned_fd();
        let extra = File::open(if mode == "dpdk_namespace" {
            "/proc/thread-self/ns/net"
        } else {
            "/dev/null"
        })
        .unwrap();
        // Keep sources above every destination so dup2 ordering cannot overwrite a source.
        let duplicate = |fd: &dyn AsFd| -> OwnedFd {
            let raw =
                nix::fcntl::fcntl(fd.as_fd(), nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(100)).unwrap();
            // SAFETY: fcntl returned a new descriptor owned exclusively by this value.
            unsafe { std::os::fd::FromRawFd::from_raw_fd(raw) }
        };
        let sources = [duplicate(&hash), duplicate(&config), duplicate(&extra)];
        let mapping = [
            (HASH_FD, !matches!(mode, "absent" | "config_only")),
            (CONFIG_FD, !matches!(mode, "absent" | "hash_only")),
            (
                NETNS_FD,
                matches!(
                    mode,
                    "kernel_unused_fd" | "dpdk_unused_fd" | "dpdk_namespace"
                ),
            ),
        ];
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
                for ((target, supplied), source) in mapping.into_iter().zip(&sources) {
                    if supplied {
                        if nix::libc::dup2(source.as_raw_fd(), target) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                    } else {
                        nix::libc::close(target);
                    }
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{mode}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn handoff_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    match mode.as_str() {
        "absent" => assert!(!LaunchConfiguration::was_inherited().unwrap()),
        "config_only" | "hash_only" => {
            assert!(LaunchConfiguration::was_inherited().is_err());
        }
        _ => {
            assert!(LaunchConfiguration::was_inherited().unwrap());
            // SAFETY: the parent supplied these descriptors exclusively for this handoff.
            let config = unsafe { LaunchConfiguration::inherit() };
            assert!(!LaunchConfiguration::was_inherited().unwrap());
            // SAFETY: the parent reserved FD 50 for this handoff; no Rust value owns it yet.
            let netns = unsafe { config.inherit_netns() };
            match mode.as_str() {
                "dpdk_namespace" => {
                    let fd = netns.unwrap().expect("requested namespace");
                    let flags = nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_GETFD).unwrap();
                    assert_ne!(flags & nix::fcntl::FdFlag::FD_CLOEXEC.bits(), 0);
                }
                "dpdk_missing_namespace" => {
                    assert_eq!(netns.unwrap_err().raw_os_error(), Some(nix::libc::EBADF));
                }
                "kernel_unused_fd" | "dpdk_unused_fd" => {
                    assert!(netns.unwrap().is_none());
                    assert_eq!(
                        std::fs::read_link("/proc/self/fd/50").unwrap(),
                        std::path::Path::new("/dev/null")
                    );
                }
                _ => unreachable!(),
            }
        }
    }
}
