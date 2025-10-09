// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
#![deny(clippy::pedantic, missing_docs)]

pub mod sysfs;

use std::path::PathBuf;

/// Errors which might occur during dataplane system initialization
#[derive(Debug, thiserror::Error)]
pub enum InitErr {
    /// The path is not under a mounted sysfs and therefore does not qualify as a [`SysfsPath`].
    #[error("path {0:?} is not under sysfs")]
    PathNotUnderSysfs(PathBuf),
    /// Some [`std::io::Error`] error occurred
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Invalid UTF-8 in a path under sysfs is an absolutely wild error case we expect to
    /// never see.
    ///
    /// The kernel just uses ascii byte strings for sysfs, so you should never see this
    /// error under healthy conditions.
    /// In the event of illegal UTF-8, something is likely deeply wrong with the kernel;
    /// likely memory corruption or some other security impacting issue.
    ///
    /// As such, the [`InitErr::SysfsPathIsNotValidUtf8`] branch deliberately does not include
    /// any information about the offending string name or any derivative, even for logging
    /// or error reporting.
    /// At best you will just end up mangling the log with unknown/unprintable bytes.
    /// At worst, injecting arbitrary bytes into a system log may be what an attacker needs
    /// for lateral compromise of some other system.
    ///
    /// You should likely `panic!` if you reach this error case as there is no plausible
    /// recovery from this type of low level operating system malfunction.
    #[error("path under sysfs is not a valid UTF-8 string")]
    SysfsPathIsNotValidUtf8,
}

fn main() {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_file(true)
        .with_level(true)
        .with_line_number(true)
        .init();
}
