// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations

use crate::control::{TargetCfg, TargetCfgDb};
use std::fmt::Display;

macro_rules! TARGET_FMT {
    () => {
        "{:>48} │ {:>8} │ {}"
    };
}
fn fmt_target_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(TARGET_FMT!(), "TARGET", "LEVEL", "TAGS")
    )
}

impl Display for TargetCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            format_args!(TARGET_FMT!(), self.target, self.level, self.tags.join(","))
        )
    }
}
impl Display for TargetCfgDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "                            ──────── Tracing configuration ────────")?;
        fmt_target_heading(f)?;
        self.targets.values().for_each(|unit| {
            let _ = writeln!(f, "{unit}");
        });
        // format the default as a target
        write!(
            f,
            "{}",
            format_args!(TARGET_FMT!(), "(default)", self.level, "--")
        )
    }
}
