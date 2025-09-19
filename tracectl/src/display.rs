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
        writeln!(
            f,
            "                        ──────── Tracing configuration per target ────────"
        )?;
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

pub(crate) struct TargetCfgDbByTag<'a>(pub(crate) &'a TargetCfgDb);
impl Display for TargetCfgDbByTag<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(
            f,
            "                            ──────── Tracing targets by tag ────────"
        )?;
        let db = self.0;
        for tag in db.tags.values() {
            writeln!(f, " {}:", tag.tag)?;
            let targets = db
                .targets
                .values()
                .filter(|target| tag.targets.contains(target.target));
            for target in targets {
                write!(f, "      {:<48} : {}", target.target, target.level)?;
                let other_tags = target.tags.iter().filter(|t| **t != tag.tag);
                let num = other_tags.clone().count();
                if num > 0 {
                    write!(f, " (also: ")?;
                    for other in other_tags {
                        write!(f, " {other}")?;
                    }
                    write!(f, ")")?;
                }
                writeln!(f)?;
            }
        }
        writeln!(f, " untagged:")?;
        for target in db.targets.values().filter(|t| t.tags.is_empty()) {
            writeln!(f, "   {:<48} : {}", target.target, target.level)?;
        }
        Ok(())
    }
}
