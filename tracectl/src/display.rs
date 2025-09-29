// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations

use crate::control::{TargetCfg, TargetCfgDb};
use std::fmt::Display;

macro_rules! TARGET_FMT {
    () => {
        "{:>25} │ {:<48} │ {:>6} │ {:>8} │ {}"
    };
}
fn fmt_target_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(TARGET_FMT!(), "NAME", "TARGET", "CUSTOM", "LEVEL", "TAGS")
    )
}

macro_rules! fmt_target {
    ($target:ident) => {
        format_args!(
            TARGET_FMT!(),
            $target.name,
            $target.target,
            if $target.custom { "yes" } else { "" },
            $target.level,
            $target.tags.join(",")
        )
    };
}

impl Display for TargetCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", fmt_target!(self))
    }
}
impl Display for TargetCfgDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        let sep = " ".repeat(34);
        writeln!(
            f,
            "{sep}───────────── Tracing configuration per target ─────────────"
        )?;
        fmt_target_heading(f)?;
        self.targets.values().for_each(|unit| {
            let _ = writeln!(f, "{unit}");
        });
        // format the default as a target
        write!(
            f,
            "{}",
            format_args!(TARGET_FMT!(), "", "(default)", "", self.default, "--")
        )
    }
}

pub(crate) struct TargetCfgDbByTag<'a>(pub(crate) &'a TargetCfgDb);
impl Display for TargetCfgDbByTag<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        let sep = " ".repeat(34);
        writeln!(f, "{sep}──────── Tracing targets tags ────────")?;
        let db = self.0;
        fmt_target_heading(f)?;

        // show tags that have more than one target to make this compact.
        // the names of the targets that appear are also tags
        for tag in db.tags.values().filter(|t| t.targets.len() > 1) {
            writeln!(f, " {}:", tag.tag)?;
            let targets = db.tag_targets(tag.tag);
            for target in targets {
                writeln!(f, "{target}")?;
            }
        }
        Ok(())
    }
}
