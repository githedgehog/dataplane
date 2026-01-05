// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use chrono::{DateTime, Utc};
use routing::Heading;
use std::fmt::Display;

use crate::processor::gwconfigdb::GwConfigDatabase;

#[allow(unused)]
use config::{ExternalConfig, GenId, GwConfig, GwConfigMeta, InternalConfig};

macro_rules! CONFIGDB_TBL_FMT {
    () => {
        " {:>6} {:<25} {:<25} {}"
    };
}

fn fmt_configdb_summary_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(CONFIGDB_TBL_FMT!(), "GenId", "created", "applied", "error")
    )
}

fn fmt_gwconfig_summary(meta: &GwConfigMeta, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let created = DateTime::<Utc>::from(meta.create_t).format("%H:%M:%S on %Y/%m/%d");
    let apply_time = if let Some(time) = meta.apply_t {
        let time = DateTime::<Utc>::from(time).format("%H:%M:%S on %Y/%m/%d");
        format!("{time}")
    } else {
        "--".to_string()
    };

    let error = meta
        .error
        .as_ref()
        .map(|e| e.to_string())
        .unwrap_or("none".to_string());

    writeln!(
        f,
        "{}",
        format_args!(CONFIGDB_TBL_FMT!(), meta.genid, created, apply_time, error)
    )
}

pub struct ConfigHistory<'a>(pub &'a GwConfigDatabase);

impl Display for ConfigHistory<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Configuration history".to_string()).fmt(f)?;

        if let Some(curr) = self.0.get_current_gen() {
            writeln!(f, " current generation: {curr}")?;
        } else {
            writeln!(f, " current generation: --")?;
        }

        fmt_configdb_summary_heading(f)?;
        for meta in self.0.history() {
            fmt_gwconfig_summary(meta, f)?;
        }
        Ok(())
    }
}
