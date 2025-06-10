// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use chrono::{DateTime, Utc};
use routing::pretty_utils::Heading;
use std::fmt::Display;

use crate::models::external::gwconfig::ExternalConfig;
use crate::models::external::gwconfig::GenId;
use crate::models::external::gwconfig::GwConfig;
use crate::models::external::gwconfig::GwConfigMeta;

use crate::models::internal::InternalConfig;
use crate::processor::gwconfigdb::GwConfigDatabase;

macro_rules! CONFIGDB_TBL_FMT {
    () => {
        " {:>6} {:<25} {:<25} {:<25} {:>6} {:<10}"
    };
}
fn fmt_configdb_summary_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            CONFIGDB_TBL_FMT!(),
            "GenId", "created", "applied", "replaced", "by", "active"
        )
    )
}
fn fmt_gwconfig_summary(
    meta: &GwConfigMeta,
    genid: GenId,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    let created = DateTime::<Utc>::from(meta.create_t).format("%H:%M:%S on %Y/%m/%d");
    let apply_time = if let Some(time) = meta.apply_t {
        let time = DateTime::<Utc>::from(time).format("%H:%M:%S on %Y/%m/%d");
        format!("{time}")
    } else {
        "--".to_string()
    };
    let replace_time = if let Some(time) = meta.replace_t {
        let time = DateTime::<Utc>::from(time).format("%H:%M:%S on %Y/%m/%d");
        format!("{time}")
    } else {
        "--".to_string()
    };

    let applied = if meta.is_applied { "yes" } else { "no" };
    let replacement = meta
        .replacement
        .map(|genid| genid.to_string())
        .unwrap_or("--".to_string());
    writeln!(
        f,
        "{}",
        format_args!(
            CONFIGDB_TBL_FMT!(),
            genid, created, apply_time, replace_time, replacement, applied
        )
    )
}

pub struct GwConfigDatabaseSummary<'a>(pub &'a GwConfigDatabase);
impl Display for GwConfigDatabaseSummary<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!(
            "Configuration database summary ({} configs)",
            self.0.len()
        ))
        .fmt(f)?;
        if let Some(curr) = self.0.get_current_gen() {
            writeln!(f, " current generation: {curr}")?;
        } else {
            writeln!(f, " current generation: --")?;
        }
        fmt_configdb_summary_heading(f)?;
        for (genid, gwconfig) in self.0.iter() {
            fmt_gwconfig_summary(&gwconfig.meta, *genid, f)?;
        }
        Ok(())
    }
}

// TODO(fredi)
impl Display for GwConfigMeta {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO
        Ok(())
    }
}
// TODO(fredi)
impl Display for ExternalConfig {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO
        Ok(())
    }
}
// TODO(fredi)
impl Display for InternalConfig {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO
        Ok(())
    }
}
// TODO(fredi)
impl Display for GwConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.meta.fmt(f)?;
        self.external.fmt(f)?;
        if let Some(internal) = &self.internal {
            internal.fmt(f)?;
        }
        Ok(())
    }
}
// TODO(fredi)
impl Display for GwConfigDatabase {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}
