// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::flow_table::FlowTable;
use common::cliprovider::{CliData, CliDataProvider, Heading};
use std::fmt::Display;

impl Display for FlowTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(table) = self.table.try_read() {
            Heading(format!("Flow Table ({} entries)", table.len())).fmt(f)?;
            for entry in table.iter() {
                let key = entry.key();
                match entry.value().upgrade() {
                    Some(value) => writeln!(f, "{key}\n{value}")?,
                    None => writeln!(f, "{key}: NONE")?,
                }
            }
        } else {
            write!(f, "Failed to lock flow table")?;
        }
        Ok(())
    }
}

impl CliDataProvider for FlowTable {
    fn provide(&self, _dataid: Option<CliData>) -> String {
        self.to_string()
    }
}
