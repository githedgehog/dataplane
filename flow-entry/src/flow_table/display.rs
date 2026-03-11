// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::flow_table::FlowTable;
use common::cliprovider::{CliData, CliDataProvider};
use std::fmt::Display;

// Copied from crates "config" and "routing"
// TODO: Move to a shared location
struct Heading(String);
const LINE_WIDTH: usize = 81;
impl Display for Heading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = (LINE_WIDTH - (self.0.len() + 2)) / 2;
        write!(f, " {0:─<width$}", "─", width = len)?;
        write!(f, " {} ", self.0)?;
        writeln!(f, " {0:─<width$}", "─", width = len)
    }
}

impl Display for FlowTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(table) = self.table.try_read() {
            Heading(format!("Flow Table ({} entries)", table.len())).fmt(f)?;
            for entry in table.iter() {
                let key = entry.key();
                match entry.value().upgrade() {
                    Some(value) => writeln!(f, "key = {key}\ndata = {value}")?,
                    None => writeln!(f, "key = {key} NONE")?,
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
