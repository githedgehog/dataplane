// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::flow_table::FlowTable;
use common::cliprovider::{CliSource, Heading};
use std::fmt::Display;

impl CliSource for FlowTable {}

/// The most entries the flow table lists. Each is written under its shard's read lock, which an
/// insertion into that shard waits on, and a table of millions would make a listing nobody reads.
pub const MAX_LISTED: usize = 10_000;

impl Display for FlowTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(table) = self.table.try_read() {
            let len = table.len();
            Heading(format!("Flow Table ({len} entries)")).fmt(f)?;
            for entry in table.iter().take(MAX_LISTED) {
                let key = entry.key();
                writeln!(f, "{key}\n{}", entry.value())?;
            }
            if len > MAX_LISTED {
                writeln!(f, "... and {} more, not listed", len - MAX_LISTED)?;
            }
        } else {
            write!(f, "Failed to lock flow table")?;
        }
        Ok(())
    }
}

/// How full the flow table is, for `show flow-table summary`: no entry is read, so no lock is taken.
pub struct FlowTableSummary(pub concurrency::sync::Arc<FlowTable>);

impl common::cliprovider::CliDataProvider for FlowTableSummary {
    fn provide(&self) -> String {
        let (live, capacity) = (self.0.live_len(), self.0.capacity());
        #[allow(clippy::cast_precision_loss)] // a percentage
        let full = if capacity == 0 {
            0.0
        } else {
            live as f64 * 100.0 / capacity as f64
        };
        format!(
            "{}live entries: {live}\ncapacity:     {capacity} ({full:.1} % full)\n",
            Heading("Flow Table")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::cliprovider::CliDataProvider;
    use concurrency::sync::Arc;

    /// The summary reads the counts the table keeps, and says how full it is.
    #[test]
    fn summary_says_how_full() {
        let table = Arc::new(FlowTable::default());
        table.set_capacity(200);
        let summary = FlowTableSummary(table).provide();
        assert!(summary.contains("live entries: 0"), "{summary}");
        assert!(
            summary.contains("capacity:     200 (0.0 % full)"),
            "{summary}"
        );
    }
}
