// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Left-right integration for [`FlowFilterTable`]

use crate::tables::FlowFilterTable;
use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle, new_from_empty};
use tracing::debug;

#[derive(Debug)]
pub(crate) enum FlowFilterTableChange {
    UpdateFlowFilterTable(FlowFilterTable),
}

impl Absorb<FlowFilterTableChange> for FlowFilterTable {
    fn absorb_first(&mut self, change: &mut FlowFilterTableChange, _: &Self) {
        match change {
            FlowFilterTableChange::UpdateFlowFilterTable(table) => {
                *self = table.clone();
            }
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

#[derive(Debug)]
pub struct FlowFilterTableReader(ReadHandle<FlowFilterTable>);

impl FlowFilterTableReader {
    pub(crate) fn enter(&self) -> Option<ReadGuard<'_, FlowFilterTable>> {
        self.0.enter()
    }

    #[must_use]
    pub fn factory(&self) -> FlowFilterTableReaderFactory {
        FlowFilterTableReaderFactory(self.0.factory())
    }
}

#[derive(Debug)]
pub struct FlowFilterTableReaderFactory(ReadHandleFactory<FlowFilterTable>);

impl FlowFilterTableReaderFactory {
    #[must_use]
    pub fn handle(&self) -> FlowFilterTableReader {
        FlowFilterTableReader(self.0.handle())
    }
}

#[derive(Debug)]
pub struct FlowFilterTableWriter(WriteHandle<FlowFilterTable, FlowFilterTableChange>);

impl FlowFilterTableWriter {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> FlowFilterTableWriter {
        let (w, _r) =
            new_from_empty::<FlowFilterTable, FlowFilterTableChange>(FlowFilterTable::new());
        FlowFilterTableWriter(w)
    }

    #[must_use]
    pub fn get_reader(&self) -> FlowFilterTableReader {
        FlowFilterTableReader(self.0.clone())
    }

    pub fn get_reader_factory(&self) -> FlowFilterTableReaderFactory {
        self.get_reader().factory()
    }

    pub fn update_flow_filter_table(&mut self, table: FlowFilterTable) {
        self.0
            .append(FlowFilterTableChange::UpdateFlowFilterTable(table));
        self.0.publish();
        debug!("Updated flow filter table");
    }
}
