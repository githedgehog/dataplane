// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A worker's handle on the shared flow table.

use super::FlowTable;
use concurrency::sync::Arc;
use std::ops::Deref;

/// One worker's handle on the shared [`FlowTable`].
///
/// The network functions that create flows hold one of these rather than the bare table: creating
/// a flow is tied to the worker that created it, which owns the flow's expiry. Lookups and every
/// other read go through [`Deref`] to the shared table.
#[derive(Debug, Clone)]
pub struct WorkerFlowTable {
    table: Arc<FlowTable>,
}

impl WorkerFlowTable {
    /// A handle on `table` for the calling worker.
    #[must_use]
    pub fn new(table: Arc<FlowTable>) -> Self {
        Self { table }
    }

    /// The shared table this handle points at.
    #[must_use]
    pub fn shared(&self) -> &Arc<FlowTable> {
        &self.table
    }
}

impl Deref for WorkerFlowTable {
    type Target = FlowTable;

    fn deref(&self) -> &FlowTable {
        &self.table
    }
}
