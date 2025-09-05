// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use config::external::overlay::vpc::VpcTable;

pub struct NatAllocatorWriter {}

impl NatAllocatorWriter {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    pub fn update_allocator(&mut self, _vpc_table: &VpcTable) {
        todo!()
    }
}

impl Default for NatAllocatorWriter {
    fn default() -> Self {
        Self::new()
    }
}
