// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub struct NatAllocatorWriter {}

impl NatAllocatorWriter {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for NatAllocatorWriter {
    fn default() -> Self {
        Self::new()
    }
}
