// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::{NatDefaultAllocator, NatVpcId};
use arc_swap::ArcSwapOption;
use config::ConfigError;
use config::external::overlay::vpc::Peering;
use config::external::overlay::vpc::VpcTable;
use std::sync::Arc;

#[derive(Debug, PartialEq)]
pub(crate) struct StatefulNatPeering {
    pub(crate) src_vpc_id: NatVpcId,
    pub(crate) dst_vpc_id: NatVpcId,
    pub(crate) peering: Peering,
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct StatefulNatConfig(Vec<StatefulNatPeering>);

impl StatefulNatConfig {
    pub(crate) fn new(vpc_table: &VpcTable) -> Self {
        let mut config = Vec::new();
        for vpc in vpc_table.values() {
            for peering in &vpc.peerings {
                config.push(StatefulNatPeering {
                    src_vpc_id: vpc.vni,
                    dst_vpc_id: vpc_table.get_remote_vni(peering),
                    peering: peering.clone(),
                });
            }
        }
        Self(config)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &StatefulNatPeering> {
        self.0.iter()
    }
}

#[derive(Debug)]
pub struct NatAllocatorWriter {
    config: StatefulNatConfig,
    allocator: Arc<ArcSwapOption<NatDefaultAllocator>>,
}

impl NatAllocatorWriter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: StatefulNatConfig::default(),
            allocator: Arc::new(ArcSwapOption::new(None)),
        }
    }

    #[must_use]
    pub fn get_reader(&self) -> NatAllocatorReader {
        NatAllocatorReader(self.allocator.clone())
    }

    pub fn update_allocator(&mut self, vpc_table: &VpcTable) -> Result<(), ConfigError> {
        let new_config = StatefulNatConfig::new(vpc_table);

        let old_allocator_guard = self.allocator.load();
        let Some(old_allocator) = old_allocator_guard.as_deref() else {
            // No existing allocator, build a new one
            let new_allocator = Self::build_new_allocator(&new_config)?;
            self.allocator.store(Some(Arc::new(new_allocator)));
            self.config = new_config;
            return Ok(());
        };

        if self.config == new_config {
            // Nothing to update, simply return
            return Ok(());
        }

        Self::update_existing_allocator(old_allocator, &self.config, &new_config)?;
        self.config = new_config;
        Ok(())
    }

    fn build_new_allocator(config: &StatefulNatConfig) -> Result<NatDefaultAllocator, ConfigError> {
        NatDefaultAllocator::build_nat_allocator(config)
    }

    fn update_existing_allocator(
        _allocator: &NatDefaultAllocator,
        _old_config: &StatefulNatConfig,
        _new_config: &StatefulNatConfig,
    ) -> Result<(), ConfigError> {
        todo!();
    }
}

impl Default for NatAllocatorWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct NatAllocatorReader(Arc<ArcSwapOption<NatDefaultAllocator>>);

impl NatAllocatorReader {
    pub fn get(&self) -> Option<Arc<NatDefaultAllocator>> {
        self.0.load().clone()
    }
}
