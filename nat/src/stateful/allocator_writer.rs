// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::NatDefaultAllocator;
use arc_swap::ArcSwapOption;
use config::ConfigError;
use config::external::overlay::vpc::Peering;
use config::external::overlay::vpc::VpcTable;
use net::packet::VpcDiscriminant;
use std::sync::Arc;

#[derive(Debug, PartialEq)]
pub(crate) struct StatefulNatPeering {
    pub(crate) src_vpc_id: VpcDiscriminant,
    pub(crate) dst_vpc_id: VpcDiscriminant,
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
                    src_vpc_id: VpcDiscriminant::from_vni(vpc.vni),
                    dst_vpc_id: VpcDiscriminant::from_vni(vpc_table.get_remote_vni(peering)),
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

        let new_allocator =
            Self::update_existing_allocator(old_allocator, &self.config, &new_config)?;
        // Swap allocators; the old one is dropped.
        self.allocator.store(Some(Arc::new(new_allocator)));
        self.config = new_config;
        Ok(())
    }

    fn build_new_allocator(config: &StatefulNatConfig) -> Result<NatDefaultAllocator, ConfigError> {
        NatDefaultAllocator::build_nat_allocator(config)
    }

    fn update_existing_allocator(
        _allocator: &NatDefaultAllocator,
        _old_config: &StatefulNatConfig,
        new_config: &StatefulNatConfig,
    ) -> Result<NatDefaultAllocator, ConfigError> {
        // TODO: Report state from old allocator to new allocator
        //
        // This means reporting all allocated IPs (and ports for these IPs) from the old allocator
        // that remain valid in the new configuration to the new allocator (and discard the ones
        // that are now invalid). This is required if we want to keep existing, valid connections open.
        //
        // It is not trivial to do, though, because it's difficult to do a meaningful "diff" between
        // the two configurations or allocators' internal states. One allocated IP from the old
        // allocator may still be available for NAT with the new configuration, but possibly for a
        // different list of original prefixes. We can even have connections using some ports for a
        // given allocated IP remaining valid, while others using other ports for the same IP become
        // invalid.
        //
        // One "option" is to process all entries in the session table, look at the new
        // configuration (or the new allocator entries) to see if they're still valid, and then
        // report them to the new allocator. However, the old allocator keeps being updated during
        // this process.
        Self::build_new_allocator(new_config)
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
