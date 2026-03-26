// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::apalloc::NatAllocator;
use arc_swap::ArcSwapOption;
use config::ConfigError;
use config::GenId;
use config::external::overlay::vpc::Peering;
use config::external::overlay::vpc::VpcTable;
use config::external::overlay::vpcpeering::VpcExpose;
use flow_entry::flow_table::FlowTable;
use net::packet::VpcDiscriminant;
use std::sync::Arc;
use tracing::debug;

use crate::stateful::flows::invalidate_all_stateful_nat_flows;
use crate::stateful::flows::upgrade_all_stateful_nat_flows;
use crate::stateful::flows::validate_stateful_nat_flows;

#[derive(Debug, PartialEq)]
pub(crate) struct StatefulNatPeering {
    pub(crate) src_vpcd: VpcDiscriminant,
    pub(crate) dst_vpcd: VpcDiscriminant,
    pub(crate) peering: Peering,
}
#[derive(Debug, Default, PartialEq)]
pub(crate) struct StatefulNatConfig(Vec<StatefulNatPeering>);

impl StatefulNatConfig {
    #[must_use]
    pub(crate) fn new(vpc_table: &VpcTable) -> Self {
        let mut config = Vec::new();
        for vpc in vpc_table.values() {
            for peering in vpc.stateful_nat_peerings() {
                config.push(StatefulNatPeering {
                    src_vpcd: VpcDiscriminant::from_vni(vpc.vni),
                    dst_vpcd: VpcDiscriminant::from_vni(vpc_table.get_remote_vni(peering)),
                    peering: peering.clone(),
                });
            }
        }
        Self(config)
    }
    pub(crate) fn iter(&self) -> impl Iterator<Item = &StatefulNatPeering> {
        self.0.iter()
    }

    pub(crate) fn num_stateful_nat_peerings(&self) -> usize {
        self.0
            .iter()
            .map(|p| &p.peering)
            .filter(|p| {
                p.local.exposes.iter().any(VpcExpose::has_stateful_nat)
                    || p.remote.exposes.iter().any(VpcExpose::has_stateful_nat)
            })
            .count()
    }

    pub(crate) fn get_peering(
        &self,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
    ) -> Option<&StatefulNatPeering> {
        self.0
            .iter()
            .find(|p| p.src_vpcd == src_vpcd && p.dst_vpcd == dst_vpcd)
    }
}

#[derive(Debug)]
pub struct NatAllocatorWriter {
    config: StatefulNatConfig,
    allocator: Arc<ArcSwapOption<NatAllocator>>,
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

    #[must_use]
    pub fn get_reader_factory(&self) -> NatAllocatorReaderFactory {
        self.get_reader().factory()
    }

    /// Replace the nat allocator with a new one
    pub fn update_nat_allocator(
        &mut self,
        vpc_table: &VpcTable,
        flow_table: &FlowTable,
        genid: GenId,
    ) -> Result<(), ConfigError> {
        let new_config = StatefulNatConfig::new(vpc_table);

        // freeze the current allocator ?
        let old_allocator = self.allocator.load();

        if new_config == self.config && old_allocator.is_some() {
            debug!("No need to update NAT allocator: NAT peerings did not change");
            upgrade_all_stateful_nat_flows(flow_table, genid);
            return Ok(());
        }
        if new_config.num_stateful_nat_peerings() == 0 {
            debug!("Stateful NAT is not required: will invalidate flows and remove allocator");
            invalidate_all_stateful_nat_flows(flow_table);
            self.allocator.store(None);
            return Ok(());
        }

        // build a new allocator to replace the current
        let mut new_allocator = NatAllocator::from_config(&new_config)?;
        if old_allocator.is_some() {
            validate_stateful_nat_flows(flow_table, &new_config, &mut new_allocator, genid);
        }
        self.allocator.store(Some(Arc::new(new_allocator)));
        self.config = new_config;
        debug!("Updated allocator for stateful NAT");
        Ok(())
    }

    fn update_allocator_and_set_randomness(
        &mut self,
        vpc_table: &VpcTable,
        #[allow(unused_variables)] disable_randomness: bool,
    ) -> Result<(), ConfigError> {
        let new_config = StatefulNatConfig::new(vpc_table);

        let old_allocator_guard = self.allocator.load();
        let Some(old_allocator) = old_allocator_guard.as_deref() else {
            // No existing allocator, build a new one
            #[cfg(test)]
            let new_allocator =
                NatAllocator::from_config(&new_config)?.set_disable_randomness(disable_randomness);
            #[cfg(not(test))]
            let new_allocator = NatAllocator::from_config(&new_config)?;

            self.allocator.store(Some(Arc::new(new_allocator)));
            self.config = new_config;
            return Ok(());
        };

        if self.config == new_config {
            // Nothing to update, simply return
            return Ok(());
        }

        let new_allocator =
            Self::update_existing_allocator(Some(old_allocator), &self.config, &new_config)?;
        // Swap allocators; the old one is dropped.
        self.allocator.store(Some(Arc::new(new_allocator)));
        self.config = new_config;
        debug!("Updated allocator for stateful NAT");
        Ok(())
    }

    pub fn update_allocator(&mut self, vpc_table: &VpcTable) -> Result<(), ConfigError> {
        self.update_allocator_and_set_randomness(vpc_table, false)
    }

    #[cfg(test)]
    pub fn update_allocator_and_turn_off_randomness(
        &mut self,
        vpc_table: &VpcTable,
    ) -> Result<(), ConfigError> {
        self.update_allocator_and_set_randomness(vpc_table, true)
    }

    fn update_existing_allocator(
        _allocator: Option<&NatAllocator>,
        _old_config: &StatefulNatConfig,
        new_config: &StatefulNatConfig,
    ) -> Result<NatAllocator, ConfigError> {
        #[allow(clippy::let_and_return)] // temporary
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
        NatAllocator::from_config(new_config)
    }
}

impl Default for NatAllocatorWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct NatAllocatorReader(Arc<ArcSwapOption<NatAllocator>>);

impl NatAllocatorReader {
    pub fn get(&self) -> Option<Arc<NatAllocator>> {
        self.0.load().clone()
    }
    #[must_use]
    pub fn factory(&self) -> NatAllocatorReaderFactory {
        NatAllocatorReaderFactory(self.clone())
    }
    pub fn inner(&self) -> Arc<ArcSwapOption<NatAllocator>> {
        self.0.clone()
    }
}

#[derive(Debug)]
pub struct NatAllocatorReaderFactory(NatAllocatorReader);
impl NatAllocatorReaderFactory {
    #[must_use]
    pub fn handle(&self) -> NatAllocatorReader {
        self.0.clone()
    }
}
