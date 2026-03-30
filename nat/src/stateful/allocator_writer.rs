// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::apalloc::NatAllocator;
use arc_swap::ArcSwapOption;
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
#[derive(Debug, Default)]
pub struct StatefulNatConfig {
    genid: GenId,
    peerings: Vec<StatefulNatPeering>,
    randomize: bool,
}
impl PartialEq for StatefulNatConfig {
    fn eq(&self, other: &Self) -> bool {
        // we exclude genid from comparison
        self.peerings == other.peerings && self.randomize == other.randomize
    }
}

impl StatefulNatConfig {
    #[must_use]
    pub fn new(vpc_table: &VpcTable, genid: GenId) -> Self {
        let mut peerings = Vec::new();
        for vpc in vpc_table.values() {
            for peering in vpc.stateful_nat_peerings() {
                peerings.push(StatefulNatPeering {
                    src_vpcd: VpcDiscriminant::from_vni(vpc.vni),
                    dst_vpcd: VpcDiscriminant::from_vni(vpc_table.get_remote_vni(peering)),
                    peering: peering.clone(),
                });
            }
        }
        Self {
            genid,
            peerings,
            randomize: true, // randomize by default
        }
    }

    #[must_use]
    pub fn genid(&self) -> GenId {
        self.genid
    }

    #[must_use]
    pub fn set_randomize(mut self, value: bool) -> Self {
        self.randomize = value;
        self
    }

    #[must_use]
    pub fn randomize(&self) -> bool {
        self.randomize
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &StatefulNatPeering> {
        self.peerings.iter()
    }

    pub(crate) fn num_stateful_nat_peerings(&self) -> usize {
        self.peerings
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
        self.peerings
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
    pub fn update_nat_allocator(&mut self, nat_config: StatefulNatConfig, flow_table: &FlowTable) {
        let genid = nat_config.genid();

        // freeze the current allocator ?
        let old_allocator = self.allocator.load();

        if nat_config == self.config && old_allocator.is_some() {
            debug!("No need to update NAT allocator: NAT peerings did not change");
            upgrade_all_stateful_nat_flows(flow_table, genid);
            return;
        }
        if nat_config.num_stateful_nat_peerings() == 0 {
            debug!("Stateful NAT is not required: will invalidate flows and remove allocator");
            invalidate_all_stateful_nat_flows(flow_table);
            self.allocator.store(None);
            return;
        }

        // build a new allocator to replace the current
        let mut allocator = NatAllocator::from_config(&nat_config);
        if old_allocator.is_some() {
            validate_stateful_nat_flows(flow_table, &nat_config, &mut allocator);
        }
        self.allocator.store(Some(Arc::new(allocator)));
        self.config = nat_config;
        debug!("Updated allocator for stateful NAT");
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
