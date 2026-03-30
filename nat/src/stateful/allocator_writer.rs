// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::NatDefaultAllocator;
use arc_swap::ArcSwapOption;
use config::GenId;
use config::external::overlay::vpc::Peering;
use config::external::overlay::vpc::VpcTable;
use config::external::overlay::vpcpeering::VpcExpose;
use flow_entry::flow_table::FlowTable;
use net::packet::VpcDiscriminant;
use std::sync::Arc;
use tracing::debug;

use crate::stateful::flows::check_masquerading_flows;
use crate::stateful::flows::invalidate_all_masquerading_flows;
use crate::stateful::flows::upgrade_all_masquerading_flows;

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

    pub(crate) fn num_masquerading_peerings(&self) -> usize {
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

    #[must_use]
    pub fn get_reader_factory(&self) -> NatAllocatorReaderFactory {
        self.get_reader().factory()
    }

    /// Replace the nat allocator with a new one
    pub fn update_nat_allocator(&mut self, nat_config: StatefulNatConfig, flow_table: &FlowTable) {
        let genid = nat_config.genid();
        let curr_allocator = self.allocator.load();

        // keep state as-is if config did not change, and just upgrade flows
        if nat_config == self.config {
            debug!("No need to update NAT allocator: NAT peerings did not change");
            if curr_allocator.is_some() {
                upgrade_all_masquerading_flows(flow_table, genid);
            }
            return;
        }

        // if we transition to a config wo/ masquerading, flush allocator and remove flows
        if nat_config.num_masquerading_peerings() == 0 {
            if curr_allocator.is_some() {
                debug!("No stateful NAT is required anymore: will invalidate flows");
                invalidate_all_masquerading_flows(flow_table);
                self.allocator.store(None);
            }
            return;
        }

        // build a new allocator
        let mut allocator = NatDefaultAllocator::from_config(&nat_config);
        if curr_allocator.is_some() {
            check_masquerading_flows(flow_table, &nat_config, &mut allocator);
        }

        // replace
        self.allocator.store(Some(Arc::new(allocator)));
        self.config = nat_config;
        debug!("Updated stateful NAT allocator");
    }
}

impl Default for NatAllocatorWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct NatAllocatorReader(Arc<ArcSwapOption<NatDefaultAllocator>>);

impl NatAllocatorReader {
    pub fn get(&self) -> Option<Arc<NatDefaultAllocator>> {
        self.0.load().clone()
    }
    #[must_use]
    pub fn factory(&self) -> NatAllocatorReaderFactory {
        NatAllocatorReaderFactory(self.clone())
    }
    pub fn inner(&self) -> Arc<ArcSwapOption<NatDefaultAllocator>> {
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
