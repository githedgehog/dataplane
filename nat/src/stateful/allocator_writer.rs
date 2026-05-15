// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::apalloc::NatAllocator;
use concurrency::slot::SlotOption;
use concurrency::sync::Arc;
use config::GenId;
use config::external::overlay::vpc::{ValidatedPeering, ValidatedVpcTable};
use config::external::overlay::vpcpeering::ValidatedExpose;
use flow_entry::flow_table::FlowTable;
use net::packet::VpcDiscriminant;
use tracing::debug;

use crate::stateful::flows::check_masquerading_flows;
use crate::stateful::flows::invalidate_all_masquerading_flows;
use crate::stateful::flows::upgrade_all_masquerading_flows;

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct StatefulNatPeering {
    pub(crate) src_vpcd: VpcDiscriminant,
    pub(crate) dst_vpcd: VpcDiscriminant,
    pub(crate) peering: ValidatedPeering,
}
#[derive(Debug, Default, Clone)]
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
    pub fn new(vpc_table: &ValidatedVpcTable, genid: GenId) -> Self {
        let mut peerings = Vec::new();
        for vpc in vpc_table.values() {
            for peering in vpc.local_stateful_nat_peerings() {
                peerings.push(StatefulNatPeering {
                    src_vpcd: VpcDiscriminant::from_vni(vpc.vni()),
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

    pub(crate) fn has_masquerading_peerings(&self) -> bool {
        self.peerings.iter().map(|p| &p.peering).any(|p| {
            p.local()
                .valexp()
                .iter()
                .any(ValidatedExpose::has_stateful_nat)
        })
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
pub struct NatAllocatorWriter(Arc<SlotOption<NatAllocator>>);

impl NatAllocatorWriter {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(SlotOption::empty()))
    }

    #[must_use]
    pub fn get_reader(&self) -> NatAllocatorReader {
        NatAllocatorReader(self.0.clone())
    }

    #[must_use]
    pub fn get_reader_factory(&self) -> NatAllocatorReaderFactory {
        self.get_reader().factory()
    }

    /// Replace the nat allocator with a new one for the new config. If the config is such that
    /// no masquerading is needed no allocator will be stored and the existing one, if any, be
    /// removed. Flows using that allocator will be cancelled. If, instead, a new, distinct
    /// masquerading config is provided, a new allocator will be installed and the flows using the
    /// previous one be either invalidated or adapted to use the new allocator: their ports/ips
    /// will be transferred (reserved) in the new allocator.
    pub fn update_nat_allocator(&mut self, nat_config: StatefulNatConfig, flow_table: &FlowTable) {
        let genid = nat_config.genid();
        let curr_allocator = self.0.load_full();

        // keep state as-is if config did not change, and just upgrade flows
        if let Some(current) = curr_allocator.as_ref()
            && current.config() == &nat_config
        {
            debug!("No need to update NAT allocator: NAT peerings did not change");
            upgrade_all_masquerading_flows(flow_table, genid);
            return;
        }

        // if we transition to a config without masquerading, flush allocator and remove all flows
        if !nat_config.has_masquerading_peerings() {
            if curr_allocator.is_some() {
                debug!("No stateful NAT is required anymore: will invalidate flows");
                self.0.store(None);
                invalidate_all_masquerading_flows(flow_table);
            }
            return;
        }

        let mut allocator = NatAllocator::new(nat_config);
        if curr_allocator.is_some() {
            let guard = check_masquerading_flows(flow_table, &mut allocator);
            debug!("Replacing stateful NAT allocator...");
            self.0.store(Some(Arc::new(allocator)));
            debug!("NAT allocator has been replaced");
            drop(guard);
        } else {
            debug!("Installing new stateful NAT allocator...");
            self.0.store(Some(Arc::new(allocator)));
            debug!("NAT allocator is installed");
        }
    }
}

impl Default for NatAllocatorWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct NatAllocatorReader(Arc<SlotOption<NatAllocator>>);

impl NatAllocatorReader {
    pub fn get(&self) -> Option<Arc<NatAllocator>> {
        self.0.load_full()
    }
    #[must_use]
    pub fn factory(&self) -> NatAllocatorReaderFactory {
        NatAllocatorReaderFactory(self.clone())
    }
    pub fn inner(&self) -> Arc<SlotOption<NatAllocator>> {
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
