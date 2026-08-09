// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::masquerade::apalloc::NatAllocator;
use concurrency::slot::SlotOption;
use concurrency::sync::Arc;
use config::GenId;
use config::external::overlay::vpc::{ValidatedPeering, ValidatedVpcTable};
use config::external::overlay::vpcpeering::ValidatedExpose;
use flow_entry::flow_table::FlowTable;
use net::packet::VpcDiscriminant;
use tracing::debug;

use crate::masquerade::flows::reconcile_nat_flows;
use crate::masquerade::flows::remove_allocator_from_flows;
use crate::masquerade::flows::upgrade_all_masquerading_flows;

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct MasqueradePeering {
    pub(crate) src_vpcd: VpcDiscriminant,
    pub(crate) dst_vpcd: VpcDiscriminant,
    pub(crate) peering: ValidatedPeering,
}
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MasqueradeConfig {
    peerings: Vec<MasqueradePeering>,
    randomize: bool,
}

impl MasqueradeConfig {
    #[must_use]
    pub fn new(vpc_table: &ValidatedVpcTable) -> Self {
        let mut peerings = Vec::new();
        for vpc in vpc_table.values() {
            for peering in vpc.local_stateful_nat_peerings() {
                peerings.push(MasqueradePeering {
                    src_vpcd: VpcDiscriminant::from_vni(vpc.vni()),
                    dst_vpcd: VpcDiscriminant::from_vni(vpc_table.get_remote_vni(peering)),
                    peering: peering.clone(),
                });
            }
        }
        Self {
            peerings,
            randomize: true, // randomize by default
        }
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

    pub(crate) fn iter(&self) -> impl Iterator<Item = &MasqueradePeering> {
        self.peerings.iter()
    }

    pub(crate) fn has_masquerading_peerings(&self) -> bool {
        self.peerings.iter().map(|p| &p.peering).any(|p| {
            p.local()
                .valexp()
                .iter()
                .any(ValidatedExpose::has_masquerade)
        })
    }

    pub(crate) fn get_peering(
        &self,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
    ) -> Option<&MasqueradePeering> {
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

    /// Install the allocator for a new NAT configuration.
    ///
    /// Removing masquerade invalidates NAT flows and clears port-forward leases. Replacement
    /// carries compatible allocations forward.
    pub fn update_nat_allocator(
        &mut self,
        nat_config: MasqueradeConfig,
        genid: GenId,
        flow_table: &FlowTable,
    ) {
        let curr_allocator = self.0.load_full();

        // keep state as-is if config did not change, and just upgrade flows
        if let Some(current) = curr_allocator.as_ref()
            && current.config() == &nat_config
        {
            debug!("No need to update NAT allocator: NAT peerings did not change");
            current.set_genid(genid);
            upgrade_all_masquerading_flows(flow_table, genid);
            return;
        }

        // if we transition to a config without masquerading, flush allocator and remove all flows
        if !nat_config.has_masquerading_peerings() {
            if curr_allocator.is_some() {
                debug!("Removing masquerade allocator and its flow state");
                self.0.store(None);
                remove_allocator_from_flows(flow_table);
            }
            return;
        }

        let allocator = NatAllocator::new(nat_config, genid);
        let guard = reconcile_nat_flows(flow_table, &allocator);
        debug!("Installing masquerade NAT allocator...");
        self.0.store(Some(Arc::new(allocator)));
        drop(guard);
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
