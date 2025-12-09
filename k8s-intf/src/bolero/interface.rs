// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

use hardware::pci::address::PciAddress;

use crate::bolero::LegalValue;
use crate::bolero::Normalize;
use crate::bolero::support::{
    UniqueV4InterfaceAddressGenerator, UniqueV6InterfaceAddressGenerator,
};
use crate::gateway_agent_crd::GatewayAgentGatewayInterfaces;

//FIXME Currently, the unique address generators are not exhaustive and so we cannot generate all legal values for GatewayAgentGatewayInterfaces.
impl TypeGenerator for LegalValue<GatewayAgentGatewayInterfaces> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let ips = if d.gen_bool(None)? {
            let count_v4 = d.gen_u16(Bound::Included(&0), Bound::Included(&10))?;
            let count_v6 = d.gen_u16(Bound::Included(&0), Bound::Included(&10))?;
            let addrs_v4 = UniqueV4InterfaceAddressGenerator::new(count_v4).generate(d)?;
            let addrs_v6 = UniqueV6InterfaceAddressGenerator::new(count_v6).generate(d)?;
            Some(addrs_v4.into_iter().chain(addrs_v6).collect())
        } else {
            None
        };

        Some(LegalValue(GatewayAgentGatewayInterfaces {
            ips,
            mtu: if d.gen_bool(None)? {
                Some(d.gen_u32(Bound::Included(&1280), Bound::Included(&9194))?)
            } else {
                None
            },
            kernel: None, // We don't really use this so keep it at false for now
            pci: if d.gen_bool(None)? {
                Some(d.produce::<PciAddress>()?.to_string())
            } else {
                None
            },
        }))
    }
}

impl Normalize for GatewayAgentGatewayInterfaces {
    fn normalize(&self) -> Self {
        GatewayAgentGatewayInterfaces {
            ips: self.ips.clone().map(|mut ips| {
                ips.sort();
                ips
            }),
            kernel: self.kernel.clone(),
            mtu: self.mtu,
            pci: self.pci.clone(),
        }
    }
}
