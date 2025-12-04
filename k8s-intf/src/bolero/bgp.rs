// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator};

use net::interface::InterfaceName;
use net::ipv4::UnicastIpv4Addr;

use crate::bolero::{LegalValue, Normalize};
use crate::gateway_agent_crd::GatewayAgentGatewayNeighbors;

impl TypeGenerator for LegalValue<GatewayAgentGatewayNeighbors> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let asn = d.gen_u32(Bound::Included(&1), Bound::Included(&u32::MAX))?;

        let ip = d.produce::<UnicastIpv4Addr>()?;
        let source = d.produce::<InterfaceName>()?.to_string();

        Some(LegalValue(GatewayAgentGatewayNeighbors {
            asn: Some(asn),
            ip: Some(ip.to_string()),
            source: Some(source),
        }))
    }
}

impl Normalize for GatewayAgentGatewayNeighbors {
    fn normalize(&self) -> Self {
        self.clone()
    }
}
