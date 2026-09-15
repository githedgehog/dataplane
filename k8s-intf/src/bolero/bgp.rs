// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator};

use net::interface::InterfaceName;
use net::ipv4::UnicastIpv4Addr;

use crate::bolero::{LegalValue, Normalize};
use crate::gateway_agent_crd::GatewayAgentGatewayNeighbors;

impl TypeGenerator for LegalValue<GatewayAgentGatewayNeighbors> {
    /// Generate a BGP neighbor entry the conversion will accept: a non-zero ASN,
    /// an interface name in `source`, and either an IPv4 address (a numbered
    /// peer) or none at all (an unnumbered peer peering over `source`).
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let asn = d.gen_u32(Bound::Included(&1), Bound::Included(&u32::MAX))?;

        let source = d.produce::<InterfaceName>()?.to_string();

        // An address-less entry is BGP unnumbered, and `source` then names the
        // interface to peer over rather than the update-source. Generate both
        // shapes.
        let ip = if d.produce::<bool>()? {
            None
        } else {
            Some(d.produce::<UnicastIpv4Addr>()?.to_string())
        };

        Some(LegalValue(GatewayAgentGatewayNeighbors {
            asn: Some(asn),
            ip,
            source: Some(source),
        }))
    }
}

impl Normalize for GatewayAgentGatewayNeighbors {
    fn normalize(&self) -> Self {
        self.clone()
    }
}
