// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, TypeGenerator};

use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;

use crate::bolero::LegalValue;
use crate::bolero::NoneIfEmpty;
use crate::bolero::Normalize;
use crate::gateway_agent_crd::{
    GatewayAgentGateway, GatewayAgentGatewayInterfaces, GatewayAgentGatewayNeighbors,
};

impl TypeGenerator for LegalValue<GatewayAgentGateway> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let n_interfaces = d.gen_usize(Bound::Included(&0), Bound::Included(&10))?;
        let mut interfaces = BTreeMap::new();
        for i in 0..n_interfaces {
            interfaces.insert(
                format!("eth{i}"),
                d.produce::<LegalValue<GatewayAgentGatewayInterfaces>>()?.0,
            );
        }

        let n_neighbors = d.gen_usize(Bound::Included(&0), Bound::Included(&10))?;
        let mut neighbors = Vec::with_capacity(n_neighbors);
        for _ in 0..n_neighbors {
            neighbors.push(d.produce::<LegalValue<GatewayAgentGatewayNeighbors>>()?.0);
        }

        Some(LegalValue(GatewayAgentGateway {
            asn: Some(d.gen_u32(Bound::Included(&1), Bound::Unbounded)?),
            logs: None, // FIXME(manishv) Add a proper implementation
            interfaces: interfaces.none_if_empty(),
            neighbors: neighbors.none_if_empty(),
            profiling: None, // FIXME(manishv) Add a proper implementation
            protocol_ip: Some(d.produce::<UnicastIpv4Addr>()?.to_string()),
            vtep_ip: Some(format!(
                "{}/{}",
                d.produce::<UnicastIpv4Addr>()?,
                d.gen_u8(Bound::Included(&0), Bound::Included(&32))?
            )),
            vtep_mac: Some(d.produce::<SourceMac>()?.to_string()),
            vtep_mtu: None, // We never use this, should we just remove it, it doesn't really make sense
            workers: Some(d.gen_u8(Bound::Included(&1), Bound::Unbounded)?),
        }))
    }
}

impl Normalize for GatewayAgentGateway {
    fn normalize(&self) -> Self {
        GatewayAgentGateway {
            asn: self.asn,
            logs: self.logs.clone(),
            interfaces: self
                .interfaces
                .as_ref()
                .and_then(|item| item.normalize().none_if_empty()),
            neighbors: self
                .neighbors
                .as_ref()
                .and_then(|item| item.normalize().none_if_empty()),
            profiling: self.profiling.clone(),
            protocol_ip: self.protocol_ip.clone(),
            vtep_ip: self.vtep_ip.clone(),
            vtep_mac: self.vtep_mac.clone(),
            vtep_mtu: self.vtep_mtu,
            workers: self.workers,
        }
    }
}
