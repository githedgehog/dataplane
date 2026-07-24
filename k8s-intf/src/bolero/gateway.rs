// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, TypeGenerator};

use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;

use crate::bolero::LegalValue;
use crate::bolero::Normalize;

use crate::gateway_agent_crd::{
    GatewayAgentGateway, GatewayAgentGatewayGroups, GatewayAgentGatewayInterfaces,
    GatewayAgentGatewayLogs, GatewayAgentGatewayNeighbors, GatewayAgentGatewayProfiling,
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
        let mut neighbors = Vec::new();
        for _ in 0..n_neighbors {
            neighbors.push(d.produce::<LegalValue<GatewayAgentGatewayNeighbors>>()?.0);
        }

        let n_groups = d.gen_usize(Bound::Included(&1), Bound::Included(&4))?;
        let mut groups = Vec::new();
        for _ in 0..n_groups {
            groups.push(d.produce::<LegalValue<GatewayAgentGatewayGroups>>()?.0);
        }

        Some(LegalValue(GatewayAgentGateway {
            asn: Some(d.gen_u32(Bound::Included(&1), Bound::Unbounded)?),
            // The converter requires this to be non-zero and to fit in a `usize`; zero is an
            // illegal value, so it is left to the hostile generators to produce.
            flow_table_capacity: d.produce::<Option<u32>>()?.map(|capacity| capacity.max(1)),
            groups: Some(groups),
            logs: Some(d.produce::<LegalValue<GatewayAgentGatewayLogs>>()?.take()),
            interfaces: Some(interfaces).filter(|i| !i.is_empty()),
            neighbors: Some(neighbors).filter(|n| !n.is_empty()),
            profiling: d
                .produce::<Option<bool>>()?
                .map(|enabled| GatewayAgentGatewayProfiling {
                    enabled: Some(enabled),
                }),
            protocol_ip: Some(format!(
                "{}/{}",
                d.produce::<UnicastIpv4Addr>()?,
                d.gen_u8(Bound::Included(&0), Bound::Included(&32))?
            )),
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
            flow_table_capacity: self.flow_table_capacity,
            groups: self.groups.clone(),
            logs: self.logs.clone(),
            interfaces: self
                .interfaces
                .clone()
                .and_then(|item| Some(item.normalize()).filter(|i| !i.is_empty())),
            neighbors: self
                .neighbors
                .clone()
                .and_then(|item| Some(item.normalize()).filter(|i| !i.is_empty())),
            profiling: self.profiling.clone(),
            protocol_ip: self.protocol_ip.clone(),
            vtep_ip: self.vtep_ip.clone(),
            vtep_mac: self.vtep_mac.clone(),
            vtep_mtu: self.vtep_mtu,
            workers: self.workers,
        }
    }
}
