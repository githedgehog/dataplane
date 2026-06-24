// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (Routes)

use super::NatRequirement;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::vpc::ValidatedPeering;
use config::external::overlay::vpcpeering::ValidatedExpose;
use lpm::prefix::Prefix;
use lpm::prefix::with_ports::{L4Protocol, PortRange};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Protocol(NextHeader);

impl Protocol {
    fn from_l4proto(l4_proto: L4Protocol) -> Option<Self> {
        match l4_proto {
            L4Protocol::Tcp => Some(Self(NextHeader::TCP)),
            L4Protocol::Udp => Some(Self(NextHeader::UDP)),
            L4Protocol::Any => None,
        }
    }

    fn from_expose(expose: &ValidatedExpose) -> Option<Self> {
        expose.nat().and_then(|nat| Self::from_l4proto(nat.proto))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteEndPrefix {
    dst: Prefix,
    proto: Option<Protocol>,
    dst_port: Option<PortRange>,
    dst_vpcd: VpcDiscriminant,
    dst_nat: Option<NatRequirement>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RemotePeeringEndTable {
    prefixes: Vec<RemoteEndPrefix>,
    has_default: bool,
}

impl RemotePeeringEndTable {
    fn from_peering(remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) -> Self {
        let mut table = Self::default();
        for remote_expose in peering
            .remote()
            .valexp()
            .iter()
            .filter(|expose| expose.can_receive_connection())
        {
            for remote_prefix in remote_expose.public_ips() {
                table.prefixes.push(RemoteEndPrefix {
                    dst: remote_prefix.prefix(),
                    proto: Protocol::from_expose(remote_expose),
                    dst_port: remote_prefix.ports(),
                    dst_vpcd: remote_vpcd,
                    dst_nat: NatRequirement::from_expose(remote_expose),
                });
            }
        }
        table.has_default = peering.remote().has_default_expose();
        table
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalEndPrefix {
    src: Prefix,
    proto: Option<Protocol>,
    src_port: Option<PortRange>,
    src_nat: Option<NatRequirement>,
}

impl LocalPeeringEndTable {
    fn from_peering(peering: &ValidatedPeering) -> Self {
        let mut table = Self::default();
        for local_expose in peering
            .local()
            .valexp()
            .iter()
            .filter(|expose| expose.can_init_connection())
        {
            for local_prefix in local_expose.ips() {
                table.prefixes.push(LocalEndPrefix {
                    src: local_prefix.prefix(),
                    proto: Protocol::from_expose(local_expose),
                    src_port: local_prefix.ports(),
                    src_nat: NatRequirement::from_expose(local_expose),
                });
            }
        }
        table.has_default = peering.local().has_default_expose();
        table
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LocalPeeringEndTable {
    prefixes: Vec<LocalEndPrefix>,
    has_default: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PeeringTable {
    local: LocalPeeringEndTable,
    remote: RemotePeeringEndTable,
}

impl PeeringTable {
    fn from_peering(remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) -> Self {
        Self {
            local: LocalPeeringEndTable::from_peering(peering),
            remote: RemotePeeringEndTable::from_peering(remote_vpcd, peering),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PeeringTables {
    tables: HashMap<VpcDiscriminant, PeeringTable>,
}

impl PeeringTables {
    fn add_peering(
        &mut self,
        local_vpcd: VpcDiscriminant,
        remote_vpcd: VpcDiscriminant,
        peering: &ValidatedPeering,
    ) {
        let table = PeeringTable::from_peering(remote_vpcd, peering);
        self.tables.insert(local_vpcd, table);
    }
}

impl From<&ValidatedOverlay> for PeeringTables {
    fn from(overlay: &ValidatedOverlay) -> Self {
        let mut map = Self::default();
        for vpc in overlay.vpc_table().values() {
            let local_vpcd = VpcDiscriminant::VNI(vpc.vni());
            for peering in vpc.peerings() {
                let remote_vpcd = VpcDiscriminant::VNI(overlay.vpc_table().get_remote_vni(peering));
                map.add_peering(local_vpcd, remote_vpcd, peering);
            }
        }
        map
    }
}
