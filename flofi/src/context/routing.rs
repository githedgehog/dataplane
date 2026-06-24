// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (Routes)

use super::NatRequirement;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::vpc::ValidatedPeering;
use lpm::prefix::Prefix;
use lpm::prefix::with_ports::{L4Protocol, PortRange};
use net::FlowKey;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::net::IpAddr;

const PORT_RANGE_WILDCARD: RangeSpec<u16> = RangeSpec::new(0, u16::MAX);

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeeringPrefixInfo {
    ip_range: Prefix,
    proto: L4Protocol,
    port_range: Option<PortRange>,
    dst_vpcd: VpcDiscriminant,
    nat_mode: Option<NatRequirement>,
}

impl From<&PeeringPrefixInfo> for RangeSpec<u16> {
    fn from(prefix: &PeeringPrefixInfo) -> Self {
        prefix
            .port_range
            .map_or(PORT_RANGE_WILDCARD, RangeSpec::from)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PeeringManifestInfo {
    prefixes: Vec<PeeringPrefixInfo>,
    has_default: bool,
}

impl PeeringManifestInfo {
    fn remote_end(remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) -> Self {
        let mut table = Self::default();
        for remote_expose in peering
            .remote()
            .valexp()
            .iter()
            .filter(|expose| expose.can_receive_connection())
        {
            for remote_prefix in remote_expose.public_ips() {
                table.prefixes.push(PeeringPrefixInfo {
                    ip_range: remote_prefix.prefix(),
                    proto: remote_expose.nat().map_or(L4Protocol::Any, |nat| nat.proto),
                    port_range: remote_prefix.ports(),
                    dst_vpcd: remote_vpcd,
                    nat_mode: NatRequirement::from_expose(remote_expose),
                });
            }
        }
        table.has_default = peering.remote().has_default_expose();
        table
    }

    fn local_end(remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) -> Self {
        let mut table = Self::default();
        for local_expose in peering
            .local()
            .valexp()
            .iter()
            .filter(|expose| expose.can_init_connection())
        {
            for local_prefix in local_expose.ips() {
                table.prefixes.push(PeeringPrefixInfo {
                    ip_range: local_prefix.prefix(),
                    proto: local_expose.nat().map_or(L4Protocol::Any, |nat| nat.proto),
                    port_range: local_prefix.ports(),
                    dst_vpcd: remote_vpcd,
                    nat_mode: NatRequirement::from_expose(local_expose),
                });
            }
        }
        table.has_default = peering.local().has_default_expose();
        table
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PeeringInfo {
    local: PeeringManifestInfo,
    remote: PeeringManifestInfo,
}

impl PeeringInfo {
    fn from_peering(remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) -> Self {
        Self {
            local: PeeringManifestInfo::local_end(remote_vpcd, peering),
            remote: PeeringManifestInfo::remote_end(remote_vpcd, peering),
        }
    }
}

// -----------------------------------------------------------------------

use acl::reference::table::{RefRule, ReferenceTable};
use match_action::{Erased, MatchKey, RangeSpec};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatMode {
    NoNat,
    StaticNat,
    Masquerade,
    PortForwarding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Verdict {
    nat_mode: NatMode,
    dst_vpcd: VpcDiscriminant,
}

trait FromPeeringEndPrefix {
    fn from(prefix: &PeeringPrefixInfo) -> Self;
}

impl FromPeeringEndPrefix for NatMode {
    fn from(prefix: &PeeringPrefixInfo) -> Self {
        prefix.nat_mode.into()
    }
}

impl FromPeeringEndPrefix for Verdict {
    fn from(prefix: &PeeringPrefixInfo) -> Self {
        Verdict {
            nat_mode: prefix.nat_mode.into(),
            dst_vpcd: prefix.dst_vpcd,
        }
    }
}

impl From<Option<NatRequirement>> for NatMode {
    fn from(nat: Option<NatRequirement>) -> Self {
        match nat {
            None => NatMode::NoNat,
            Some(NatRequirement::Static) => NatMode::StaticNat,
            Some(NatRequirement::Masquerade) => NatMode::Masquerade,
            Some(NatRequirement::PortForwarding) => NatMode::PortForwarding,
        }
    }
}

impl<V: FromPeeringEndPrefix> From<&PeeringPrefixInfo> for RefRule<V> {
    fn from(prefix: &PeeringPrefixInfo) -> Self {
        match prefix.ip_range {
            Prefix::IPV4(ip_range) => RefRule::new(
                TwoTupleIpv4Rule {
                    ip_range: ip_range.into(),
                    port_range: prefix.into(),
                }
                .into_backend_fields::<Erased>(),
                V::from(prefix),
            ),
            Prefix::IPV6(ip_range) => RefRule::new(
                TwoTupleIpv6Rule {
                    ip_range: ip_range.into(),
                    port_range: prefix.into(),
                }
                .into_backend_fields::<Erased>(),
                V::from(prefix),
            ),
        }
    }
}

struct PeeringEndContext<T, V> {
    tcp: ReferenceTable<T, V>,
    udp: ReferenceTable<T, V>,
    other: ReferenceTable<T, V>,
    has_default: bool,
}

impl<T, V> From<&PeeringManifestInfo> for PeeringEndContext<T, V>
where
    T: MatchKey,
    V: FromPeeringEndPrefix,
{
    fn from(table: &PeeringManifestInfo) -> Self {
        let mut tcp: Vec<RefRule<V>> = vec![];
        let mut udp: Vec<RefRule<V>> = vec![];
        let mut other: Vec<RefRule<V>> = vec![];

        for prefix in &table.prefixes {
            match prefix.proto {
                L4Protocol::Tcp => tcp.push(prefix.into()),
                L4Protocol::Udp => udp.push(prefix.into()),
                L4Protocol::Any => {
                    tcp.push(prefix.into());
                    udp.push(prefix.into());
                    other.push(prefix.into());
                }
            }
        }

        Self {
            tcp: ReferenceTable::new(tcp),
            udp: ReferenceTable::new(udp),
            other: ReferenceTable::new(other),
            has_default: table.has_default,
        }
    }
}

#[derive(MatchKey)]
struct TwoTupleIpv4 {
    #[prefix]
    ip_range: Ipv4Addr,
    #[range]
    port_range: u16,
}

struct PeeringContextIpv4 {
    local: PeeringEndContext<TwoTupleIpv4, NatMode>,
    remote: PeeringEndContext<TwoTupleIpv4, Verdict>,
}

impl From<&PeeringInfo> for PeeringContextIpv4 {
    fn from(table: &PeeringInfo) -> Self {
        Self {
            local: PeeringEndContext::from(&table.local),
            remote: PeeringEndContext::from(&table.remote),
        }
    }
}

impl PeeringContextIpv4 {
    fn lookup(&self, key: &FlowKey) -> (Verdict, NatMode) {
        let table = match key.proto() {
            NextHeader::TCP => &self.remote.tcp,
            NextHeader::UDP => &self.remote.udp,
            _ => &self.remote.other,
        };
        todo!()
    }
}

#[derive(MatchKey)]
struct TwoTupleIpv6 {
    #[prefix]
    ip_range: Ipv6Addr,
    #[range]
    port_range: u16,
}

struct PeeringContextIpv6 {
    local: PeeringEndContext<TwoTupleIpv6, NatMode>,
    remote: PeeringEndContext<TwoTupleIpv6, Verdict>,
}

impl From<&PeeringInfo> for PeeringContextIpv6 {
    fn from(table: &PeeringInfo) -> Self {
        Self {
            local: PeeringEndContext::from(&table.local),
            remote: PeeringEndContext::from(&table.remote),
        }
    }
}

#[derive(Default)]
pub(crate) struct PeeringTables {
    v4: HashMap<VpcDiscriminant, PeeringContextIpv4>,
    v6: HashMap<VpcDiscriminant, PeeringContextIpv6>,
}

impl From<&ValidatedOverlay> for PeeringTables {
    fn from(overlay: &ValidatedOverlay) -> Self {
        let mut map_v4 = HashMap::new();
        let mut map_v6 = HashMap::new();
        for vpc in overlay.vpc_table().values() {
            let local_vpcd = VpcDiscriminant::VNI(vpc.vni());
            for peering in vpc.peerings() {
                let remote_vpcd = VpcDiscriminant::VNI(overlay.vpc_table().get_remote_vni(peering));
                let table = PeeringInfo::from_peering(remote_vpcd, peering);
                if peering.is_v4() {
                    map_v4.insert(local_vpcd, PeeringContextIpv4::from(&table));
                } else {
                    map_v6.insert(local_vpcd, PeeringContextIpv6::from(&table));
                }
            }
        }
        Self {
            v4: map_v4,
            v6: map_v6,
        }
    }
}

impl PeeringTables {
    pub(crate) fn lookup(
        &self,
        src_vpcd: VpcDiscriminant,
        key: &FlowKey,
    ) -> Option<&PeeringContextIpv4> {
        todo!()
        /*
        match key.src_ip() {
            IpAddr::V4(_) => self.v4.get(&src_vpcd).lookup(key)
            IpAddr::V6(_) => self.v6.get(&src_vpcd).lookup(key)
        }
        */
    }
}
