// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ordered peering matches selecting a named meter.

use acl::table::{Backend, Table, build_table};
use config::ConfigError;
use config::external::overlay::ratelimit::ValidatedRateLimitRule;
use lpm::prefix::Prefix;
use lpm::prefix::with_ports::{KeyPort, PORT_RANGE_WILDCARD};
use match_action::{Erased, ExactSpec, MatchKey, PrefixSpec};
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryHeaders, UpperLayerProto};
use net::ip::{IpAddress, NextHeader};
use net::packet::{Packet, VpcDiscriminant};
use net::vxlan::Vni;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A rule's position in its configuration.
pub type RuleIndex = usize;

/// Selects the first matching rule.
pub trait Classify: Send + Sync {
    /// The rule matching this packet, if any.
    fn classify<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> Option<RuleIndex>;
}

#[derive(Debug, MatchKey, Clone, PartialEq, Eq)]
struct PeeringKey<I> {
    #[mask]
    proto: NextHeader,
    #[exact]
    src_vni: Vni,
    #[exact]
    dst_vni: Vni,
    #[prefix]
    source: I,
    #[prefix]
    destination: I,
    #[range]
    src_port: KeyPort,
    #[range]
    dst_port: KeyPort,
}

/// ACL-style matches scoped to a directed VPC peering, in configuration order.
#[derive(Debug)]
pub struct PeeringRules {
    v4: Table<PeeringKey<Ipv4Addr>, RuleIndex>,
    v6: Table<PeeringKey<Ipv6Addr>, RuleIndex>,
}

impl PeeringRules {
    /// A classifier matching no traffic.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            v4: Table::empty(),
            v6: Table::empty(),
        }
    }

    /// Compile ordered rules for either the DPDK or reference backend.
    ///
    /// # Errors
    ///
    /// Returns classifier construction errors.
    pub fn new(rules: &[ValidatedRateLimitRule], backend: Backend) -> Result<Self, ConfigError> {
        Ok(Self {
            v4: table::<Ipv4Addr>(rules, backend)?,
            v6: table::<Ipv6Addr>(rules, backend)?,
        })
    }
}

fn table<I: IpVersion>(
    rules: &[ValidatedRateLimitRule],
    backend: Backend,
) -> Result<Table<PeeringKey<I>, RuleIndex>, ConfigError> {
    let mut lowered = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        for src in rule.pattern.src() {
            let Some(source) = I::prefix_spec(src.prefix()) else {
                continue;
            };
            for dst in rule.pattern.dst() {
                let Some(destination) = I::prefix_spec(dst.prefix()) else {
                    continue;
                };
                let key = PeeringKeyRule {
                    proto: rule.pattern.proto().into(),
                    src_vni: ExactSpec::new(rule.from),
                    dst_vni: ExactSpec::new(rule.to),
                    source,
                    destination,
                    src_port: src.ports().map_or(PORT_RANGE_WILDCARD, Into::into),
                    dst_port: dst.ports().map_or(PORT_RANGE_WILDCARD, Into::into),
                };
                lowered.push((key, key.into_backend_fields::<Erased>(), index));
            }
        }
    }
    build_table(backend, I::NAME, lowered).map_err(ConfigError::FailureApply)
}

impl Classify for PeeringRules {
    fn classify<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> Option<RuleIndex> {
        let VpcDiscriminant::VNI(src_vni) = packet.meta().src_vpcd?;
        let VpcDiscriminant::VNI(dst_vni) = packet.meta().dst_vpcd?;
        let (_, net, transport) = packet
            .headers()
            .pat()
            .opt_eth()
            .net()
            .opt_transport()
            .done()?;
        let upper = packet.upper_layer_proto();
        let proto = match upper {
            UpperLayerProto::Carried(proto) => proto,
            UpperLayerProto::NonFirstFragment => NextHeader::FRAGMENT,
            UpperLayerProto::Indeterminate => return None,
        };
        let ports = match upper {
            UpperLayerProto::NonFirstFragment => None,
            _ => transport.and_then(|t| t.src_port().zip(t.dst_port())),
        };
        let src_port = KeyPort::new(ports.map(|p| p.0));
        let dst_port = KeyPort::new(ports.map(|p| p.1));
        match (net.src_addr(), net.dst_addr()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => self.v4.lookup(&PeeringKey {
                proto,
                src_vni,
                dst_vni,
                source,
                destination,
                src_port,
                dst_port,
            }),
            (IpAddr::V6(source), IpAddr::V6(destination)) => self.v6.lookup(&PeeringKey {
                proto,
                src_vni,
                dst_vni,
                source,
                destination,
                src_port,
                dst_port,
            }),
            _ => None,
        }
        .copied()
    }
}

trait IpVersion: IpAddress {
    const NAME: &'static str;
    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>>;
}
impl IpVersion for Ipv4Addr {
    const NAME: &'static str = "rate_limit_v4";
    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>> {
        match prefix {
            Prefix::IPV4(p) => Some(p.into()),
            Prefix::IPV6(_) => None,
        }
    }
}
impl IpVersion for Ipv6Addr {
    const NAME: &'static str = "rate_limit_v6";
    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>> {
        match prefix {
            Prefix::IPV6(p) => Some(p.into()),
            Prefix::IPV4(_) => None,
        }
    }
}

pub(crate) fn ip_bytes(net: &Net) -> u32 {
    match net {
        Net::Ipv4(ip) => u32::from(ip.total_len()),
        Net::Ipv6(ip) => u32::from(net::ipv6::Ipv6::MIN_LEN.get()) + u32::from(ip.payload_length()),
    }
}
