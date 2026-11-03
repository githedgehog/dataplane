// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ordered peering matches selecting a named meter.

use acl::table::{Backend, RuleRow, Table, build_table};
use config::ConfigError;
use config::external::overlay::acl::{AclProtoMatch, ValidatedAclPattern};
use config::external::overlay::ratelimit::ValidatedRateLimitRule;
use lpm::prefix::Prefix;
use lpm::prefix::with_ports::{KeyPort, PORT_RANGE_WILDCARD};
use match_action::{Erased, ExactSpec, MatchKey, PrefixSpec, RangeSpec};
use net::buffer::PacketBufferMut;
use net::headers::{Net, Transport, TryHeaders, TryIp, UpperLayerProto};
use net::ip::{IpAddress, NextHeader};
use net::packet::{Packet, VpcDiscriminant};
use net::parse::DeParse;
use net::tcp::TcpFlags;
use net::vxlan::Vni;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A rule's position in its configuration.
pub type RuleIndex = usize;

/// Selects the first matching rule.
pub trait Classify: Send + Sync {
    /// What the bytes components of its rules' meters count.
    const BILLING: Billing;
    /// The rule matching this packet, if any.
    fn classify<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> Option<RuleIndex>;
}

/// What a byte of a meter's bytes component is: the unit its rates and bursts are in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Billing {
    /// A byte of the IP packet, or of anything the frame carries after it, as its VPC sent it:
    /// what a peering's rate limit is about.
    Ip,
    /// A byte of the outer IP packet a VPC's packet arrived in, VXLAN encapsulation included: what
    /// reaches the gateway, and what a NIC meter counts (IP length, without L2).
    OuterIp,
}

impl Billing {
    /// The bytes `packet` is charged, if it can be: `None` for packets that are not IP, or, for
    /// [`Billing::OuterIp`], were not received encapsulated.
    pub(crate) fn bytes<Buf: PacketBufferMut>(self, packet: &Packet<Buf>) -> Option<u32> {
        match self {
            Billing::Ip => billed_bytes(packet),
            Billing::OuterIp => packet.meta().outer_ip_len.map(u32::from),
        }
    }
}

/// What a rate-limit rule matches: the directed peering, addresses, protocol, ports and TCP flags.
///
/// Its derived `PeeringKeyRule` is the typed rule each table keeps, which offloads lower.
#[derive(Debug, MatchKey, Clone, PartialEq, Eq)]
pub struct PeeringKey<I> {
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
    #[mask]
    tcp_flags: TcpFlags,
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

    /// The IPv4 rules, in first-match order, each with the index of the configured rule it came
    /// from.
    #[must_use]
    pub fn v4(&self) -> &[RuleRow<PeeringKey<Ipv4Addr>, RuleIndex>] {
        self.v4.rules()
    }

    /// The IPv6 rules, in first-match order.
    #[must_use]
    pub fn v6(&self) -> &[RuleRow<PeeringKey<Ipv6Addr>, RuleIndex>] {
        self.v6.rules()
    }
}

/// One row of a family's table: a pair of a rule's sources and destinations of family `I`, with
/// their ports, and the rule's index.
pub(crate) struct Row<'r, R, I: IpVersion> {
    pub(crate) index: RuleIndex,
    pub(crate) rule: &'r R,
    pub(crate) proto: AclProtoMatch,
    pub(crate) source: PrefixSpec<I>,
    pub(crate) destination: PrefixSpec<I>,
    pub(crate) src_port: RangeSpec<KeyPort>,
    pub(crate) dst_port: RangeSpec<KeyPort>,
}

/// The rows family `I`'s table gets of `rules`, in their order: every pair of a rule's sources and
/// destinations of the family. Both classifiers' tables are made of these.
pub(crate) fn rows<R, I: IpVersion>(
    rules: &[R],
    pattern: impl Fn(&R) -> &ValidatedAclPattern,
) -> Vec<Row<'_, R, I>> {
    let mut rows = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let pattern = pattern(rule);
        for src in pattern.src() {
            let Some(source) = I::prefix_spec(src.prefix()) else {
                continue;
            };
            for dst in pattern.dst() {
                let Some(destination) = I::prefix_spec(dst.prefix()) else {
                    continue;
                };
                rows.push(Row {
                    index,
                    rule,
                    proto: pattern.proto(),
                    source,
                    destination,
                    src_port: src.ports().map_or(PORT_RANGE_WILDCARD, Into::into),
                    dst_port: dst.ports().map_or(PORT_RANGE_WILDCARD, Into::into),
                });
            }
        }
    }
    rows
}

fn table<I: IpVersion>(
    rules: &[ValidatedRateLimitRule],
    backend: Backend,
) -> Result<Table<PeeringKey<I>, RuleIndex>, ConfigError> {
    let lowered = rows::<_, I>(rules, |r| &r.pattern)
        .into_iter()
        .map(|row| {
            let key = PeeringKeyRule {
                proto: row.proto.into(),
                src_vni: ExactSpec::new(row.rule.from),
                dst_vni: ExactSpec::new(row.rule.to),
                source: row.source,
                destination: row.destination,
                src_port: row.src_port,
                dst_port: row.dst_port,
                tcp_flags: row.proto.tcp_flags().into(),
            };
            (key, key.into_backend_fields::<Erased>(), row.index)
        })
        .collect();
    build_table(backend, I::NAME, lowered).map_err(ConfigError::FailureApply)
}

/// What a rule matches of a packet beyond its VPCs.
pub(crate) struct Fields {
    pub(crate) proto: NextHeader,
    pub(crate) source: IpAddr,
    pub(crate) destination: IpAddr,
    pub(crate) src_port: KeyPort,
    pub(crate) dst_port: KeyPort,
    pub(crate) tcp_flags: TcpFlags,
}

impl Fields {
    /// `None` for a packet that is not IP, or whose upper-layer protocol is indeterminate.
    pub(crate) fn of<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<Fields> {
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
        // The parser may have read ports and flags from fragment payload.
        let transport = transport.filter(|_| !matches!(upper, UpperLayerProto::NonFirstFragment));
        let ports = transport.and_then(|t| t.src_port().zip(t.dst_port()));
        Some(Fields {
            proto,
            source: net.src_addr(),
            destination: net.dst_addr(),
            src_port: KeyPort::new(ports.map(|p| p.0)),
            dst_port: KeyPort::new(ports.map(|p| p.1)),
            tcp_flags: match transport {
                Some(Transport::Tcp(tcp)) => tcp.flags(),
                _ => TcpFlags::empty(),
            },
        })
    }
}

impl Classify for PeeringRules {
    const BILLING: Billing = Billing::Ip;

    fn classify<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> Option<RuleIndex> {
        let VpcDiscriminant::VNI(src_vni) = packet.meta().src_vpcd?;
        let VpcDiscriminant::VNI(dst_vni) = packet.meta().dst_vpcd?;
        let Fields {
            proto,
            source,
            destination,
            src_port,
            dst_port,
            tcp_flags,
        } = Fields::of(packet)?;
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => self.v4.lookup(&PeeringKey {
                proto,
                src_vni,
                dst_vni,
                source,
                destination,
                src_port,
                dst_port,
                tcp_flags,
            }),
            (IpAddr::V6(source), IpAddr::V6(destination)) => self.v6.lookup(&PeeringKey {
                proto,
                src_vni,
                dst_vni,
                source,
                destination,
                src_port,
                dst_port,
                tcp_flags,
            }),
            _ => None,
        }
        .copied()
    }
}

pub(crate) trait IpVersion: IpAddress {
    const NAME: &'static str;
    const INGRESS: &'static str;
    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>>;
}
impl IpVersion for Ipv4Addr {
    const NAME: &'static str = "rate_limit_v4";
    const INGRESS: &'static str = "ingress_v4";
    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>> {
        match prefix {
            Prefix::IPV4(p) => Some(p.into()),
            Prefix::IPV6(_) => None,
        }
    }
}
impl IpVersion for Ipv6Addr {
    const NAME: &'static str = "rate_limit_v6";
    const INGRESS: &'static str = "ingress_v6";
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

/// The shortest Ethernet frame, without its FCS. A shorter one leaves padded to this length.
const MIN_FRAME: u32 = 60;

/// The bytes a packet is charged: the length its IP header states or, if more, what the frame
/// carries from the IP header on. Whatever trails the datagram in the frame is forwarded with it,
/// so a short datagram in a long frame must not be charged as a short packet. Padding up to the
/// shortest Ethernet frame is not charged: the frame would leave that long anyway. `None` for
/// packets that are not IP.
pub(crate) fn billed_bytes<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<u32> {
    let headers = packet.headers();
    let stated = ip_bytes(headers.try_ip()?);
    let frame = u32::from(packet.total_len());
    if frame <= MIN_FRAME {
        return Some(stated);
    }
    let l2 = headers.eth().map_or(0, |eth| u32::from(eth.size().get()))
        + headers
            .vlan()
            .iter()
            .map(|vlan| u32::from(vlan.size().get()))
            .sum::<u32>();
    Some(stated.max(frame.saturating_sub(l2)))
}
