// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ordered matches on what a packet carries as it arrives from a VPC: the
//! [ingress policy](config::external::overlay::ingress).

use acl::table::{Backend, RuleRow, Table, build_table};
use config::ConfigError;
use config::external::overlay::ingress::ValidatedIngressRule;
use lpm::prefix::with_ports::KeyPort;
use match_action::{Erased, ExactSpec, MatchKey};
use net::buffer::PacketBufferMut;
use net::ip::NextHeader;
use net::packet::{Packet, VpcDiscriminant};
use net::tcp::TcpFlags;
use net::vxlan::Vni;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::classify::{Billing, Classify, Fields, IpVersion, RuleIndex, rows};

/// What an ingress rule matches: the source VPC, addresses, protocol, ports and TCP flags. No
/// destination VPC: that is the flow filter's decision, made later.
///
/// Its derived `IngressKeyRule` is the typed rule each table keeps, which offloads lower.
#[derive(Debug, MatchKey, Clone, PartialEq, Eq)]
pub struct IngressKey<I> {
    #[mask]
    proto: NextHeader,
    #[exact]
    src_vni: Vni,
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

/// The ingress policy's matches, in configuration order.
#[derive(Debug)]
pub struct IngressRules {
    v4: Table<IngressKey<Ipv4Addr>, RuleIndex>,
    v6: Table<IngressKey<Ipv6Addr>, RuleIndex>,
}

impl IngressRules {
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
    pub fn new(rules: &[ValidatedIngressRule], backend: Backend) -> Result<Self, ConfigError> {
        Ok(Self {
            v4: table::<Ipv4Addr>(rules, backend)?,
            v6: table::<Ipv6Addr>(rules, backend)?,
        })
    }

    /// The IPv4 rules, in first-match order, each with the index of the validated rule it came
    /// from.
    #[must_use]
    pub fn v4(&self) -> &[RuleRow<IngressKey<Ipv4Addr>, RuleIndex>] {
        self.v4.rules()
    }

    /// The IPv6 rules, in first-match order.
    #[must_use]
    pub fn v6(&self) -> &[RuleRow<IngressKey<Ipv6Addr>, RuleIndex>] {
        self.v6.rules()
    }
}

fn table<I: IpVersion>(
    rules: &[ValidatedIngressRule],
    backend: Backend,
) -> Result<Table<IngressKey<I>, RuleIndex>, ConfigError> {
    let lowered = rows::<_, I>(rules, |r| &r.pattern)
        .into_iter()
        .map(|row| {
            let key = IngressKeyRule {
                proto: row.proto.into(),
                src_vni: ExactSpec::new(row.rule.from),
                source: row.source,
                destination: row.destination,
                src_port: row.src_port,
                dst_port: row.dst_port,
                tcp_flags: row.proto.tcp_flags().into(),
            };
            (key, key.into_backend_fields::<Erased>(), row.index)
        })
        .collect();
    build_table(backend, I::INGRESS, lowered).map_err(ConfigError::FailureApply)
}

impl Classify for IngressRules {
    const BILLING: Billing = Billing::OuterIp;

    fn classify<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> Option<RuleIndex> {
        let VpcDiscriminant::VNI(src_vni) = packet.meta().src_vpcd?;
        let Fields {
            proto,
            source,
            destination,
            src_port,
            dst_port,
            tcp_flags,
        } = Fields::of(packet)?;
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => self.v4.lookup(&IngressKey {
                proto,
                src_vni,
                source,
                destination,
                src_port,
                dst_port,
                tcp_flags,
            }),
            (IpAddr::V6(source), IpAddr::V6(destination)) => self.v6.lookup(&IngressKey {
                proto,
                src_vni,
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
