// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Which rule meters a packet.

use acl::table::{Backend, Table, build_table};
use config::ConfigError;
use lpm::prefix::Prefix;
use match_action::{Erased, ExactSpec, MaskSpec, MatchKey, PrefixSpec};
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryIp};
use net::ip::{IpAddress, NextHeader};
use net::packet::{Packet, VpcDiscriminant};
use net::vxlan::Vni;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A rule's place in its [`RuleTable`](crate::RuleTable).
pub type RuleIndex = usize;

/// Finds the rule that meters a packet.
pub trait Classify: Send + Sync {
    /// The rule that meters `packet`, if one does.
    fn classify<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> Option<RuleIndex>;
}

/// The key a [`VpcDestination`] looks packets up by.
#[derive(Debug, MatchKey, Clone, PartialEq, Eq)]
pub(crate) struct VpcDestinationKey<I> {
    /// Wildcarded protocol byte: `rte_acl` requires a one-byte first field.
    #[mask]
    proto: NextHeader,
    #[exact]
    #[cli(column_name = "src-vni")]
    src_vni: Vni,
    #[prefix]
    #[cli(column_name = "destination")]
    destination: I,
}

/// Classifies by the VPC a packet comes from and where it is going.
///
/// When several rules match, the one with the longest destination prefix meters the packet.
#[derive(Debug)]
pub struct VpcDestination {
    v4: Table<VpcDestinationKey<Ipv4Addr>, RuleIndex>,
    v6: Table<VpcDestinationKey<Ipv6Addr>, RuleIndex>,
}

impl VpcDestination {
    /// A classifier that matches nothing.
    #[must_use]
    pub fn empty() -> VpcDestination {
        VpcDestination {
            v4: Table::empty(),
            v6: Table::empty(),
        }
    }

    /// A classifier for `rules`, whose index is their place in the slice.
    ///
    /// # Errors
    ///
    /// Fails if the classifier's tables cannot be built.
    pub fn new(rules: &[(Vni, Prefix)], backend: Backend) -> Result<VpcDestination, ConfigError> {
        // The tables are first match, so the longest destination goes first.
        let mut order: Vec<RuleIndex> = (0..rules.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(rules[i].1.length()));
        Ok(VpcDestination {
            v4: table::<Ipv4Addr>(rules, &order, backend)?,
            v6: table::<Ipv6Addr>(rules, &order, backend)?,
        })
    }
}

/// A table holding those of `rules` whose destination is an `I`, in `order`.
fn table<I: IpVersion>(
    rules: &[(Vni, Prefix)],
    order: &[RuleIndex],
    backend: Backend,
) -> Result<Table<VpcDestinationKey<I>, RuleIndex>, ConfigError> {
    let lowered = order
        .iter()
        .filter_map(|&i| {
            let (vni, destination) = rules[i];
            let rule = VpcDestinationKeyRule {
                proto: MaskSpec::wildcard(),
                src_vni: ExactSpec::new(vni),
                destination: I::prefix_spec(destination)?,
            };
            Some((rule, rule.into_backend_fields::<Erased>(), i))
        })
        .collect();
    build_table(backend, I::NAME, lowered).map_err(ConfigError::FailureApply)
}

impl Classify for VpcDestination {
    fn classify<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> Option<RuleIndex> {
        let VpcDiscriminant::VNI(src_vni) = packet.meta().src_vpcd?;
        let net = packet.try_ip()?;
        let proto = net.next_header();
        match net.dst_addr() {
            IpAddr::V4(destination) => self.v4.lookup(&VpcDestinationKey {
                proto,
                src_vni,
                destination,
            }),
            IpAddr::V6(destination) => self.v6.lookup(&VpcDestinationKey {
                proto,
                src_vni,
                destination,
            }),
        }
        .copied()
    }
}

/// An address family, as a classifier table sees it.
trait IpVersion: IpAddress {
    /// Names the family's table.
    const NAME: &'static str;

    /// `prefix`, if it is of this family.
    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>>;
}

impl IpVersion for Ipv4Addr {
    const NAME: &'static str = "rate_limit_v4";

    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>> {
        match prefix {
            Prefix::IPV4(prefix) => Some(prefix.into()),
            Prefix::IPV6(_) => None,
        }
    }
}

impl IpVersion for Ipv6Addr {
    const NAME: &'static str = "rate_limit_v6";

    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>> {
        match prefix {
            Prefix::IPV6(prefix) => Some(prefix.into()),
            Prefix::IPV4(_) => None,
        }
    }
}

/// IP packet length, including the header, for byte accounting.
pub(crate) fn ip_bytes(net: &Net) -> u32 {
    match net {
        Net::Ipv4(ip) => u32::from(ip.total_len()),
        Net::Ipv6(ip) => u32::from(net::ipv6::Ipv6::MIN_LEN.get()) + u32::from(ip.payload_length()),
    }
}
