// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds types for IP/port tuples that masquerade may not hand out since they may be
//! reserved by port forwarding.
//!
//! Port forwarding maps a public address and port onto a private endpoint, and a masquerade expose
//! may cover that same public address. Both would then claim one public tuple, and since a
//! [`FlowKey`](net::FlowKey) carries no notion of which translation owns it, the resulting flows can
//! collide: an inbound packet for the forwarded service is instead matched by a masquerade flow and
//! delivered to an unrelated private endpoint.
//!
//! Which tuples port forwarding may claim follows from the configuration, so they are removed from
//! the masquerade pools while those pools are built rather than defended per flow. The reserved bits
//! are then indistinguishable from allocated ones, and no allocation path has to know that port
//! forwarding exists.

use lpm::prefix::{PortRange, Prefix, PrefixPortsSet};
use std::net::IpAddr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Ports of the (public) address space that port forwarding may claim, as (prefix, ports) pairs.
pub(crate) struct ReservedPorts(Vec<(Prefix, PortRange)>);
impl ReservedPorts {
    /// Build a `ReservedPorts` from a `PrefixPortsSet`. The object contains the set of (prefix, ports)
    /// that may be reserved upfront and not handed out.
    ///
    /// Every pair is kept: two rules may claim different ports of one address, and collapsing them
    /// to a single range per address would lose one of the claims.
    ///
    /// Prefixes carrying no port range are skipped since port-forwarding always specifies port-ranges.
    pub(crate) fn from_set(set: &PrefixPortsSet) -> Self {
        Self(
            set.iter()
                .filter_map(|prefix| Some((prefix.prefix(), prefix.ports()?)))
                .collect(),
        )
    }

    /// The claims that apply to one public address.
    #[must_use]
    pub(crate) fn for_addr(&self, addr: IpAddr) -> ReservedForAddr {
        ReservedForAddr(
            self.0
                .iter()
                .filter(|(prefix, _)| prefix.covers_addr(&addr))
                .map(|(_, ports)| *ports)
                .collect(),
        )
    }
}

/// The reserved port ranges that apply to one (public) address.
///
/// Empty for most addresses, and never large: it holds one range per configured claim covering that
/// address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReservedForAddr(Vec<PortRange>);

impl ReservedForAddr {
    #[must_use]
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The reserved ranges, for whoever has to keep those ports out of a bitmap.
    #[must_use]
    pub(crate) fn ranges(&self) -> &[PortRange] {
        &self.0
    }

    /// Whether a specific port is reserved.
    #[must_use]
    pub(crate) fn contains(&self, port: u16) -> bool {
        self.0
            .iter()
            .any(|range| range.start() <= port && port <= range.end())
    }
}

#[cfg(test)]
mod tests {
    use super::{ReservedForAddr, ReservedPorts};
    use lpm::prefix::{PortRange, PrefixPortsSet, PrefixWithOptionalPorts};
    use std::net::IpAddr;

    fn claim(prefix: &str, start: u16, end: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(prefix.into(), Some(PortRange::new(start, end).unwrap()))
    }

    fn addr(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn ports(reserved: &ReservedForAddr) -> Vec<(u16, u16)> {
        reserved
            .ranges()
            .iter()
            .map(|range| (range.start(), range.end()))
            .collect()
    }

    #[test]
    fn claims_on_one_prefix_all_survive() {
        // The defect the previous static implementation had: a single-range-per-address model kept
        // only one of these two claims.
        let reserved = ReservedPorts::from_set(&PrefixPortsSet::from([
            claim("5.6.7.8/32", 8080, 8080),
            claim("5.6.7.8/32", 9090, 9090),
        ]));

        let for_addr = reserved.for_addr(addr("5.6.7.8"));
        assert_eq!(ports(&for_addr), [(8080, 8080), (9090, 9090)]);
        assert!(for_addr.contains(8080), "first claim was lost");
        assert!(for_addr.contains(9090), "second claim was lost");
        assert!(!for_addr.contains(8081));
    }

    #[test]
    fn claims_apply_only_to_the_addresses_they_cover() {
        let reserved =
            ReservedPorts::from_set(&PrefixPortsSet::from([claim("5.6.7.0/30", 4000, 4001)]));

        assert!(reserved.for_addr(addr("5.6.7.1")).contains(4000));
        assert!(reserved.for_addr(addr("5.6.7.4")).is_empty());
        // An address of the other version is never covered.
        assert!(reserved.for_addr(addr("::1")).is_empty());
    }

    #[test]
    fn a_prefix_without_ports_claims_nothing() {
        let set = PrefixPortsSet::from([PrefixWithOptionalPorts::new("5.6.7.8/32".into(), None)]);
        assert!(ReservedPorts::from_set(&set).0.is_empty());
    }
}
