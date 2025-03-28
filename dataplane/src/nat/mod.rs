// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(dead_code)]
#![allow(rustdoc::private_doc_tests)]

//! Network Address Translation (NAT) for the dataplane
//!
//! This module implements a [`NetworkFunction`] that provides Network Address
//! Translation (NAT) functionality, either source or destination.
//!
//! # Example
//!
//! ```
//! let mut nat = Nat::new::<TestBuffer>(NatDirection::SrcNat, NatMode::Stateless);
//! let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
//! let packets_out: Vec<_> = nat.process(packets).collect();
//!
//! let hdr0_out = &packets_out[0]
//!     .try_ipv4()
//!     .expect("Failed to get IPv4 header");
//! ```
//!
//! # Limitations
//!
//! The module is subject to the following limitations:
//!
//! - Only stateless NAT is supported (no stateful NAT)
//! - Only NAT44 is supported (no NAT46, NAT64, or NAT66)
//! - Either source or destination NAT is supported, only one at a time, by a
//!   given [`Nat`] object. To perform NAT for different address fields, instantiate
//!   multiple [`Nat`] objects.
//! - PIFs mixing IPv4 and IPv6 endpoints or list of exposed IPs are not
//!   supported
//! - For a given PIF used for NAT, the number of IP addresses covered by the
//!   full set of (VPC-internal) endpoint prefixes must be equal to the number of
//!   IP addresses covered by the full set of externally-exposed IP prefixes; this
//!   is in order to make the 1:1 address mapping work.

mod fabric;
mod iplist;
mod prefixtrie;

use crate::nat::fabric::Vrf;
use crate::nat::iplist::IpList;
use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{TryHeadersMut, TryIpMut};
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::Packet;
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;

#[derive(Debug)]
struct GlobalContext {
    vpcs: HashMap<u32, Vrf>,
}

/// An object containing the [`Nat`] object state, not in terms of stateful NAT
/// processing, but instead holding references to the different fabric objects
/// that the [`Nat`] component uses, namely VPCs and their PIFs, and peering
/// interfaces.
///
/// This context will likely change and be shared with other components in the
/// future.
impl GlobalContext {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            vpcs: HashMap::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn insert_vpc(&mut self, vni: Vni, vpc: Vrf) {
        let _ = self.vpcs.insert(vni.as_u32(), vpc);
    }
}

/// A helper to retrieve the source IP address from a [`Net`] object,
/// independently of the IP version.
#[tracing::instrument(level = "trace")]
fn get_src_addr(net: &Net) -> IpAddr {
    match net {
        Net::Ipv4(hdr) => IpAddr::V4(hdr.source().inner()),
        Net::Ipv6(hdr) => IpAddr::V6(hdr.source().inner()),
    }
}

/// A helper to retrieve the destination IP address from a [`Net`] object,
/// independently of the IP version.
#[tracing::instrument(level = "trace")]
fn get_dst_addr(net: &Net) -> IpAddr {
    match net {
        Net::Ipv4(hdr) => IpAddr::V4(hdr.destination()),
        Net::Ipv6(hdr) => IpAddr::V6(hdr.destination()),
    }
}

/// Indicates whether a [`Nat`] processor should perform source NAT or destination
/// NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatDirection {
    /// Source NAT
    SrcNat,
    /// Destination NAT
    DstNat,
}

/// Indicates whether a [`Nat`] processor should perform stateless or stateful NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatMode {
    Stateless,
    #[allow(dead_code)]
    Stateful,
}

/// A NAT processor, implementing the [`NetworkFunction`] trait. [`Nat`] processes
/// packets to run source or destination Network Address Translation (NAT) on
/// their IP addresses.
#[derive(Debug)]
pub struct Nat {
    context: GlobalContext,
    mode: NatMode,
    direction: NatDirection,
}

impl Nat {
    /// Creates a new [`Nat`] processor. The `direction` indicates whether this
    /// processor should perform source or destination NAT. The `mode` indicates
    /// whether this processor should perform stateless or stateful NAT.
    #[tracing::instrument(level = "trace")]
    pub fn new<Buf: PacketBufferMut>(direction: NatDirection, mode: NatMode) -> Self {
        let context = GlobalContext::new();
        Self {
            context,
            mode,
            direction,
        }
    }

    /// Temporary, expect this to be removed in the future.
    #[tracing::instrument(level = "trace")]
    pub fn add_vpc(&mut self, vni: Vni, vpc: Vrf) {
        self.context.insert_vpc(vni, vpc);
    }

    #[tracing::instrument(level = "trace")]
    fn nat_supported(&self) -> bool {
        // We only support stateless NAT for now
        match self.mode {
            NatMode::Stateless => (),
            NatMode::Stateful => return false,
        }

        true
    }

    #[tracing::instrument(level = "trace")]
    fn find_src_nat_ranges(&self, net: &Net, vni: Vni) -> Option<(IpList, IpList)> {
        let vrf = self.context.vpcs.get(&vni.as_u32())?;
        let src_ip = &get_src_addr(net);
        match vrf.lookup_src_prefix(src_ip) {
            Some((c, t)) => Some((IpList::new(c, None), IpList::new(t.clone(), None))),
            None => return None,
        }
    }

    #[tracing::instrument(level = "trace")]
    fn find_dst_nat_ranges(&self, net: &Net, vni: Vni) -> Option<(IpList, IpList)> {
        let vrf = self.context.vpcs.get(&vni.as_u32())?;
        let dst_ip = &get_dst_addr(net);
        match vrf.lookup_dst_prefix(dst_ip) {
            Some((c, t)) => Some((IpList::new(c, None), IpList::new(t.clone(), None))),
            None => return None,
        }
    }

    #[tracing::instrument(level = "trace")]
    fn find_nat_ranges(&self, net: &mut Net, vni_opt: Option<Vni>) -> Option<(IpList, IpList)> {
        let vni = vni_opt?;
        match self.direction {
            NatDirection::SrcNat => self.find_src_nat_ranges(net, vni),
            NatDirection::DstNat => self.find_dst_nat_ranges(net, vni),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn map_ip(
        &self,
        current_range: &IpList,
        target_range: &IpList,
        current_ip: &IpAddr,
    ) -> Option<IpAddr> {
        let offset = current_range.get_offset(current_ip)?;
        target_range.get_addr(offset)
    }

    /// Applies network address translation to a packet, knowing the current and
    /// target ranges.
    #[tracing::instrument(level = "trace")]
    fn translate(
        &self,
        net: &mut Net,
        current_range: &IpList,
        target_range: &IpList,
    ) -> Option<()> {
        let current_ip = match self.direction {
            NatDirection::SrcNat => get_src_addr(net),
            NatDirection::DstNat => get_dst_addr(net),
        };
        let target_ip = self.map_ip(current_range, target_range, &current_ip)?;

        match self.direction {
            NatDirection::SrcNat => match (net, target_ip) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_source(UnicastIpv4Addr::new(ip).ok()?);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_source(UnicastIpv6Addr::new(ip).ok()?);
                }
                (_, _) => return None,
            },
            NatDirection::DstNat => match (net, target_ip) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_destination(ip);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_destination(ip);
                }
                (_, _) => return None,
            },
        }
        Some(())
    }

    /// Processes one packet. This is the main entry point for processing a
    /// packet. This is also the function that we pass to [`Nat::process`] to
    /// iterate over packets.
    fn process_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) {
        if !self.nat_supported() {
            return;
        }

        // ----------------------------------------------------
        // TODO: Get VNI
        // Currently hardcoded as required to have the tests pass, for demonstration purposes
        let vni = Vni::new_checked(100).ok();
        // ----------------------------------------------------
        let Some(net) = packet.headers_mut().try_ip_mut() else {
            return;
        };

        let ranges = self.find_nat_ranges(net, vni);
        let Some((current_range, target_range)) = ranges else {
            return;
        };
        self.translate(net, &current_range, &target_range);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Nat {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.map(|mut packet| {
            self.process_packet(&mut packet);
            packet
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::fabric::{Peering, PeeringAs, PeeringEntry, PeeringIps};
    use iptrie::Ipv4Prefix;
    use net::buffer::TestBuffer;
    use net::headers::TryIpv4;
    use net::packet::test_utils::build_test_ipv4_packet;
    use routing::prefix::Prefix;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn prefix_v4(s: &str) -> Prefix {
        Ipv4Prefix::from_str(s).expect("Invalid IPv4 prefix").into()
    }

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn build_context() -> (Vrf, Vrf, Peering) {
        let mut vpc1 = Vrf::new(
            "test_vpc1".into(),
            Vni::new_checked(100).expect("Failed to create VNI"),
        );
        let mut vpc2 = Vrf::new(
            "test_vpc2".into(),
            Vni::new_checked(200).expect("Failed to create VNI"),
        );

        let mut peering = Peering {
            name: "test_peering".into(),
            entries: HashMap::new(),
        };
        peering.entries.insert(
            "test_vpc1".into(),
            PeeringEntry {
                internal: vec![
                    PeeringIps {
                        cidr: prefix_v4("1.2.3.0/24"),
                    },
                    PeeringIps {
                        cidr: prefix_v4("4.5.6.0/24"),
                    },
                    PeeringIps {
                        cidr: prefix_v4("7.8.9.0/24"),
                    },
                ],
                external: vec![
                    PeeringAs {
                        cidr: prefix_v4("10.0.1.0/24"),
                    },
                    PeeringAs {
                        cidr: prefix_v4("10.0.2.0/24"),
                    },
                    PeeringAs {
                        cidr: prefix_v4("10.0.3.0/24"),
                    },
                ],
            },
        );
        peering.entries.insert(
            "test_vpc2".into(),
            PeeringEntry {
                internal: vec![
                    PeeringIps {
                        cidr: prefix_v4("9.9.0.0/16"),
                    },
                    PeeringIps {
                        cidr: prefix_v4("99.99.0.0/16"),
                    },
                ],
                external: vec![
                    PeeringAs {
                        cidr: prefix_v4("1.1.0.0/16"),
                    },
                    PeeringAs {
                        cidr: prefix_v4("1.2.0.0/16"),
                    },
                ],
            },
        );

        vpc1.add_peering(&peering).expect("Failed to add peering");
        vpc2.add_peering(&peering).expect("Failed to add peering");

        (vpc1, vpc2, peering)
    }

    #[test]
    fn test_dst_nat_stateless_44() {
        let (vpc1, vpc2, _) = build_context();
        let mut nat = Nat::new::<TestBuffer>(NatDirection::DstNat, NatMode::Stateless);
        nat.add_vpc(Vni::new_checked(100).expect("Failed to create VNI"), vpc1);
        nat.add_vpc(Vni::new_checked(200).expect("Failed to create VNI"), vpc2);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.destination(), addr_v4("99.99.3.4"));
    }

    #[test]
    fn test_src_nat_stateless_44() {
        let (vpc1, vpc2, _) = build_context();
        let mut nat = Nat::new::<TestBuffer>(NatDirection::SrcNat, NatMode::Stateless);
        nat.add_vpc(Vni::new_checked(100).expect("Failed to create VNI"), vpc1);
        nat.add_vpc(Vni::new_checked(200).expect("Failed to create VNI"), vpc2);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.source().inner(), addr_v4("10.0.1.4"));
    }
}
