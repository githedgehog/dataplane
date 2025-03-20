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

use crate::nat::fabric::{PeeringPolicy, Pif, Vpc};
use crate::nat::iplist::IpList;
use crate::nat::prefixtrie::PrefixTrie;
use pipeline::NetworkFunction;

use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{TryHeadersMut, TryIpMut};
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::Packet;
use net::vxlan::Vni;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;

#[derive(Debug)]
#[allow(dead_code)]
struct GlobalContext {
    vpcs: HashMap<u32, Vpc>,
    global_pif_trie: PrefixTrie,
    peerings: HashMap<String, PeeringPolicy>,
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
            global_pif_trie: PrefixTrie::new(),
            peerings: HashMap::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn insert_vpc(&mut self, vni: Vni, vpc: Vpc) {
        vpc.iter_pifs().for_each(|pif| {
            pif.iter_ips().for_each(|prefix| {
                let _ = self.global_pif_trie.insert(prefix, pif.name().clone());
            });
        });
        let _ = self.vpcs.insert(vni.as_u32(), vpc);
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_ip(&self, ip: &IpAddr) -> Option<String> {
        self.global_pif_trie.find_ip(ip)
    }

    #[tracing::instrument(level = "trace")]
    fn get_vpc(&self, vni: Vni) -> Option<&Vpc> {
        self.vpcs.get(&vni.as_u32())
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_name(&self, name: &String) -> Option<&Pif> {
        self.vpcs.values().find_map(|vpc| vpc.get_pif(name))
    }

    #[tracing::instrument(level = "trace")]
    fn find_src_pif(&self, src_vpc_vni: Vni, dst_pif: &Pif, dst_ip: &IpAddr) -> Option<&Pif> {
        // Iterate on destination PIF's peering policies
        for peering_name in dst_pif.iter_peerings() {
            let peering = self.peerings.get(peering_name)?;
            let peer_pif_idx = peering.get_peer_index(dst_pif);
            let peer_pif_vni = peering.vnis()[peer_pif_idx];

            // Filter peering policies, discard if not attached to source VPC
            if peer_pif_vni != src_vpc_vni {
                continue;
            }

            // Retrieve destination PIF's peer PIF for the policy
            let src_vpc = self.get_vpc(src_vpc_vni)?;
            let peer_pif_name = &peering.pifs()[peer_pif_idx];
            let peer_pif = src_vpc.get_pif(peer_pif_name)?;

            // Search peer PIF's endpoints for packet's destination IP
            if peer_pif
                .iter_endpoints()
                .any(|endpoint| endpoint.covers_addr(dst_ip))
            {
                return Some(peer_pif);
            }
        }
        None
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
    #[allow(dead_code)]
    /// Source NAT
    SrcNat,
    #[allow(dead_code)]
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
    pub fn add_vpc(&mut self, vni: Vni, vpc: Vpc) {
        self.context.insert_vpc(vni, vpc);
    }

    /// Temporary, expect this to be removed in the future.
    #[tracing::instrument(level = "trace")]
    pub fn add_peering_policy(&mut self, pp: PeeringPolicy) {
        self.context.peerings.insert(pp.name().clone(), pp);
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

    /// From the destination IP address contained in `net`, finds the
    /// destination PIF for the packet.
    #[tracing::instrument(level = "trace")]
    fn find_dst_pif(&self, dst_ip: &IpAddr) -> Option<&Pif> {
        self.context
            .find_pif_by_ip(dst_ip)
            .and_then(|name| self.context.find_pif_by_name(&name))
    }

    /// Finds the two [`IpList`] objects necessary to perform _source_ NAT on the
    /// packet represented by the network header `net`. These objects represent
    /// two lists of IP addresses, such that the NAT operation translates one IP
    /// from the first list to one in the second list.
    ///
    /// To find these ranges:
    ///
    /// - First we lookup for the destination PIF, based on the destination IP
    ///   address.
    /// - Then we derive the source PIF from the destination PIF and source IP
    ///   address (see [`GlobalContext::find_src_pif()`]).
    /// - At last, we get the relevant NAT ranges from the source PIF:
    ///     - For the initial range, the list of endpoints from the source PIF.
    ///     - For the target range, the list of publicly-exposed IP addresses from
    ///       the source PIF.
    #[tracing::instrument(level = "trace")]
    fn find_src_nat_ranges(
        &self,
        dst_ip: &IpAddr,
        src_ip: &IpAddr,
        vni_opt: Option<Vni>,
    ) -> Option<(IpList, IpList)> {
        // For now we don't support NAT if we don't have a VNI
        let vni = vni_opt?;
        let dst_pif = self.find_dst_pif(dst_ip)?;
        let src_pif = self.context.find_src_pif(vni, dst_pif, dst_ip)?;

        IpList::generate_ranges(src_pif.iter_endpoints(), src_pif.iter_ips(), dst_ip)
    }

    /// Finds the two [`IpList`] objects necessary to perform _destination NAT_ on
    /// the packet represented by the network header `net`. These objects
    /// represent two lists of IP addresses, such that the NAT operation
    /// translates one IP from the first list to one in the second list.
    ///
    /// These ranges are:
    ///
    /// - For the initial range, the list of publicly-exposed IP addresses from
    ///   the destination PIF.
    /// - For the target range, the list of endpoints from the destination PIF.
    #[tracing::instrument(level = "trace")]
    fn find_dst_nat_ranges(&self, dst_ip: &IpAddr) -> Option<(IpList, IpList)> {
        let dst_pif = self.find_dst_pif(dst_ip)?;
        IpList::generate_ranges(dst_pif.iter_ips(), dst_pif.iter_endpoints(), dst_ip)
    }

    #[tracing::instrument(level = "trace")]
    fn find_nat_ranges(&self, net: &mut Net, vni: Option<Vni>) -> Option<(IpList, IpList)> {
        let dst_ip = &get_dst_addr(net);
        match self.direction {
            NatDirection::SrcNat => self.find_src_nat_ranges(dst_ip, &get_src_addr(net), vni),
            NatDirection::DstNat => self.find_dst_nat_ranges(dst_ip),
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
        let vni = match self.direction {
            NatDirection::SrcNat => Vni::new_checked(200).ok(),
            NatDirection::DstNat => Vni::new_checked(100).ok(),
        };
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

    fn build_vpc1() -> Vpc {
        let mut vpc1 = Vpc::new(
            "test_vpc1".into(),
            Vni::new_checked(100).expect("Failed to create VNI"),
        );
        let mut pif1 = Pif::new("pif1".into(), "test_vpc1".into());
        pif1.add_endpoint(prefix_v4("10.0.0.0/24"));
        pif1.add_endpoint(prefix_v4("8.8.8.0/24"));
        pif1.add_ip(prefix_v4("192.168.0.0/24"));
        pif1.add_ip(prefix_v4("1.2.3.0/24"));
        pif1.add_peering("peering_policy".into());

        vpc1.add_pif(pif1.clone()).expect("Failed to add PIF");
        vpc1
    }

    fn build_vpc2() -> Vpc {
        let mut vpc2 = Vpc::new(
            "test_vpc2".into(),
            Vni::new_checked(200).expect("Failed to create VNI"),
        );
        let mut pif2 = Pif::new("pif2".into(), "test_vpc2".into());
        pif2.add_endpoint(prefix_v4("10.0.2.0/24"));
        pif2.add_endpoint(prefix_v4("1.2.3.0/24"));
        pif2.add_ip(prefix_v4("192.168.2.0/24"));
        pif2.add_ip(prefix_v4("4.4.4.0/24"));
        pif2.add_peering("peering_policy".into());

        vpc2.add_pif(pif2.clone()).expect("Failed to add PIF");

        vpc2
    }

    fn build_peering_policy() -> PeeringPolicy {
        PeeringPolicy::new(
            "peering_policy".into(),
            [
                Vni::new_checked(100).expect("Failed to create VNI"),
                Vni::new_checked(200).expect("Failed to create VNI"),
            ],
            ["pif1".into(), "pif2".into()],
        )
    }

    #[test]
    fn test_src_nat_stateless_44() {
        let mut nat = Nat::new::<TestBuffer>(NatDirection::SrcNat, NatMode::Stateless);
        let vpc1 = build_vpc1();
        nat.add_vpc(Vni::new_checked(100).expect("Failed to create VNI"), vpc1);
        let vpc2 = build_vpc2();
        nat.add_vpc(Vni::new_checked(200).expect("Failed to create VNI"), vpc2);

        let pp = build_peering_policy();
        nat.add_peering_policy(pp);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.source().inner(), addr_v4("4.4.4.4"));
    }

    #[test]
    fn test_dst_nat_stateless_44() {
        let mut nat = Nat::new::<TestBuffer>(NatDirection::DstNat, NatMode::Stateless);
        let vpc1 = build_vpc1();
        nat.add_vpc(Vni::new_checked(100).expect("Failed to create VNI"), vpc1);
        let vpc2 = build_vpc2();
        nat.add_vpc(Vni::new_checked(200).expect("Failed to create VNI"), vpc2);

        let pp = build_peering_policy();
        nat.add_peering_policy(pp);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.destination(), addr_v4("8.8.8.4"));
    }
}
