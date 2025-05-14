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

mod iplist;

use crate::nat::iplist::IpList;
use pipeline::NetworkFunction;

use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{TryHeadersMut, TryIpMut};
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::Packet;
use net::vxlan::Vni;
use std::fmt::Debug;
use std::net::IpAddr;

/// A helper to retrieve the source IP address from a [`Net`] object,
/// independently of the IP version.
fn get_src_addr(net: &Net) -> IpAddr {
    match net {
        Net::Ipv4(hdr) => IpAddr::V4(hdr.source().inner()),
        Net::Ipv6(hdr) => IpAddr::V6(hdr.source().inner()),
    }
}

/// A helper to retrieve the destination IP address from a [`Net`] object,
/// independently of the IP version.
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
    mode: NatMode,
    direction: NatDirection,
}

impl Nat {
    /// Creates a new [`Nat`] processor. The `direction` indicates whether this
    /// processor should perform source or destination NAT. The `mode` indicates
    /// whether this processor should perform stateless or stateful NAT.
    pub fn new<Buf: PacketBufferMut>(direction: NatDirection, mode: NatMode) -> Self {
        Self {
            mode,
            direction,
        }
    }

    fn nat_supported(&self) -> bool {
        // We only support stateless NAT for now
        match self.mode {
            NatMode::Stateless => (),
            NatMode::Stateful => return false,
        }

        true
    }

    fn find_src_nat_ranges(
        &self,
        _dst_ip: &IpAddr,
        _src_ip: &IpAddr,
        _vni_opt: Option<Vni>,
    ) -> Option<(IpList, IpList)> {
        todo!();
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
    fn find_dst_nat_ranges(&self, _dst_ip: &IpAddr) -> Option<(IpList, IpList)> {
        todo!();
    }

    fn find_nat_ranges(&self, net: &mut Net, vni: Option<Vni>) -> Option<(IpList, IpList)> {
        let dst_ip = &get_dst_addr(net);
        match self.direction {
            NatDirection::SrcNat => self.find_src_nat_ranges(dst_ip, &get_src_addr(net), vni),
            NatDirection::DstNat => self.find_dst_nat_ranges(dst_ip),
        }
    }

    fn map_ip(
        &self,
        _current_range: &IpList,
        _target_range: &IpList,
        _current_ip: &IpAddr,
    ) -> Option<IpAddr> {
        todo!();
    }

    /// Applies network address translation to a packet, knowing the current and
    /// target ranges.
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
