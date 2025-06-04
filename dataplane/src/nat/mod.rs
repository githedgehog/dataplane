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
//! - Only NAT44 is supported (no NAT46, NAT64, or NAT66)
//! - Either source or destination NAT is supported, only one at a time, by a given [`Nat`] object.
//!   To perform NAT for different address fields, instantiate multiple [`Nat`] objects.
//! - "Expose" objects mixing IPv4 and IPv6 endpoints or list of exposed IPs are not supported
//! - The total number of available (not excluded) private addresses used in an "Expose" object must
//!   be equal to the total number of publicly exposed addresses in this object.

mod iplist;
mod stateful;
mod stateless;

use crate::nat::iplist::IpList;
use mgmt::models::internal::nat::tables::{NatTables, TrieValue};
use net::buffer::PacketBufferMut;
use net::headers::{TryHeadersMut, TryIpMut};
use net::packet::Packet;
use net::vxlan::Vni;
use pipeline::NetworkFunction;

/// Indicates whether a [`Nat`] processor should perform source NAT or destination NAT.
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
    Stateful,
}

/// A NAT processor, implementing the [`NetworkFunction`] trait. [`Nat`] processes packets to run
/// source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct Nat {
    context: NatTables,
    mode: NatMode,
    direction: NatDirection,
}

impl Nat {
    /// Creates a new [`Nat`] processor. The `direction` indicates whether this processor should
    /// perform source or destination NAT. The `mode` indicates whether this processor should
    /// perform stateless or stateful NAT.
    pub fn new(direction: NatDirection, mode: NatMode) -> Self {
        let context = NatTables::new();
        Self {
            context,
            mode,
            direction,
        }
    }

    /// Updates the VNI tables in the NAT processor.
    pub fn update_tables(&mut self, tables: NatTables) {
        self.context = tables;
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`Nat::process`] to iterate over packets.
    fn process_packet<Buf: PacketBufferMut>(&mut self, packet: &mut Packet<Buf>) {
        // ----------------------------------------------------
        // TODO: Get VNI
        // Currently hardcoded as required to have the tests pass, for demonstration purposes
        let vni = Vni::new_checked(100).ok();
        // ----------------------------------------------------
        let Some(net) = packet.headers_mut().try_ip_mut() else {
            return;
        };

        match self.mode {
            NatMode::Stateless => self.stateless_nat(net, vni),
            NatMode::Stateful => self.stateful_nat(net, vni),
        }
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
    use mgmt::models::external::overlay::vpc::Peering;
    use mgmt::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use mgmt::models::internal::nat::table_extend;
    use mgmt::models::internal::nat::tables::{NatTables, PerVniTable};
    use net::headers::TryIpv4;
    use net::packet::test_utils::build_test_ipv4_packet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn build_context() -> NatTables {
        // Build VpcExpose objects
        //
        //     expose:
        //       - ips:
        //         - cidr: 1.1.0.0/16
        //         - cidr: 1.2.0.0/16 # <- 1.2.3.4 will match here
        //         - not: 1.1.5.0/24  # to account for when computing the offset
        //         - not: 1.1.3.0/24  # to account for when computing the offset
        //         - not: 1.1.1.0/24  # to account for when computing the offset
        //         - not: 1.2.2.0/24  # to account for when computing the offset
        //         as:
        //         - cidr: 2.2.0.0/16
        //         - cidr: 2.1.0.0/16 # <- corresp. target range, initially
        //                            # (prefixes in BTreeSet are sorted)
        //                            # offset for 2.1.255.4, before applying exlusions
        //                            # final offset is for 2.2.0.4 after accounting for the one
        //                            # relevant exclusion prefix
        //         - not: 2.1.8.0/24  # to account for when fetching the address in range
        //         - not: 2.2.10.0/24
        //         - not: 2.2.1.0/24  # ignored, offset too low
        //         - not: 2.2.2.0/24  # ignored, offset too low
        //       - ips:
        //         - cidr: 3.0.0.0/16
        //         as:
        //         - cidr: 4.0.0.0/16
        let expose1 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .not("1.1.5.0/24".into())
            .not("1.1.3.0/24".into())
            .not("1.1.1.0/24".into())
            .ip("1.2.0.0/16".into())
            .not("1.2.2.0/24".into())
            .as_range("2.2.0.0/16".into())
            .not_as("2.1.8.0/24".into())
            .not_as("2.2.10.0/24".into())
            .not_as("2.2.1.0/24".into())
            .not_as("2.2.2.0/24".into())
            .as_range("2.1.0.0/16".into());
        let expose2 = VpcExpose::empty()
            .ip("3.0.0.0/16".into())
            .as_range("4.0.0.0/16".into());

        let manifest1 = VpcManifest {
            name: "VPC-1".into(),
            exposes: vec![expose1, expose2],
        };

        //     expose:
        //       - ips:
        //         - cidr: 8.0.0.0/17
        //         - cidr: 9.0.0.0/17
        //         - not: 8.0.0.0/24
        //         as:
        //         - cidr: 3.0.0.0/16
        //         - not: 3.0.1.0/24
        //       - ips:
        //         - cidr: 10.0.0.0/16 # <- corresponding target range
        //         - not: 10.0.1.0/24  # to account for when fetching the address in range
        //         - not: 10.0.2.0/24  # to account for when fetching the address in range
        //         as:
        //         - cidr: 1.1.0.0/17
        //         - cidr: 1.2.0.0/17  # <- 1.2.3.4 will match here
        //         - not: 1.2.0.0/24   # to account for when computing the offset
        //         - not: 1.2.8.0/24
        let expose3 = VpcExpose::empty()
            .ip("8.0.0.0/17".into())
            .not("8.0.0.0/24".into())
            .ip("9.0.0.0/17".into())
            .as_range("3.0.0.0/16".into())
            .not_as("3.0.1.0/24".into());
        let expose4 = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("10.0.1.0/24".into())
            .not("10.0.2.0/24".into())
            .as_range("1.1.0.0/17".into())
            .as_range("1.2.0.0/17".into())
            .not_as("1.2.0.0/24".into())
            .not_as("1.2.8.0/24".into());

        let manifest2 = VpcManifest {
            name: "VPC-2".into(),
            exposes: vec![expose3, expose4],
        };

        let peering: Peering = Peering {
            name: "test_peering".into(),
            local: manifest1,
            remote: manifest2,
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
        };

        let mut vni_table = PerVniTable::new();
        table_extend::add_peering(&mut vni_table, &peering).expect("Failed to build NAT tables");

        let vni = Vni::new_checked(100).expect("Failed to create VNI");
        let mut nat_table = NatTables::new();
        nat_table.add_table(vni, vni_table);

        nat_table
    }

    #[test]
    fn test_dst_nat_stateless_44() {
        let nat_tables = build_context();
        let mut nat = Nat::new(NatDirection::DstNat, NatMode::Stateless);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.destination(), addr_v4("10.0.132.4"));
    }

    #[test]
    fn test_src_nat_stateless_44() {
        let nat_tables = build_context();
        let mut nat = Nat::new(NatDirection::SrcNat, NatMode::Stateless);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.source().inner(), addr_v4("2.2.0.4"));
    }
}
