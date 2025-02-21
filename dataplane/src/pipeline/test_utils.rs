// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use net::buffer::TestBuffer;
use net::eth::Eth;
use net::eth::ethtype::EthType;
use net::eth::mac::{DestinationMac, Mac, SourceMac};
use net::headers::{Headers, Net};
use net::ipv4::Ipv4;
use net::ipv4::addr::UnicastIpv4Addr;
use net::parse::DeParse;
use std::default::Default;
use std::net::Ipv4Addr;

use crate::packet::{InvalidPacket, Packet};

pub fn build_test_ipv4_packet(ttl: u8) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let mut ipv4 = Ipv4::default();
    ipv4.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(1, 2, 3, 4)).unwrap());
    ipv4.set_destination(Ipv4Addr::new(1, 2, 3, 4));
    ipv4.set_ttl(ttl);

    let mut headers = Headers::new(Eth::new(
        SourceMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
        DestinationMac::new(Mac([0x2, 0, 0, 0, 0, 2])).unwrap(),
        EthType::IPV4,
    ));
    headers.net = Some(Net::Ipv4(ipv4));

    let mut buffer: TestBuffer = TestBuffer::new();
    headers.deparse(buffer.as_mut()).unwrap();

    Packet::new(buffer)
}
