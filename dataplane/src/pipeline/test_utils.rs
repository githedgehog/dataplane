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
use crate::pipeline::sample_nfs::{BroadcastMacs, DecrementTtl, InspectHeaders, Passthrough};
use crate::pipeline::{DynNetworkFunction, nf_dyn};

/// Generates an infinite sequence of network functions.
///
/// The sequence is a repeating pattern of:
/// - [`InspectHeaders`]
/// - [`BroadcastMacs`]
/// - [`InspectHeaders`]
/// - [`DecrementTtl`]
///
/// To avoid decrementing the TTL below 0, once there are 255 [`DecrementTtl`] stages, the pattern
/// becomes:
/// - [`InspectHeaders`]
/// - [`BroadcastMacs`]
/// - [`InspectHeaders`]
/// - [`Passthrough`]
pub struct DynStageGenerator {
    i: usize,
}

impl DynStageGenerator {
    pub fn new() -> Self {
        Self { i: 0 }
    }

    pub fn num_ttl_decs(count: usize) -> usize {
        let num = count / 4;
        if num > u8::MAX as usize {
            u8::MAX as usize
        } else {
            num
        }
    }
}

impl Iterator for DynStageGenerator {
    #![allow(clippy::match_same_arms)]

    type Item = Box<dyn DynNetworkFunction<TestBuffer>>;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.i % 4 {
            0 => Some(nf_dyn(InspectHeaders)),
            1 => Some(nf_dyn(BroadcastMacs)),
            2 => Some(nf_dyn(InspectHeaders)),
            3 => {
                if Self::num_ttl_decs(self.i) == u8::MAX as usize {
                    Some(nf_dyn(Passthrough))
                } else {
                    Some(nf_dyn(DecrementTtl))
                }
            }
            _ => unreachable!(),
        };
        self.i += 1;
        ret
    }
}

/// Builds a test packet with the given TTL value.
///
/// The packet is an IPv4 packet with a source and destination IP address of 1.2.3.4.
/// The Ethernet source and destination MAC addresses are 0x02:00:00:00:00:01 and 0x02:00:00:00:00:02
/// respectively.
///
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
