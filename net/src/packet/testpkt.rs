// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tools for building test packets

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    unsafe_code
)]
#![allow(clippy::double_must_use)]
#![allow(missing_docs)]
#![allow(unused)]
#![allow(non_camel_case_types)]

use crate::headers::MAX_VLANS;
use arrayvec::ArrayVec;
use derive_builder::Builder;
use std::marker::PhantomData;

#[derive(Debug, Builder, Clone)]
#[builder(pattern = "owned", setter(into), name = "eth")]

struct TestEth {
    #[builder(default)]
    src_mac: String,
    #[builder(default)]
    dst_mac: String,
}
impl Default for TestEth {
    fn default() -> Self {
        Self {
            src_mac: "02:00:00:00:00:01".to_string(),
            dst_mac: "02:00:00:00:00:02".to_string(),
        }
    }
}

#[derive(Debug, Default, Builder, Clone)]
#[builder(pattern = "owned", setter(into), name = "vlans")]
struct TestVlans {
    #[builder(default, setter(each = "vlanid"))]
    vlanids: ArrayVec<u16, MAX_VLANS>,
}

#[derive(Debug, Builder, Clone)]
#[builder(pattern = "owned", setter(into), name = "ipv4")]
struct TestIpv4 {
    ttl: u8,
    src_ip: String,
    dst_ip: String,
}
impl Default for TestIpv4 {
    fn default() -> Self {
        Self {
            ttl: 64,
            src_ip: "1.2.3.4".to_string(),
            dst_ip: "5.6.7.8".to_string(),
        }
    }
}

#[derive(Debug, Default, Builder, Clone)]
#[builder(pattern = "owned", setter(into), name = "udp")]
struct TestUdp {
    sport: u16,
    dport: u16,
}

#[derive(Debug, Default, Builder, Clone)]
#[builder(pattern = "owned", setter(into), name = "tcp")]
struct TestTcp {
    sport: u16,
    dport: u16,
}

#[derive(Debug, Default, Builder, Clone)]
#[builder(pattern = "owned", setter(into), name = "icmp")]
struct TestIcmp {
    //todo
}

#[derive(Debug, Default, Builder, Clone)]
#[builder(pattern = "owned", setter(into), name = "data")]
struct TestData {
    octets: Vec<u8>,
}

#[derive(Debug, Default, Builder, Clone)]
#[builder(build_fn(skip))]
pub struct TestPacket {
    #[builder(setter(into, strip_option), default)]
    eth: Option<TestEth>,

    #[builder(setter(into, strip_option), default)]
    vlans: Option<TestVlans>,

    #[builder(setter(into, strip_option), default)]
    ipv4: Option<TestIpv4>,

    #[builder(setter(into, strip_option), default)]
    udp: Option<TestUdp>,

    #[builder(setter(into, strip_option), default)]
    tcp: Option<TestTcp>,

    #[builder(setter(into, strip_option), default)]
    icmp: Option<TestIcmp>,

    #[builder(setter(into, strip_option), default)]
    data: Option<TestData>,
}
impl TestPacketBuilder {
    pub fn build(&self) -> Result<TestPacket, String> {
        let mut count = 0;
        count += self.udp.clone().flatten().is_some() as u8;
        count += self.tcp.clone().flatten().is_some() as u8;
        count += self.icmp.clone().flatten().is_some() as u8;
        if count > 1 {
            //            return Err("Only one of udp|tcp|icmp is allowed".to_string());
        }

        Ok(TestPacket {
            eth: self.eth.clone().flatten(),
            vlans: self.vlans.clone().flatten(),
            ipv4: self.ipv4.clone().flatten(),
            udp: self.udp.clone().flatten(),
            tcp: self.tcp.clone().flatten(),
            icmp: self.icmp.clone().flatten(),
            data: self.data.clone().flatten(),
        })
    }
}

#[cfg(test)]
pub mod playground {
    use crate::packet::testpkt::{
        TestPacket, TestPacketBuilder, data, eth, icmp, ipv4, tcp, udp, vlans,
    };
    use std::u8;

    #[test]
    fn test_packet_builder() {
        let udp = udp::default()
            .sport(111u16)
            .dport(53u16)
            .build()
            .expect("Udp build failed");

        let tcp = tcp::default()
            .sport(9876u16)
            .dport(8080u16)
            .build()
            .expect("Tcp build failed");

        let mut builder = TestPacketBuilder::create_empty();
        builder
            .eth(
                eth::default()
                    .src_mac("02:00:00:00:00:01")
                    .dst_mac("02:00:00:00:00:02")
                    .build()
                    .expect("Eth build failed"),
            )
            .vlans(
                vlans::default()
                    .vlanid(100)
                    .vlanid(101)
                    .build()
                    .expect("Vlans build failed"),
            )
            .ipv4(
                ipv4::default()
                    .src_ip("1.2.3.4")
                    .dst_ip("5.6.7.8")
                    .ttl(128)
                    .build()
                    .expect("Ip build failed"),
            )
            .udp(udp)
            .tcp(tcp)
            .icmp(icmp::default().build().expect("Icmp build failed"))
            .data(
                data::default()
                    .octets(vec![1, 2, 3])
                    .build()
                    .expect("Data build failed"),
            );

        //.src_mac("00:11:22:33:44:55".to_string());

        let packet = builder.build().unwrap();
        println!("{packet:#?}");
    }
}
