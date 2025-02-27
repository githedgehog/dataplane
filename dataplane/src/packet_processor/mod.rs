// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod egress;
mod ingress;
mod ipforward;
mod ipstaticfilter;
mod stats;

#[cfg(test)]
mod test {
    use crate::packet_meta::DropReason;
    use crate::packet_meta::InterfaceId;
    use crate::packet_meta::PacketDropStats;
    use crate::pipeline::{DynPipeline, NetworkFunction};
    use net::buffer::TestBuffer;
    use net::eth::mac::Mac;
    use net::vlan::Vid;
    use routing::interface::*;
    use routing::vrf::Vrf;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::RwLock;

    use net::eth::Eth;
    use net::eth::ethtype::EthType;
    use net::eth::mac::{DestinationMac, SourceMac};
    use net::headers::{Headers, Net};
    use net::ip::NextHeader;
    use net::ipv4::Ipv4;
    use net::ipv4::addr::UnicastIpv4Addr;
    use net::ipv6::Ipv6;
    use net::ipv6::addr::UnicastIpv6Addr;
    use net::parse::DeParse;
    use std::default::Default;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::egress::Egress;
    use super::ingress::Ingress;
    use super::ipforward::IpForwarder;
    use super::ipstaticfilter::IpFilter;
    use super::stats::StatsSink;
    use crate::Packet;

    pub fn init_test_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_target(true)
            .with_line_number(true)
            .with_thread_names(false)
            .try_init();
    }

    /// Build test interface table
    fn build_test_iftable() -> IfTable {
        let mut iftable = IfTable::new();
        let vrf = Arc::new(RwLock::new(Vrf::new("default-vrf", 0)));

        /* create Eth1 */
        let mut eth1 = Interface::new("eth0", 1);
        eth1.set_admin_state(IfState::Up);
        eth1.set_oper_state(IfState::Up);
        eth1.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x2, 0, 0, 0, 0, 1]),
        }));
        eth1.attach(&vrf).expect("Attach should succeed");

        /* create Eth2 */
        let mut eth2 = Interface::new("eth2", 2);
        eth2.set_admin_state(IfState::Up);
        eth2.set_oper_state(IfState::Up);
        eth2.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: Mac::from([0x2, 0, 0, 0, 0, 2]),
            vlanid: Vid::new(100).unwrap(),
        }));
        eth2.attach(&vrf).expect("Attach should succeed");

        /* Add the interfaces to the iftable */
        iftable.add_interface(eth1);
        iftable.add_interface(eth2);

        iftable
    }

    /// Builds a sample 6-stage pipeline with ingress, ipfilter, 2 stages of routing, egress and
    /// a stats-collecting stage.
    fn build_processor_pipeline() -> (DynPipeline<TestBuffer>, Arc<RwLock<PacketDropStats>>) {
        let iftable = Arc::new(RwLock::new(build_test_iftable()));
        let stage_ingress = Ingress::new("Ingress", &iftable);
        let stage_egress = Egress::new("Egress", &iftable);
        let iprouter1 = IpForwarder::new("IP-Forward-1");
        let iprouter2 = IpForwarder::new("IP-Forward-2");
        let ipfilter = IpFilter::new("Pre-routing-1-filter");

        let drop_stats = Arc::new(RwLock::new(PacketDropStats::new("Drop-stats-1")));
        let sink = StatsSink::new("Pipeline-stats", &drop_stats);

        let pipeline = DynPipeline::with_name("Router")
            .add_stage(stage_ingress)
            .add_stage(ipfilter)
            .add_stage(iprouter1)
            .add_stage(iprouter2)
            .add_stage(stage_egress)
            .add_stage(sink);
        (pipeline, drop_stats.clone())
    }

    fn addr_v4(a: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(a).expect("Bad IPv4 address")
    }
    fn addr_v6(a: &str) -> Ipv6Addr {
        Ipv6Addr::from_str(a).expect("Bad Ipv6 address")
    }
    fn build_test_ipv4_pkt(dst_ip: &str, dst_mac: Mac, proto: NextHeader) -> Packet<TestBuffer> {
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(UnicastIpv4Addr::new(addr_v4("1.2.3.4")).unwrap());
        ipv4.set_destination(addr_v4(dst_ip));
        ipv4.set_ttl(255);
        unsafe {
            ipv4.set_next_header(proto);
        }

        let mut headers = Headers::new(Eth::new(
            SourceMac::new(Mac([0x2, 0, 0, 0, 0, 99])).unwrap(),
            DestinationMac::new(dst_mac).unwrap(),
            EthType::IPV4,
        ));
        headers.net = Some(Net::Ipv4(ipv4));

        let mut buffer: TestBuffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();

        Packet::new(buffer).unwrap()
    }

    fn build_test_ipv6_pkt(dst_ip: &str, dst_mac: Mac, proto: NextHeader) -> Packet<TestBuffer> {
        let mut ipv6 = Ipv6::default();
        ipv6.set_source(UnicastIpv6Addr::new(addr_v6("2001::1")).unwrap());
        ipv6.set_destination(addr_v6(dst_ip));
        ipv6.set_hop_limit(255);
        ipv6.set_next_header(proto);

        let mut headers = Headers::new(Eth::new(
            SourceMac::new(Mac([0x2, 0, 0, 0, 0, 99])).unwrap(),
            DestinationMac::new(dst_mac).unwrap(),
            EthType::IPV6,
        ));
        headers.net = Some(Net::Ipv6(ipv6));

        let mut buffer: TestBuffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();

        Packet::new(buffer).unwrap()
    }

    impl Packet<TestBuffer> {
        fn set_description(mut self, descr: &'static str) -> Self {
            self.meta.descr = descr;
            self
        }
        fn set_iif(mut self, iif: u32) -> Self {
            self.meta.iif = InterfaceId::new(iif);
            self
        }
        fn keep(mut self) -> Self {
            self.meta.keep = true;
            self
        }
    }

    fn build_test_packets() -> Vec<Packet<TestBuffer>> {
        let mut packets = Vec::new();

        let p1 = build_test_ipv4_pkt("192.168.0.1", Mac([0x2, 0, 0, 0, 0, 29]), NextHeader::TCP)
            .set_description("MAC not for us")
            .set_iif(1)
            .keep();

        let p2 = build_test_ipv4_pkt("10.0.0.255", Mac::BROADCAST, NextHeader::UDP)
            .set_description("broadcast")
            .set_iif(1)
            .keep();

        let p3 = build_test_ipv4_pkt("10.0.0.2", Mac([0x2, 0, 0, 0, 0, 1]), NextHeader::UDP)
            .set_description("for us")
            .set_iif(1)
            .keep();

        let p4 = build_test_ipv4_pkt("11.0.0.4", Mac([0x2, 0, 0, 0, 0, 1]), NextHeader::UDP)
            .set_description("forward")
            .set_iif(1)
            .keep();

        let p5 = build_test_ipv4_pkt("11.0.0.5", Mac([0x2, 0, 0, 0, 0, 1]), NextHeader::ICMP)
            .set_description("filtered")
            .set_iif(1)
            .keep();

        let p6 = build_test_ipv6_pkt("2001::1:2:3", Mac([0x2, 0, 0, 0, 0, 1]), NextHeader::TCP)
            .set_description("ipv6")
            .set_iif(1)
            .keep();

        let p7 = build_test_ipv4_pkt("8.8.8.8", Mac([0x2, 0, 0, 0, 0, 1]), NextHeader::TCP)
            .set_description("route-drop")
            .set_iif(1)
            .keep();

        packets.push(p1);
        packets.push(p2);
        packets.push(p3);
        packets.push(p4);
        packets.push(p5);
        packets.push(p6);
        packets.push(p7);

        packets
    }

    #[test]
    fn test_pktprocessor() {
        init_test_tracing();
        let (mut pipeline, stats) = build_processor_pipeline();
        let packets = build_test_packets();
        let mut packets_out: Vec<_> = pipeline.process(packets.into_iter()).collect();

        for pkt in packets_out.iter_mut() {
            match pkt.meta.descr {
                "MAC not for us" => {
                    assert!(!pkt.meta.is_iplocal);
                    assert!(!pkt.meta.is_l2bcast);
                    assert_eq!(pkt.meta.drop, Some(DropReason::MacNotForUs));
                }
                "broadcast" => {
                    assert!(pkt.meta.is_l2bcast);
                    assert_eq!(pkt.meta.drop, Some(DropReason::Unhandled));
                }
                "for us" => {
                    assert!(!pkt.meta.is_l2bcast);
                    assert!(pkt.meta.is_iplocal);
                }
                "forward" => {
                    assert!(!pkt.meta.is_l2bcast);
                    assert!(!pkt.meta.is_iplocal);
                }
                "filtered" => {
                    assert_eq!(pkt.meta.drop, Some(DropReason::Filtered));
                }
                "ipv6" => {}
                "route-drop" => {
                    assert_eq!(pkt.meta.drop, Some(DropReason::RouteDrop));
                }
                &_ => {
                    println!("{}", pkt.meta.descr);
                    panic!("Test error")
                }
            }
        }

        if let Ok(stats) = stats.read() {
            println!("{stats:#?}");

            /* all packets counted ? */
            let total_count = stats.get_stats().iter().fold(0, |sum, entry| sum + entry.1) as usize;
            assert_eq!(total_count, packets_out.len());

            /* delivered */
            let delivered = stats.get_stats().iter().fold(0, |sum, entry| {
                if *entry.0 == DropReason::Delivered {
                    sum + entry.1
                } else {
                    sum
                }
            }) as usize;

            /* dropped */
            let dropped = stats.get_stats().iter().fold(0, |sum, entry| {
                if *entry.0 != DropReason::Delivered {
                    sum + entry.1
                } else {
                    sum
                }
            }) as usize;

            println!("total: {}", total_count);
            println!("Delivered: {}", delivered);
            println!("dropped: {}", dropped);
        }
    }
}
