// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network Function specific flow table.

use tracing::debug;

use concurrency::sync::Arc;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::NetworkFunction;

use crate::flow_table::{FlowKey, FlowTable};

use tracectl::trace_target;
trace_target!("flow-lookup", LevelFilter::INFO, &["pipeline"]);

pub struct LookupNF {
    name: String,
    flow_table: Arc<FlowTable>,
}

impl LookupNF {
    pub fn new(name: &str, flow_table: Arc<FlowTable>) -> Self {
        Self {
            name: name.to_string(),
            flow_table,
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for LookupNF {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(move |mut packet| {
            if !packet.is_done() && packet.meta().is_overlay() {
                let flow_key = FlowKey::try_from(crate::flow_table::flow_key::Uni(&packet)).ok();
                if let Some(flow_key) = flow_key
                    && let Some(flow_info) = self.flow_table.lookup(&flow_key)
                {
                    debug!(
                        "{}: Tagging packet with flow info for flow key {:?}",
                        self.name, flow_key
                    );
                    packet.meta_mut().flow_info = Some(flow_info);
                } else {
                    debug!(
                        "{}: No flow info found for flow key {:?}",
                        self.name, flow_key
                    );
                }
            }
            packet.enforce()
        })
    }
}

#[cfg(test)]
mod test {
    use flow_info::FlowInfo;
    use net::buffer::PacketBufferMut;
    use net::buffer::TestBuffer;
    use net::ip::NextHeader;
    use net::ip::UnicastIpAddr;
    use net::packet::Packet;
    use net::packet::VpcDiscriminant;
    use net::packet::test_utils::{
        build_test_ipv4_packet_with_transport, build_test_udp_ipv4_packet,
    };
    use net::tcp::TcpPort;
    use net::vxlan::Vni;
    use pipeline::DynPipeline;
    use pipeline::NetworkFunction;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tracing_test::traced_test;

    use crate::flow_table::ExpirationsNF;
    use crate::flow_table::FlowKey;
    use crate::flow_table::FlowTable;
    use crate::flow_table::nf_lookup::LookupNF;

    #[test]
    fn test_lookup_nf() {
        let flow_table = Arc::new(FlowTable::default());
        let mut lookup_nf = LookupNF::new("test_lookup_nf", flow_table.clone());
        let src_vpcd = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let src_ip = "1.2.3.4".parse::<UnicastIpAddr>().unwrap();
        let dst_ip = "5.6.7.8".parse::<IpAddr>().unwrap();
        let src_port = TcpPort::new_checked(1025).unwrap();
        let dst_port = TcpPort::new_checked(2048).unwrap();

        // Create a packet with the right info
        let mut packet = build_test_ipv4_packet_with_transport(100, Some(NextHeader::TCP)).unwrap();
        packet.meta_mut().src_vpcd = Some(src_vpcd);
        packet.set_ip_source(src_ip).unwrap();
        packet.set_ip_destination(dst_ip).unwrap();
        packet.set_tcp_source_port(src_port).unwrap();
        packet.set_tcp_destination_port(dst_port).unwrap();
        packet.meta_mut().set_overlay(true);

        // Insert matching flow entry
        let flow_key = FlowKey::try_from(crate::flow_table::flow_key::Uni(&packet)).unwrap();
        let flow_info = FlowInfo::new(Instant::now() + Duration::from_secs(10));
        flow_table.insert(flow_key, flow_info);

        // Ensure packet is tagged
        let mut output_iter = lookup_nf.process(std::iter::once(packet));
        let output = output_iter.next().unwrap();
        assert!(output.meta().flow_info.is_some());
    }

    // A dummy NF that creates a flow entry for each packet, with a lifetime of 2 seconds
    struct FlowInfoCreator {
        flow_table: Arc<FlowTable>,
        timeout: Duration,
    }
    impl FlowInfoCreator {
        fn new(flow_table: Arc<FlowTable>, timeout: Duration) -> Self {
            Self {
                flow_table,
                timeout,
            }
        }
    }
    impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowInfoCreator {
        fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
            &'a mut self,
            input: Input,
        ) -> impl Iterator<Item = Packet<Buf>> + 'a {
            input.filter_map(move |packet| {
                let flow_key =
                    FlowKey::try_from(crate::flow_table::flow_key::Uni(&packet)).unwrap();
                let flow_info = FlowInfo::new(Instant::now() + self.timeout);
                self.flow_table.insert(flow_key, flow_info);
                packet.enforce()
            })
        }
    }

    #[traced_test]
    #[test]
    fn test_lookup_nf_with_expiration_nf() {
        let flow_table = Arc::new(FlowTable::default());
        let lookup_nf = LookupNF::new("lookup_nf", flow_table.clone());
        let flowinfo_creator = FlowInfoCreator::new(flow_table.clone(), Duration::from_secs(1));
        let expirations_nf = ExpirationsNF::new(flow_table.clone());
        let mut pipeline: DynPipeline<TestBuffer> = DynPipeline::new()
            .add_stage(lookup_nf)
            .add_stage(flowinfo_creator)
            .add_stage(expirations_nf);

        const NUM_PACKETS: u16 = 1000;

        // create NUM_PACKETS, each with a distinct port from in [1, NUM_PACKETS]
        let dst_ports = 1..=NUM_PACKETS;
        let packets_in = dst_ports
            .into_iter()
            .map(|port| build_test_udp_ipv4_packet("10.0.0.1", "20.0.0.1", 80, port));

        // process the NUM_PACKETS
        let packets_out = pipeline.process(packets_in.clone());
        assert_eq!(packets_out.count(), NUM_PACKETS as usize);
        let num_entries = flow_table.len().unwrap();
        assert_eq!(num_entries, NUM_PACKETS as usize);

        // wait twice as much as entry lifetimes. All flow entries should be gone after this.
        std::thread::sleep(std::time::Duration::from_secs(2));
        pipeline
            .process(std::iter::empty::<Packet<TestBuffer>>())
            .count();

        // Entries are all gone
        let num_entries = flow_table.len().unwrap();
        assert_eq!(num_entries, 0);
    }

    //#[traced_test]
    #[test]
    fn test_lookups_with_related_flows() {
        let flow_table = Arc::new(FlowTable::default());
        let lookup_nf = LookupNF::new("lookup_nf", flow_table.clone());
        let expirations_nf = ExpirationsNF::new(flow_table.clone());
        let mut pipeline: DynPipeline<TestBuffer> = DynPipeline::new()
            .add_stage(lookup_nf)
            .add_stage(expirations_nf);

        {
            let mut packet_1 = build_test_udp_ipv4_packet("10.0.0.1", "20.0.0.1", 80, 500);
            let mut packet_2 = build_test_udp_ipv4_packet("192.168.1.1", "20.0.0.1", 500, 80);
            packet_1.meta_mut().set_overlay(true);
            packet_2.meta_mut().set_overlay(true);

            // build keys for the packets
            let key_1 = FlowKey::try_from(crate::flow_table::flow_key::Uni(&packet_1)).unwrap();
            let key_2 = FlowKey::try_from(crate::flow_table::flow_key::Uni(&packet_2)).unwrap();

            // create a pair of related flow entries; flow_2 will get a longer timeout
            let (flow_1, flow_2) = FlowInfo::related_pair(Instant::now() + Duration::from_secs(2));
            assert_eq!(Arc::weak_count(&flow_1), 1);
            assert_eq!(Arc::weak_count(&flow_2), 1);
            assert_eq!(Arc::strong_count(&flow_1), 1);
            assert_eq!(Arc::strong_count(&flow_2), 1);

            // extend flow2's timeout so that it does not expire
            flow_2.extend_expiry_unchecked(Duration::from_secs(60));

            // ... and insert the two flows in the flow table
            flow_table.insert_from_arc(key_1, &flow_1);
            flow_table.insert_from_arc(key_2, &flow_2);

            // check that flows can be looked up
            let _ = flow_table.lookup(&key_1).unwrap();
            let _ = flow_table.lookup(&key_2).unwrap();

            // process the packets and check that related flows are accessible
            let input = vec![packet_1, packet_2];
            let out: Vec<_> = pipeline.process(input.into_iter()).collect();
            let packet_1 = &out[0];
            let packet_2 = &out[1];

            let flow_1_pkt = packet_1.meta().flow_info.as_ref().unwrap();
            let flow_2_pkt = packet_2.meta().flow_info.as_ref().unwrap();
            assert!(Arc::ptr_eq(flow_1_pkt, &flow_1));
            assert!(Arc::ptr_eq(flow_2_pkt, &flow_2));

            let related_1 = flow_1.related.as_ref().unwrap().upgrade().unwrap();
            let related_2 = flow_2.related.as_ref().unwrap().upgrade().unwrap();
            assert!(Arc::ptr_eq(&related_1, &flow_2));
            assert!(Arc::ptr_eq(&related_1, flow_2_pkt));
            assert!(Arc::ptr_eq(&related_2, &flow_1));
            assert!(Arc::ptr_eq(&related_2, flow_1_pkt));
            assert_eq!(flow_table.len().unwrap(), 2);
        }

        // wait 3 secs. Flow 1 should have been removed
        std::thread::sleep(Duration::from_secs(3));
        pipeline
            .process(std::iter::empty::<Packet<TestBuffer>>())
            .count();

        assert_eq!(flow_table.len().unwrap(), 1);

        // build identical packets and process them again
        let mut packet_1 = build_test_udp_ipv4_packet("10.0.0.1", "20.0.0.1", 80, 500);
        let mut packet_2 = build_test_udp_ipv4_packet("192.168.1.1", "20.0.0.1", 500, 80);
        packet_1.meta_mut().set_overlay(true);
        packet_2.meta_mut().set_overlay(true);
        let key_1 = FlowKey::try_from(crate::flow_table::flow_key::Uni(&packet_1)).unwrap();
        let key_2 = FlowKey::try_from(crate::flow_table::flow_key::Uni(&packet_2)).unwrap();
        let input = vec![packet_1, packet_2];
        let out: Vec<_> = pipeline.process(input.into_iter()).collect();
        let packet_1 = &out[0];
        let packet_2 = &out[1];

        // flow 1 should have expired and packet packet_1 no longer refer to it
        assert!(packet_1.meta().flow_info.is_none());
        assert!(flow_table.lookup(&key_1).is_none());

        // flow 2 should remain and packet_2 refer to it
        assert!(flow_table.lookup(&key_2).is_some());
        let flow_info_2 = packet_2.meta().flow_info.as_ref().unwrap();

        // the flow 2's reference to flow 1 should exist but be invalid
        let related = flow_info_2.related.as_ref().unwrap();
        assert!(related.upgrade().is_none());
    }
}
