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
}
