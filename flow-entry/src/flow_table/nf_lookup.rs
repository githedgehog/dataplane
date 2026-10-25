// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network Function specific flow table.

use tracing::debug;

use concurrency::sync::Arc;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::NetworkFunction;

use crate::flow_table::FlowTable;
use net::FlowKey;

use tracectl::trace_target;
trace_target!("flow-lookup", LevelFilter::INFO, &["pipeline"]);

pub struct FlowLookup {
    name: String,
    flow_table: Arc<FlowTable>,
}

impl FlowLookup {
    #[must_use]
    pub fn new(name: &str, flow_table: Arc<FlowTable>) -> Self {
        Self {
            name: name.to_string(),
            flow_table,
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowLookup {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        for packet in burst.iter_mut() {
            let nfi = &self.name;
            if !packet.is_done() && packet.meta().is_overlay() && packet.meta().dst_vpcd.is_none() {
                if let Ok(flow_key) = FlowKey::try_from(&*packet) {
                    if let Some(flow_info) = self.flow_table.lookup(&flow_key) {
                        debug!("{nfi}: Tagging packet with flow info for flow key {flow_key}",);
                        packet.meta_mut().flow_info = Some(flow_info);
                    } else {
                        debug!("{nfi}: No flow info found for flow key {flow_key}",);
                    }
                } else {
                    debug!("{nfi}: can't build flow key for packet");
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use clock::Duration;
    use concurrency::sync::Arc;
    use net::FlowKey;
    use net::buffer::PacketBufferMut;
    use net::buffer::TestBuffer;
    use net::flows::{FlowInfo, FlowInfoFlags};
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
    use tracing_test::traced_test;

    use crate::flow_table::FlowTable;
    use crate::flow_table::WorkerFlowTable;
    use crate::flow_table::nf_lookup::FlowLookup;

    #[tokio::test]
    async fn test_lookup_nf() {
        let flow_table = Arc::new(FlowTable::default());
        let flows = WorkerFlowTable::new(flow_table.clone());
        let mut lookup_nf = FlowLookup::new("test_lookup_nf", flow_table.clone());
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
        let flow_key = FlowKey::try_from(&packet).unwrap();
        let flow_info = FlowInfo::new(flow_key, clock::now() + Duration::from_secs(10));
        flows.insert(flow_info).unwrap();

        // Ensure packet is tagged
        let mut output_iter = lookup_nf.process(std::iter::once(packet));
        let output = output_iter.next().unwrap();
        assert!(output.meta().flow_info.is_some());
    }

    // A dummy NF that creates a flow entry for each packet, with a configurable lifetime
    struct FlowInfoCreator {
        flow_table: WorkerFlowTable,
        timeout: Duration,
    }
    impl FlowInfoCreator {
        fn new(flow_table: WorkerFlowTable, timeout: Duration) -> Self {
            Self {
                flow_table,
                timeout,
            }
        }
    }
    impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowInfoCreator {
        fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
            for packet in burst.iter() {
                let flow_key = FlowKey::try_from(packet).unwrap();
                let flow_info = FlowInfo::new(flow_key, clock::now() + self.timeout);
                self.flow_table
                    .insert(flow_info)
                    .expect("insert in FlowInfoCreator should not fail");
            }
        }
    }

    #[cfg_attr(not(miri), traced_test)]
    #[tokio::test(start_paused = true)]
    async fn test_lookup_nf_with_expiration() {
        let flow_table = Arc::new(FlowTable::default());
        let flows = WorkerFlowTable::new(flow_table.clone());
        let lookup_nf = FlowLookup::new("lookup_nf", flow_table.clone());
        let flowinfo_creator = FlowInfoCreator::new(flows.clone(), Duration::from_secs(1));
        let mut pipeline: DynPipeline<'static, TestBuffer> = DynPipeline::new()
            .add_stage(lookup_nf)
            .add_stage(flowinfo_creator);

        const NUM_PACKETS: u16 = cfg_select! {
            emulated => 10,
            _ => 1000,
        };

        // create NUM_PACKETS, each with a distinct port from in [1, NUM_PACKETS]
        let dst_ports = 1..=NUM_PACKETS;
        let packets_in = dst_ports
            .into_iter()
            .map(|port| build_test_udp_ipv4_packet("10.0.0.1", "20.0.0.1", 80, port));

        // process the NUM_PACKETS
        let packets_out = pipeline.process(packets_in.clone());
        assert_eq!(packets_out.count(), NUM_PACKETS as usize);
        let num_entries = flow_table.active_len().unwrap();
        assert_eq!(num_entries, NUM_PACKETS as usize);

        // wait twice as much as entry lifetimes — all flow timers are due by now
        tokio::time::sleep(Duration::from_secs(2)).await;
        flows.expire_all(clock::now());

        // All flows are now expired (by the wheel of the handle that inserted them)
        let num_entries = flow_table.active_len().unwrap();
        assert_eq!(num_entries, 0);
    }

    //#[traced_test]
    // start_paused so flow deadlines and the test's sleep share tokio's virtual
    // clock; otherwise miri's slow interpretation lets real wall time blow past the pair's
    // 1-minute deadline (the whole test takes ~90s under miri). Same root cause as
    // test_flow_table_timeout.
    #[tokio::test(start_paused = true)]
    async fn test_lookups_with_related_flows() {
        let flow_table = Arc::new(FlowTable::default());
        let flows = WorkerFlowTable::new(flow_table.clone());
        let lookup_nf = FlowLookup::new("lookup_nf", flow_table.clone());
        let mut pipeline: DynPipeline<'static, TestBuffer> =
            DynPipeline::new().add_stage(lookup_nf);
        let doomed;

        {
            let mut packet_1 = build_test_udp_ipv4_packet("10.0.0.1", "20.0.0.1", 80, 500);
            let mut packet_2 = build_test_udp_ipv4_packet("192.168.1.1", "20.0.0.1", 500, 80);
            packet_1.meta_mut().set_overlay(true);
            packet_2.meta_mut().set_overlay(true);

            // build keys for the packets
            let key_1 = FlowKey::try_from(&packet_1).unwrap();
            let key_2 = FlowKey::try_from(&packet_2).unwrap();

            // create a pair of related flow entries
            let expires_at = clock::now() + Duration::from_secs(2);
            let (flow_1, flow_2) = FlowInfo::related_pair(
                expires_at,
                key_1,
                FlowInfoFlags::default() | FlowInfoFlags::INITIATOR,
                key_2,
                FlowInfoFlags::default(),
            )
            .unwrap();

            assert_eq!(Arc::weak_count(&flow_1), 1);
            assert_eq!(Arc::weak_count(&flow_2), 1);
            assert_eq!(Arc::strong_count(&flow_1), 1);
            assert_eq!(Arc::strong_count(&flow_2), 1);

            // the halves share their expiry: extending one extends both
            flow_2.extend_expiry_unchecked(Duration::from_mins(1));
            assert_eq!(flow_1.expires_at(), flow_2.expires_at());

            // ... and insert the two flows in the flow table
            flows.insert_from_arc(&flow_1).unwrap();
            flows.insert_from_arc(&flow_2).unwrap();

            // check that flows can be looked up
            let _ = flow_table.lookup(&key_1).unwrap();
            let _ = flow_table.lookup(&key_2).unwrap();

            // process the packets and check that related flows are accessible
            let input = vec![packet_1, packet_2];
            let out: Vec<_> = pipeline.process(input).collect();
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
            assert_eq!(flow_table.active_len().unwrap(), 2);
            doomed = Arc::downgrade(&flow_1);
        }

        // past the pair's original deadline, both halves live on; then flow 1 is invalidated,
        // and the worker removes it
        tokio::time::sleep(Duration::from_secs(3)).await;
        flows.expire_all(clock::now());
        assert_eq!(flow_table.active_len().unwrap(), 2);
        doomed.upgrade().unwrap().invalidate();
        flows.expire_all(clock::now());

        assert_eq!(flow_table.active_len().unwrap(), 1);

        // build identical packets and process them again
        let mut packet_1 = build_test_udp_ipv4_packet("10.0.0.1", "20.0.0.1", 80, 500);
        let mut packet_2 = build_test_udp_ipv4_packet("192.168.1.1", "20.0.0.1", 500, 80);
        packet_1.meta_mut().set_overlay(true);
        packet_2.meta_mut().set_overlay(true);
        let key_1 = FlowKey::try_from(&packet_1).unwrap();
        let key_2 = FlowKey::try_from(&packet_2).unwrap();
        let input = vec![packet_1, packet_2];
        let out: Vec<_> = pipeline.process(input).collect();
        let packet_1 = &out[0];
        let packet_2 = &out[1];

        // flow 1 should be gone and packet packet_1 no longer refer to it
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
