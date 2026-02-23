// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod nf_test {
    use crate::portfw::flow_state::{PortFwFlowStatus, get_portfw_state_flow_status};
    use crate::portfw::{PortForwarder, PortFwEntry, PortFwKey, PortFwState, PortFwTableWriter};

    use flow_entry::flow_table::{ExpirationsNF, FlowLookup, FlowTable};
    use flow_info::{ExtractRef, FlowStatus};
    use net::buffer::TestBuffer;
    use net::headers::TryTcpMut;
    use net::ip::NextHeader;
    use net::packet::test_utils::{build_test_tcp_ipv4_packet, build_test_udp_ipv4_packet};
    use net::packet::{DoneReason, Packet, VpcDiscriminant};
    use std::time::Duration;

    use lpm::prefix::Prefix;
    use pipeline::{DynPipeline, NetworkFunction};
    use std::str::FromStr;
    use std::sync::Arc;
    use tracing_test::traced_test;

    // build a reply for a given packet
    fn build_reply(packet: &Packet<TestBuffer>) -> Packet<TestBuffer> {
        let src_vpcd = packet.meta().src_vpcd;
        let dst_vpcd = packet.meta().dst_vpcd;
        let src_mac = packet.eth_source().unwrap();
        let dst_mac = packet.eth_destination().unwrap();
        let src_ip = packet.ip_source().unwrap();
        let dst_ip = packet.ip_destination().unwrap();
        let src_port = packet.transport_src_port().unwrap();
        let dst_port = packet.transport_dst_port().unwrap();

        let mut reply = packet.clone();
        reply.meta_mut().src_vpcd = dst_vpcd;
        reply.meta_mut().dst_vpcd = src_vpcd;
        reply.set_eth_source(dst_mac).unwrap();
        reply.set_eth_destination(src_mac).unwrap();
        reply.set_ip_source(dst_ip.try_into().unwrap()).unwrap();
        reply.set_ip_destination(src_ip).unwrap();
        reply.set_source_port(dst_port).unwrap();
        reply.set_destination_port(src_port).unwrap();
        reply.meta_mut().dst_vpcd.take(); // FIXME

        if reply.is_tcp() {
            let tcp = reply.try_tcp_mut().unwrap();
            if tcp.syn() && tcp.ack() {
                tcp.set_syn(false);
            }
            tcp.set_ack(true);
        }
        reply
    }

    // build a sample port forwarding table
    fn build_test_port_forwarding_ruleset() -> Vec<PortFwEntry> {
        let mut ruleset = vec![];
        let key = PortFwKey::new(
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            NextHeader::TCP,
        );
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (3022, 3022),
            (22, 22),
            None,
            None,
        )
        .unwrap();
        ruleset.push(entry);

        let key = PortFwKey::new(
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            NextHeader::UDP,
        );
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.2/32").unwrap(),
            (3053, 3053),
            (53, 53),
            None,
            None,
        )
        .unwrap();
        ruleset.push(entry);
        ruleset
    }

    // build a UDP packet to be port forwarded according to the port-forwarding table
    fn udp_packet_to_port_forward() -> Packet<TestBuffer> {
        let mut packet: Packet<TestBuffer> =
            build_test_udp_ipv4_packet("10.0.0.1", "70.71.72.73", 9876, 3053);
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(2000.try_into().unwrap()));
        packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(3000.try_into().unwrap()));
        packet.meta_mut().set_port_forwarding(true);
        packet
    }

    // build a TCP packet to be port forwarded according to the port-forwarding table
    fn tcp_packet_to_port_forward() -> Packet<TestBuffer> {
        let mut packet = build_test_tcp_ipv4_packet("10.0.0.2", "70.71.72.73", 7777, 3022);
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(2000.try_into().unwrap()));
        packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(3000.try_into().unwrap()));
        packet.meta_mut().set_port_forwarding(true);
        packet
    }

    fn tcp_packet_reverse_reply() -> Packet<TestBuffer> {
        let mut packet = build_test_tcp_ipv4_packet("192.168.1.1", "10.0.0.2", 22, 7777);
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(3000.try_into().unwrap()));
        packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(2000.try_into().unwrap()));
        packet.meta_mut().set_port_forwarding(true);
        packet
    }

    // packet-dumping wrapper
    fn process_packet(
        pipeline: &mut DynPipeline<TestBuffer>,
        packet: Packet<TestBuffer>,
    ) -> Packet<TestBuffer> {
        println!("INPUT:{packet}");
        let output: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
        let output = output.first().unwrap();
        println!("OUTPUT:{output}");
        output.clone()
    }

    /// sets up a port-forwarding pipeline
    fn setup_pipeline(
        ruleset: &[PortFwEntry],
    ) -> (Arc<FlowTable>, DynPipeline<TestBuffer>, PortFwTableWriter) {
        // build a pipeline with flow lookup + port forwarder
        let mut writer = PortFwTableWriter::new();
        let flow_table = Arc::new(FlowTable::new(1024));
        let flow_lookup_nf = FlowLookup::new("flow-lookup", flow_table.clone());
        let nf = PortForwarder::new("port-forwarder", writer.reader(), flow_table.clone());
        let flow_expirations = ExpirationsNF::new(flow_table.clone());
        let pipeline: DynPipeline<TestBuffer> = DynPipeline::new()
            .add_stage(flow_lookup_nf)
            .add_stage(nf)
            .add_stage(flow_expirations);

        // set port-forwarding rules
        writer.update_table(ruleset).unwrap();
        if let Some(table) = writer.enter() {
            println!("{}", table.as_ref());
        }
        (flow_table, pipeline, writer)
    }

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding_base() {
        let ruleset = build_test_port_forwarding_ruleset();

        // build a pipeline with flow lookup + port forwarder
        let (_flow_table, mut pipeline, _writer) = setup_pipeline(&ruleset);

        // process an overlay packet matching a port-forwarding rule
        let output = process_packet(&mut pipeline, udp_packet_to_port_forward());
        assert_eq!(output.ip_source().unwrap().to_string(), "10.0.0.1");
        assert_eq!(output.ip_destination().unwrap().to_string(), "192.168.1.2");
        assert_eq!(output.udp_source_port().unwrap().as_u16(), 9876);
        assert_eq!(output.udp_destination_port().unwrap().as_u16(), 53);
        assert!(output.meta().flow_info.is_none());

        // process a packet in the reverse direction
        let reply = build_reply(&output);
        let output = process_packet(&mut pipeline, reply);
        assert_eq!(output.ip_source().unwrap().to_string(), "70.71.72.73");
        assert_eq!(output.ip_destination().unwrap().to_string(), "10.0.0.1");
        assert_eq!(output.udp_source_port().unwrap().as_u16(), 3053);
        assert_eq!(output.udp_destination_port().unwrap().as_u16(), 9876);
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::TwoWay)
        );

        let flow_info = output.meta().flow_info.as_ref().unwrap();
        assert_eq!(flow_info.status(), FlowStatus::Active);
        let expires_in = flow_info
            .expires_at()
            .saturating_duration_since(std::time::Instant::now())
            .as_secs();
        assert!(expires_in > PortFwEntry::INITIAL_TIMEOUT.as_secs() - 2);

        // process original packet again. It should be fast-natted
        let mut repeated = udp_packet_to_port_forward();
        // this is a hack needed until the flow lookup gets fixed.
        repeated.meta_mut().dst_vpcd.take();
        let output = process_packet(&mut pipeline, repeated);
        assert_eq!(output.ip_source().unwrap().to_string(), "10.0.0.1");
        assert_eq!(output.ip_destination().unwrap().to_string(), "192.168.1.2");
        assert_eq!(output.udp_source_port().unwrap().as_u16(), 9876);
        assert_eq!(output.udp_destination_port().unwrap().as_u16(), 53);

        // flow entry should be there
        let flow_info = output.meta().flow_info.as_ref().unwrap();
        assert_eq!(flow_info.status(), FlowStatus::Active);
        let expires_in = flow_info
            .expires_at()
            .saturating_duration_since(std::time::Instant::now())
            .as_secs();
        assert!(expires_in > PortFwEntry::ESTABLISHED_TIMEOUT.as_secs() - 5);
    }

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding_tcp_filtered() {
        let ruleset = build_test_port_forwarding_ruleset();

        // build a pipeline with flow lookup + port forwarder
        let (_, mut pipeline, _writer) = setup_pipeline(&ruleset);

        // process packet with TCP segment without SYN: no entry should be created and packet be dropped
        let mut packet = tcp_packet_to_port_forward();
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_syn(false);
        let output = process_packet(&mut pipeline, packet);
        assert_eq!(output.get_done(), Some(DoneReason::Filtered));

        // process a packet in reverse direction: no flow info should have been found
        let packet = tcp_packet_reverse_reply();
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_none());
    }

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding_tcp_success() {
        let ruleset = build_test_port_forwarding_ruleset();

        // build a pipeline with flow lookup + port forwarder
        let (flow_table, mut pipeline, _writer) = setup_pipeline(&ruleset);

        // process TCP SYN packet: entries should be created in both directions
        let mut packet = tcp_packet_to_port_forward();
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_syn(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());

        // process TCP SYN|ACK packet in reverse direction: flow entry should be found. State should become 2way
        let reply = build_reply(&output);
        let output = process_packet(&mut pipeline, reply);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::TwoWay)
        );

        // process TCP ACK packet in forward direction
        let mut packet = tcp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_ack(true);
        tcp.set_syn(false);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::Established)
        );

        // process TCP FIN in reverse direction: flow entry should be found. State should become Closing
        let mut packet = tcp_packet_reverse_reply();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_fin(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::Closing)
        );

        // process TCP FIN ACK packet in forward direction
        let mut packet = tcp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_ack(true);
        tcp.set_fin(false);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::Closing)
        );

        // process TCP ACK in reverse direction: flow entry should be found. State should become Closing
        let mut packet = tcp_packet_reverse_reply();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_ack(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::Closing)
        );
        println!("{flow_table}");
        assert_eq!(flow_table.len().unwrap(), 2);
    }

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding_tcp_reset() {
        let ruleset = build_test_port_forwarding_ruleset();
        let (flow_table, mut pipeline, _writer) = setup_pipeline(&ruleset);

        // process TCP SYN packet: entries should be created in both directions
        let mut packet = tcp_packet_to_port_forward();
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_syn(true);
        let output = process_packet(&mut pipeline, packet);

        // process TCP SYN|ACK packet in reverse direction: flow entry should be found. State should become 2way
        let reply = build_reply(&output);
        process_packet(&mut pipeline, reply);

        // process TCP ACK packet in forward direction
        let mut packet = tcp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_ack(true);
        tcp.set_syn(false);
        let output = process_packet(&mut pipeline, packet);
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::Established)
        );

        // process TCP RST packet in forward direction.
        let mut packet = tcp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_rst(true);
        tcp.set_syn(false);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert!(get_portfw_state_flow_status(&output).is_none());

        // the flow table still contains the two flows, although they are unusable
        // this will be fixed later.
        assert_eq!(flow_table.len(), Some(2));
        println!("{flow_table}");
    }

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding_config_removal_interrupts_traffic() {
        let ruleset = build_test_port_forwarding_ruleset();

        // build a pipeline with flow lookup + port forwarder
        let (flow_table, mut pipeline, mut writer) = setup_pipeline(&ruleset);

        // process TCP SYN packet: entries should be created in both directions
        let mut packet = tcp_packet_to_port_forward();
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_syn(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());

        // process TCP SYN|ACK packet in reverse direction: flow entry should be found. State should become 2way
        let mut packet = tcp_packet_reverse_reply();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_syn(true);
        tcp.set_ack(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::TwoWay)
        );

        // process TCP ACK packet in forward direction
        let mut packet = tcp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_ack(true);
        tcp.set_syn(false);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::Established)
        );

        // build the same table without the TCP port-forwarding rule
        let mut ruleset = build_test_port_forwarding_ruleset();
        ruleset.remove(0);
        writer.update_table(&ruleset).unwrap();

        let mut packet = tcp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_ack(false);
        tcp.set_syn(false);
        let output = process_packet(&mut pipeline, packet);
        assert_eq!(output.get_done(), Some(DoneReason::Filtered));
        assert!(get_portfw_state_flow_status(&output).is_none());

        println!("{flow_table}");

        std::thread::sleep(Duration::from_secs(4));
        let _ = pipeline.process(std::iter::empty::<Packet<TestBuffer>>());

        let mut packet = tcp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_ack(false);
        tcp.set_syn(false);
        let output = process_packet(&mut pipeline, packet);
        assert_eq!(output.get_done(), Some(DoneReason::Filtered));
        assert!(get_portfw_state_flow_status(&output).is_none());
        println!("{flow_table}");
    }

    fn build_test_port_forwarding_table_with_ranges() -> Vec<PortFwEntry> {
        let mut ruleset = vec![];
        let key = PortFwKey::new(
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            NextHeader::UDP,
        );
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.2/32").unwrap(),
            (3000, 3100),
            (2000, 2100),
            None,
            None,
        )
        .unwrap();
        ruleset.push(entry);
        ruleset
    }

    fn build_test_port_forwarding_table_with_prefixes_and_port_ranges() -> Vec<PortFwEntry> {
        let mut ruleset = vec![];
        let key = PortFwKey::new(
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            NextHeader::UDP,
        );
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.70/24").unwrap(),
            Prefix::from_str("192.168.6.0/24").unwrap(),
            (3000, 3100),
            (2000, 2100),
            None,
            None,
        )
        .unwrap();
        ruleset.push(entry);
        ruleset
    }

    fn hit_port_fw_state_invalid(packet: &Packet<TestBuffer>) -> bool {
        // should have reference to some entry
        let flow = packet.meta().flow_info.as_ref().unwrap();

        // flow entry should have port-forwarding state
        let locked = flow.locked.read().unwrap();
        let state = locked
            .port_fw_state
            .as_ref()
            .unwrap()
            .extract_ref::<PortFwState>()
            .unwrap();

        // tell if port forwarding state is valid
        state.rule().upgrade().is_none()
    }
    fn hit_port_fw_state_valid(packet: &Packet<TestBuffer>) -> bool {
        // should have reference to some entry
        let flow = packet.meta().flow_info.as_ref().unwrap();

        // flow entry should have port-forwarding state
        let locked = flow.locked.read().unwrap();
        let state = locked
            .port_fw_state
            .as_ref()
            .unwrap()
            .extract_ref::<PortFwState>()
            .unwrap();

        // tell if port forwarding state is valid
        state.rule().upgrade().is_some()
    }

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding_with_port_ranges() {
        let ruleset = build_test_port_forwarding_table_with_ranges();
        let (flow_table, mut pipeline, mut writer) = setup_pipeline(&ruleset);

        // process udp packet to be port-forwarded
        let packet = udp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());

        // send another packet to be port-forwarded: it should hit a flow
        //       let mut packet = udp_packet_to_port_forward();
        //        packet.meta_mut().dst_vpcd.take();
        //        let output = process_packet(&mut pipeline, packet);
        //        assert!(hit_port_fw_state_valid(&output));

        // the flow table should have 2 flows
        assert_eq!(flow_table.len(), Some(2));
        println!("{flow_table}");

        // process a reply from the dest vpc. It should hit a flow
        let mut reply = build_reply(&output);
        reply.meta_mut().dst_vpcd.take();
        let output = process_packet(&mut pipeline, reply);
        assert!(!output.is_done());
        assert!(hit_port_fw_state_valid(&output));

        // clear table: all rules will be gone
        writer.update_table(&[]).unwrap();

        // the flow table keeps the two flows, but the flows should be invalidated
        assert_eq!(flow_table.len(), Some(2));

        // process the original udp packet to be port-forwarded: it should still find a flow
        // but it should not be valid for port-forwarding.
        let mut packet = udp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take();
        let output = process_packet(&mut pipeline, packet);
        assert!(hit_port_fw_state_invalid(&output));

        println!("{flow_table}");
    }

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding_with_prefixes_and_port_ranges() {
        let ruleset = build_test_port_forwarding_table_with_prefixes_and_port_ranges();
        let (flow_table, mut pipeline, mut writer) = setup_pipeline(&ruleset);

        // process udp packet to be port-forwarded
        let packet = udp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());

        // send another packet to be port-forwarded: it should hit a flow
        //        let mut packet = udp_packet_to_port_forward();
        //        packet.meta_mut().dst_vpcd.take();
        //        let output = process_packet(&mut pipeline, packet);
        //        assert!(hit_port_fw_state_valid(&output));

        // the flow table should have 2 flows
        assert_eq!(flow_table.len(), Some(2));
        println!("{flow_table}");

        // process a reply from the dest vpc. It should hit a flow
        let mut reply = build_reply(&output);
        reply.meta_mut().dst_vpcd.take();
        let output = process_packet(&mut pipeline, reply);
        assert!(!output.is_done());
        assert!(hit_port_fw_state_valid(&output));

        // clear table: all rules will be gone
        writer.update_table(&[]).unwrap();

        // the flow table keeps the two flows, but the flows should be invalidated
        assert_eq!(flow_table.len(), Some(2));

        // process the original udp packet to be port-forwarded: it should still find a flow
        // but it should not be valid for port-forwarding.
        let mut packet = udp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take();
        let output = process_packet(&mut pipeline, packet);
        assert!(hit_port_fw_state_invalid(&output));

        println!("{flow_table}");
    }
}
