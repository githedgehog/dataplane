// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod nf_test {
    use crate::portfw::protocol::PortFwFlowStatus;
    use crate::portfw::{PortForwarder, PortFwEntry, PortFwKey, PortFwState, PortFwTableWriter};

    use flow_entry::flow_table::{FlowLookup, FlowTable};
    use net::buffer::TestBuffer;
    use net::flows::FlowStatus;
    use net::flows::flow_info_item::ExtractRef;
    use net::headers::TryTcpMut;
    use net::ip::NextHeader;
    use net::packet::test_utils::{build_test_tcp_ipv4_packet, build_test_udp_ipv4_packet};
    use net::packet::{DoneReason, Packet, VpcDiscriminant};
    use std::time::Duration;

    use concurrency::sync::Arc;
    use lpm::prefix::Prefix;
    use pipeline::{DynPipeline, NetworkFunction};
    use std::str::FromStr;
    use tracing_test::traced_test;

    fn get_flow_status(packet: &Packet<TestBuffer>) -> Option<FlowStatus> {
        packet
            .meta()
            .flow_info
            .as_ref()
            .map(|flow_info| flow_info.status())
    }

    fn get_pfw_flow_status(packet: &Packet<TestBuffer>) -> Option<PortFwFlowStatus> {
        packet
            .meta()
            .flow_info
            .as_ref()?
            .locked
            .read()
            .unwrap()
            .port_fw_state
            .as_ref()
            .and_then(|s| s.extract_ref::<PortFwState>())
            .map(|state| state.status.load())
    }

    fn get_pfw_flow_state_rule(packet: &Packet<TestBuffer>) -> Option<Arc<PortFwEntry>> {
        packet
            .meta()
            .flow_info
            .as_ref()?
            .locked
            .read()
            .unwrap()
            .port_fw_state
            .as_ref()
            .and_then(|s| s.extract_ref::<PortFwState>())
            .and_then(|state| state.rule.upgrade())
    }

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
        packet.try_tcp_mut().unwrap().set_syn(false);
        packet.try_tcp_mut().unwrap().set_ack(false);
        packet.try_tcp_mut().unwrap().set_fin(false);
        packet.try_tcp_mut().unwrap().set_rst(false);

        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(2000.try_into().unwrap()));
        packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(3000.try_into().unwrap()));
        packet.meta_mut().set_port_forwarding(true);
        packet
    }

    fn tcp_packet_reverse_reply() -> Packet<TestBuffer> {
        let mut packet = build_test_tcp_ipv4_packet("192.168.1.1", "10.0.0.2", 22, 7777);
        packet.try_tcp_mut().unwrap().set_syn(false);
        packet.try_tcp_mut().unwrap().set_ack(false);
        packet.try_tcp_mut().unwrap().set_fin(false);
        packet.try_tcp_mut().unwrap().set_rst(false);

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
        let flow_table = Arc::new(FlowTable::default());
        let flow_lookup_nf = FlowLookup::new("flow-lookup", flow_table.clone());
        let nf = PortForwarder::new("port-forwarder", writer.reader(), flow_table.clone());
        let pipeline: DynPipeline<TestBuffer> =
            DynPipeline::new().add_stage(flow_lookup_nf).add_stage(nf);

        // set port-forwarding rules
        writer.update_table(ruleset).unwrap();
        if let Some(table) = writer.enter() {
            println!("{}", table.as_ref());
        }
        (flow_table, pipeline, writer)
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_base() {
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
        assert_eq!(get_flow_status(&output), Some(FlowStatus::Active));
        assert_eq!(get_pfw_flow_status(&output), Some(PortFwFlowStatus::TwoWay));

        let flow_info = output.meta().flow_info.as_ref().unwrap();
        assert_eq!(flow_info.status(), FlowStatus::Active);
        let expires_in = flow_info
            .expires_at()
            .saturating_duration_since(std::time::Instant::now())
            .as_secs();
        assert!(expires_in > PortFwEntry::DEFAULT_INITIAL_TOUT.as_secs() - 2);

        // process original packet again. It should be fast-natted
        let repeated = udp_packet_to_port_forward();
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
        assert!(expires_in > PortFwEntry::DEFAULT_ESTABLISHED_TOUT_UDP.as_secs() - 5);
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
        assert_eq!(output.get_done(), Some(DoneReason::NatNotPortForwarded));

        // process a packet in reverse direction: no flow info should have been found
        let packet = tcp_packet_reverse_reply();
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_none());
    }

    fn establish_tcp_connection(pipeline: &mut DynPipeline<TestBuffer>) {
        // process TCP SYN packet: entries should be created in both directions
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_syn(true);

        let output = process_packet(pipeline, packet);
        assert!(!output.is_done());

        // process TCP SYN|ACK packet in reverse direction: flow entry should be found. State should become 2way
        let reply = build_reply(&output);
        let output = process_packet(pipeline, reply);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(get_flow_status(&output), Some(FlowStatus::Active));
        assert_eq!(get_pfw_flow_status(&output), Some(PortFwFlowStatus::TwoWay));

        // process TCP ACK packet in forward direction
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_ack(true);
        let output = process_packet(pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(get_flow_status(&output), Some(FlowStatus::Active));
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::Established)
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_tcp_establishment() {
        let ruleset = build_test_port_forwarding_ruleset();

        // build a pipeline with flow lookup + port forwarder
        let (_flow_table, mut pipeline, _writer) = setup_pipeline(&ruleset);

        // establish a TCP connection (port-forwarded)
        establish_tcp_connection(&mut pipeline);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_tcp_close_server() {
        let ruleset = build_test_port_forwarding_ruleset();

        // build a pipeline with flow lookup + port forwarder
        let (flow_table, mut pipeline, _writer) = setup_pipeline(&ruleset);

        // establish a TCP connection (port-forwarded)
        establish_tcp_connection(&mut pipeline);

        // process TCP FIN in reverse direction: flow entry should be found. State should become SClosing
        let mut packet = tcp_packet_reverse_reply();
        packet.try_tcp_mut().unwrap().set_fin(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(get_flow_status(&output), Some(FlowStatus::Active));
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::SClosing)
        );

        // process TCP FIN ACK packet in forward direction
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_ack(true).set_fin(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(get_flow_status(&output), Some(FlowStatus::Active));
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::LastAck)
        );

        // process TCP ACK in reverse direction: flow entry should be found. State should become Closed
        let mut packet = tcp_packet_reverse_reply();
        packet.try_tcp_mut().unwrap().set_ack(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert!(get_flow_status(&output) != Some(FlowStatus::Active)); // it may be None if the nf expiration removes it
        assert_eq!(get_pfw_flow_status(&output), Some(PortFwFlowStatus::Closed));
        println!("{flow_table}");
        assert_eq!(flow_table.len().unwrap(), 2);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_tcp_close_client() {
        let ruleset = build_test_port_forwarding_ruleset();

        // build a pipeline with flow lookup + port forwarder
        let (flow_table, mut pipeline, _writer) = setup_pipeline(&ruleset);

        // establish a TCP connection (port-forwarded)
        establish_tcp_connection(&mut pipeline);

        // process TCP FIN in reverse direction: flow entry should be found. State should become CClosing
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_fin(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::CClosing)
        );

        // process TCP FIN ACK packet in reverse direction
        let mut packet = tcp_packet_reverse_reply();
        packet.try_tcp_mut().unwrap().set_ack(true).set_fin(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::LastAck)
        );

        // process TCP ACK in forward direction: flow entry should be found. State should become Closed
        let mut packet = tcp_packet_reverse_reply();
        packet.try_tcp_mut().unwrap().set_ack(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert!(get_flow_status(&output) != Some(FlowStatus::Active)); // may be cancelled or none
        assert_eq!(get_pfw_flow_status(&output), Some(PortFwFlowStatus::Closed));
        println!("{flow_table}");
        assert_eq!(flow_table.len().unwrap(), 2);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_tcp_half_close_client() {
        let ruleset = build_test_port_forwarding_ruleset();

        // build a pipeline with flow lookup + port forwarder
        let (flow_table, mut pipeline, _writer) = setup_pipeline(&ruleset);

        // establish a TCP connection (port-forwarded)
        establish_tcp_connection(&mut pipeline);

        // process TCP FIN in forward direction: flow entry should be found. State should become CClosing
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_fin(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::CClosing)
        );

        // process TCP ACK packet in reverse direction. We assume this ACKs the FIN
        let mut packet = tcp_packet_reverse_reply();
        packet.try_tcp_mut().unwrap().set_ack(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::CHalfClose)
        );

        // process TCP FIN in reverse direction: flow entry should be found. State should become LastAck
        let mut packet = tcp_packet_reverse_reply();
        packet.try_tcp_mut().unwrap().set_fin(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::LastAck)
        );

        // process TCP ACK in forward direction: flow entry should be found. State should become Closed
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_ack(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert!(get_flow_status(&output) != Some(FlowStatus::Active)); // may be cancelled or none
        assert_eq!(get_pfw_flow_status(&output), Some(PortFwFlowStatus::Closed));
        println!("{flow_table}");
        assert_eq!(flow_table.len().unwrap(), 2);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_tcp_reset() {
        let ruleset = build_test_port_forwarding_ruleset();
        let (flow_table, mut pipeline, _writer) = setup_pipeline(&ruleset);

        // process TCP SYN packet: entries should be created in both directions
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_syn(true);
        let output = process_packet(&mut pipeline, packet);

        // process TCP SYN|ACK packet in reverse direction: flow entry should be found. State should become 2way
        let reply = build_reply(&output);
        process_packet(&mut pipeline, reply);

        // process TCP ACK packet in forward direction
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_ack(true);
        let output = process_packet(&mut pipeline, packet);
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::Established)
        );

        // process TCP RST packet in forward direction.
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_rst(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(get_flow_status(&output), Some(FlowStatus::Cancelled));
        assert_eq!(get_pfw_flow_status(&output), Some(PortFwFlowStatus::Reset));

        // the flow table still contains the two flows, although they are unusable
        assert_eq!(flow_table.len(), Some(2));
        println!("{flow_table}");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_config_removal_interrupts_traffic() {
        let ruleset = build_test_port_forwarding_ruleset();

        // build a pipeline with flow lookup + port forwarder
        let (flow_table, mut pipeline, mut writer) = setup_pipeline(&ruleset);

        // process TCP SYN packet: entries should be created in both directions
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_syn(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());

        // process TCP SYN|ACK packet in reverse direction: flow entry should be found. State should become 2way
        let mut packet = tcp_packet_reverse_reply();
        packet.try_tcp_mut().unwrap().set_syn(true).set_ack(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(get_pfw_flow_status(&output), Some(PortFwFlowStatus::TwoWay));

        // process TCP ACK packet in forward direction
        let mut packet = tcp_packet_to_port_forward();
        packet.try_tcp_mut().unwrap().set_ack(true);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::Established)
        );

        // build the same table without the TCP port-forwarding rule
        let mut ruleset = build_test_port_forwarding_ruleset();
        ruleset.remove(0);
        writer.update_table(&ruleset).unwrap();

        let packet = tcp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert_eq!(output.get_done(), Some(DoneReason::NatNotPortForwarded));

        println!("{flow_table}");

        tokio::time::sleep(Duration::from_secs(4)).await;
        let _ = pipeline.process(std::iter::empty::<Packet<TestBuffer>>());

        let packet = tcp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert_eq!(output.get_done(), Some(DoneReason::NatNotPortForwarded));
        assert_eq!(get_flow_status(&output), None); // expiration NF should have removed the flow
        assert!(get_pfw_flow_status(&output).is_none());
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
    #[tokio::test]
    async fn test_nf_port_forwarding_with_port_ranges() {
        let ruleset = build_test_port_forwarding_table_with_ranges();
        let (flow_table, mut pipeline, mut writer) = setup_pipeline(&ruleset);

        // process udp packet to be port-forwarded
        let packet = udp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());

        // send another packet to be port-forwarded: it should hit a flow
        let packet = udp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(hit_port_fw_state_valid(&output));

        // the flow table should have 2 flows
        assert_eq!(flow_table.len(), Some(2));
        println!("{flow_table}");

        // process a reply from the dest vpc. It should hit a flow
        let reply = build_reply(&output);
        let output = process_packet(&mut pipeline, reply);
        assert!(!output.is_done());
        assert!(hit_port_fw_state_valid(&output));

        // clear table: all rules will be gone
        writer.update_table(&[]).unwrap();

        // the flow table keeps the two flows, but the flows should be invalidated
        assert_eq!(flow_table.len(), Some(2));

        // process the original udp packet to be port-forwarded: it should still find a flow
        // but it should not be valid for port-forwarding.
        let packet = udp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(hit_port_fw_state_invalid(&output));

        println!("{flow_table}");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_with_prefixes_and_port_ranges() {
        let ruleset = build_test_port_forwarding_table_with_prefixes_and_port_ranges();
        let (flow_table, mut pipeline, mut writer) = setup_pipeline(&ruleset);

        // process udp packet to be port-forwarded
        let packet = udp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());

        // send another packet to be port-forwarded: it should hit a flow
        let packet = udp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(hit_port_fw_state_valid(&output));

        // the flow table should have 2 flows
        assert_eq!(flow_table.len(), Some(2));
        println!("{flow_table}");

        // process a reply from the dest vpc. It should hit a flow
        let reply = build_reply(&output);
        let output = process_packet(&mut pipeline, reply);
        assert!(!output.is_done());
        assert!(hit_port_fw_state_valid(&output));

        // clear table: all rules will be gone
        writer.update_table(&[]).unwrap();

        // the flow table keeps the two flows, but the flows should be invalidated
        assert_eq!(flow_table.len(), Some(2));

        // process the original udp packet to be port-forwarded: it should still find a flow
        // but it should not be valid for port-forwarding.
        let packet = udp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(hit_port_fw_state_invalid(&output));

        println!("{flow_table}");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_compatible_rule_updates_preserves_flows() {
        // check that, when updating a rule, existing flows remain if the new rule would allow them

        // build rule
        let entry = PortFwEntry::new(
            PortFwKey::new(
                VpcDiscriminant::VNI(2000.try_into().unwrap()),
                NextHeader::TCP,
            ),
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.0/24").unwrap(),
            Prefix::from_str("192.168.1.0/24").unwrap(),
            (3010, 3050),
            (10, 50),
            None,
            None,
        )
        .unwrap();

        // create pipeline with port-forwarder
        let (flow_table, mut pipeline, mut writer) = setup_pipeline(&[entry]);

        // establish a TCP connection (port-forwarded). This should succeed and 2 flows be created
        establish_tcp_connection(&mut pipeline);
        assert_eq!(flow_table.len(), Some(2));

        // update the rule to include the previous one
        let entry = PortFwEntry::new(
            PortFwKey::new(
                VpcDiscriminant::VNI(2000.try_into().unwrap()),
                NextHeader::TCP,
            ),
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.73/32").unwrap(),
            (3022, 3023),
            (22, 23),
            None,
            None,
        )
        .unwrap();
        writer.update_table(std::slice::from_ref(&entry)).unwrap();

        // send a new packet in forward path. Flow entry remains Active and flow status is still Established
        let packet = tcp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(get_flow_status(&output), Some(FlowStatus::Active));
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::Established)
        );
        let rule_referenced = get_pfw_flow_state_rule(&output);
        assert_eq!(rule_referenced.as_ref().unwrap().as_ref(), &entry);

        println!("{flow_table}");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_nf_port_forwarding_incompatible_rule_updates_remove_flows() {
        // check that, when updating a rule, existing flows remain if the new rule would allow them

        // build rule
        let entry = PortFwEntry::new(
            PortFwKey::new(
                VpcDiscriminant::VNI(2000.try_into().unwrap()),
                NextHeader::TCP,
            ),
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.0/24").unwrap(),
            Prefix::from_str("192.168.1.0/24").unwrap(),
            (3010, 3050),
            (10, 50),
            None,
            None,
        )
        .unwrap();

        // create pipeline with port-forwarder
        let (flow_table, mut pipeline, mut writer) = setup_pipeline(&[entry]);

        // establish a TCP connection (port-forwarded). This should succeed and 2 flows be created
        establish_tcp_connection(&mut pipeline);
        assert_eq!(flow_table.len(), Some(2));

        // update the rule so that the traffic would be sent somewhere else
        let entry = PortFwEntry::new(
            PortFwKey::new(
                VpcDiscriminant::VNI(2000.try_into().unwrap()),
                NextHeader::TCP,
            ),
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.0/24").unwrap(),
            Prefix::from_str("192.168.2.0/24").unwrap(),
            (3010, 3050),
            (10, 50),
            None,
            None,
        )
        .unwrap();
        writer.update_table(std::slice::from_ref(&entry)).unwrap();

        // send a new packet in forward path. Flow entry should be invalidated and the packet dropped
        let packet = tcp_packet_to_port_forward();
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_some());
        assert_eq!(get_flow_status(&output), Some(FlowStatus::Cancelled)); // flow should be cancelled
        assert_eq!(
            get_pfw_flow_status(&output),
            Some(PortFwFlowStatus::Established) // this remains established. That's fine.
        );
        let rule_referenced = get_pfw_flow_state_rule(&output);
        assert!(rule_referenced.is_none()); // flow did not get a new reference to a rule
        assert_eq!(output.get_done(), Some(DoneReason::NatNotPortForwarded)); // packet was dropped

        println!("{flow_table}");
    }
}
