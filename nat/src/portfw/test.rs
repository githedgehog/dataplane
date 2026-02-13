// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod nf_test {
    use crate::portfw::flow_state::{PortFwFlowStatus, get_portfw_state_flow_status};
    use crate::portfw::{PortForwarder, PortFwEntry, PortFwKey, PortFwTableWriter};

    use flow_entry::flow_table::{ExpirationsNF, FlowLookup, FlowTable};
    use flow_info::FlowStatus;
    use net::buffer::TestBuffer;
    use net::headers::TryTcpMut;
    use net::ip::NextHeader;
    use net::ip::UnicastIpAddr;
    use net::packet::DoneReason;
    use net::packet::test_utils::{build_test_tcp_ipv4_packet, build_test_udp_ipv4_packet};
    use net::packet::{Packet, VpcDiscriminant};
    use std::net::IpAddr;

    use pipeline::{DynPipeline, NetworkFunction};
    use std::num::NonZero;
    use std::str::FromStr;
    use std::sync::Arc;
    use tracing_test::traced_test;

    // build a sample port forwarding table
    fn build_test_port_forwarding_table() -> Vec<PortFwEntry> {
        let mut ruleset = vec![];
        let key = PortFwKey::new(
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            NextHeader::TCP,
            NonZero::new(3022).unwrap(),
        );
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            22,
            None,
            None,
        )
        .unwrap();
        ruleset.push(entry);

        let key = PortFwKey::new(
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            NextHeader::UDP,
            NonZero::new(3053).unwrap(),
        );
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.2").unwrap(),
            53,
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
        packet
    }

    // build reply packet to the port forwarded packet
    fn udp_packet_reverse_reply() -> Packet<TestBuffer> {
        let mut packet: Packet<TestBuffer> =
            build_test_udp_ipv4_packet("192.168.1.2", "10.0.0.1", 53, 9876);
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(3000.try_into().unwrap()));
        //packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(2000.try_into().unwrap()));
        //N.B: we assume dst_vpcd is not known atm
        packet
    }

    fn tcp_packet_to_port_forward() -> Packet<TestBuffer> {
        let mut packet = build_test_tcp_ipv4_packet("10.0.0.2", "70.71.72.73", 7777, 3022);
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(2000.try_into().unwrap()));
        packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(3000.try_into().unwrap()));
        packet
    }

    fn tcp_packet_reverse_reply() -> Packet<TestBuffer> {
        let mut packet = build_test_tcp_ipv4_packet("192.168.1.1", "10.0.0.2", 22, 7777);
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(3000.try_into().unwrap()));
        packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(2000.try_into().unwrap()));
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

    /// sets up a port-forwarding pipeline with a sample configuration
    fn setup_pipeline() -> (Arc<FlowTable>, DynPipeline<TestBuffer>, PortFwTableWriter) {
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
        writer
            .update_table(build_test_port_forwarding_table().as_slice())
            .unwrap();
        if let Some(table) = writer.enter() {
            println!("{}", table.as_ref());
        }
        (flow_table, pipeline, writer)
    }

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding() {
        // build a pipeline with flow lookup + port forwarder
        let (_flow_table, mut pipeline, _writer) = setup_pipeline();

        // process an overlay packet matching a port-forwarding rule
        let output = process_packet(&mut pipeline, udp_packet_to_port_forward());
        assert_eq!(output.ip_source().unwrap().to_string(), "10.0.0.1");
        assert_eq!(output.ip_destination().unwrap().to_string(), "192.168.1.2");
        assert_eq!(output.udp_source_port().unwrap().as_u16(), 9876);
        assert_eq!(output.udp_destination_port().unwrap().as_u16(), 53);
        assert!(output.meta().flow_info.is_none());

        // process a packet in the reverse direction
        let output = process_packet(&mut pipeline, udp_packet_reverse_reply());
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
        // build a pipeline with flow lookup + port forwarder
        let (_, mut pipeline, _writer) = setup_pipeline();

        // process packet with TCP segment without SYN: no entry should be created and packet be dropped
        let mut packet = tcp_packet_to_port_forward();
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_syn(false);
        let output = process_packet(&mut pipeline, packet);
        assert_eq!(output.get_done(), Some(DoneReason::Filtered));

        // process packet in reverse direction: no flow info should have been found
        let packet = tcp_packet_reverse_reply();
        let output = process_packet(&mut pipeline, packet);
        assert!(output.meta().flow_info.is_none());
    }

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding_tcp_success() {
        // build a pipeline with flow lookup + port forwarder
        let (flow_table, mut pipeline, _writer) = setup_pipeline();

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

        // process TCP RST packet in forward direction. This would normally not
        // be processed, but we we'll let it through
        let mut packet = tcp_packet_to_port_forward();
        packet.meta_mut().dst_vpcd.take(); // FIXME when flow-filter fixed
        let tcp = packet.try_tcp_mut().unwrap();
        tcp.set_rst(true);
        tcp.set_syn(false);
        let output = process_packet(&mut pipeline, packet);
        assert!(!output.is_done());
        assert_eq!(
            get_portfw_state_flow_status(&output),
            Some(PortFwFlowStatus::Reset)
        );

        println!("{flow_table}");
    }
}
