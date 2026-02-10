// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod nf_test {
    use crate::portfw::{PortForwarder, PortFwEntry, PortFwKey, PortFwTable, PortFwTableRw};
    use flow_entry::flow_table::FlowLookup;
    use flow_entry::flow_table::FlowTable;
    use flow_info::FlowStatus;
    use net::buffer::TestBuffer;
    use net::ip::NextHeader;
    use net::ip::UnicastIpAddr;
    use net::packet::test_utils::build_test_udp_ipv4_packet;
    use net::packet::{Packet, VpcDiscriminant};
    use std::net::IpAddr;

    use pipeline::{DynPipeline, NetworkFunction};
    use std::num::NonZero;
    use std::str::FromStr;
    use std::sync::Arc;
    use tracing_test::traced_test;

    // build a sample port forwarding table
    fn build_test_port_forwarding_table() -> Arc<PortFwTable> {
        let mut fwtable = PortFwTable::new();
        let key = PortFwKey::new(
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            NextHeader::TCP,
            NonZero::new(3022).unwrap(),
        );
        let entry = PortFwEntry::new(
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            22,
            None,
            None,
        )
        .unwrap();
        fwtable.add_entry(key, entry).unwrap();

        let key = PortFwKey::new(
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            NextHeader::UDP,
            NonZero::new(3053).unwrap(),
        );
        let entry = PortFwEntry::new(
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.2").unwrap(),
            53,
            None,
            None,
        )
        .unwrap();
        fwtable.add_entry(key, entry).unwrap();

        Arc::new(fwtable)
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

    #[traced_test]
    #[test]
    fn test_nf_port_forwarding() {
        // build a pipeline with flow lookup + port forwarder
        let fwtablerw = PortFwTableRw::new();
        let flow_table = Arc::new(FlowTable::new(1024));
        let flow_lookup_nf = FlowLookup::new("flow-lookup", flow_table.clone());
        let nf = PortForwarder::new("port-forwarder", fwtablerw.clone(), flow_table.clone());
        let mut pipeline: DynPipeline<TestBuffer> =
            DynPipeline::new().add_stage(flow_lookup_nf).add_stage(nf);

        // set port-forwarding rules
        fwtablerw.update(build_test_port_forwarding_table());
        println!("{fwtablerw}");

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

        let flow_info = output.meta().flow_info.as_ref().unwrap();
        assert_eq!(flow_info.status(), FlowStatus::Active);
        let expires_in = flow_info
            .expires_at()
            .saturating_duration_since(std::time::Instant::now())
            .as_secs();
        assert!(expires_in > PortFwEntry::ESTABLISHED_TIMEOUT.as_secs() - 5);

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
}
