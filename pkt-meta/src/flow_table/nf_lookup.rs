// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network Function specific flow table.

use tracing::debug;

use concurrency::sync::Arc;
use flow_info::ExtractRef;
use net::buffer::PacketBufferMut;
use net::packet::{Packet, VpcDiscriminant};
use pipeline::NetworkFunction;

use crate::flow_table::{FlowKey, FlowTable};

pub struct LookupNF {
    flow_table: Arc<FlowTable>,
}

impl LookupNF {
    pub fn new(flow_table: Arc<FlowTable>) -> Self {
        Self { flow_table }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for LookupNF {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(move |mut packet| {
            let flow_key = FlowKey::try_from(crate::flow_table::flow_key::Uni(&packet)).ok();
            let Some(flow_key) = flow_key else {
                return packet.enforce();
            };
            if let Some(flow_info) = self.flow_table.lookup(&flow_key) {
                debug!(
                    "LookupNF: Tagging packet with flow info for flow key {:?}",
                    flow_key
                );
                if let Some(dst_vpc_info) = flow_info.locked.read().unwrap().dst_vpc_info.as_ref() {
                    let dst_vpcd = dst_vpc_info.extract_ref::<VpcDiscriminant>();
                    if let Some(dst_vpcd) = dst_vpcd {
                        debug!(
                            "LookupNF: Tagging packet with dst_vpcd from flow info {:?}, old dst_vpcd {:?}",
                            dst_vpcd, packet.meta.dst_vpcd
                        );
                        packet.meta.dst_vpcd = Some(*dst_vpcd);
                    }
                }
                packet.meta.flow_info = Some(flow_info);
            }
            packet.enforce()
        })
    }
}

#[cfg(test)]
mod test {
    use flow_info::FlowInfo;
    use net::ip::NextHeader;
    use net::ip::UnicastIpAddr;
    use net::packet::VpcDiscriminant;
    use net::packet::test_utils::build_test_ipv4_packet_with_transport;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;
    use pipeline::NetworkFunction;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::flow_table::FlowKey;
    use crate::flow_table::FlowTable;
    use crate::flow_table::nf_lookup::LookupNF;

    #[test]
    fn test_lookup_nf() {
        let flow_table = Arc::new(FlowTable::default());
        let mut lookup_nf = LookupNF::new(flow_table.clone());
        let src_vpcd = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let dst_vpcd = VpcDiscriminant::VNI(Vni::new_checked(200).unwrap());
        let src_ip = "1.2.3.4".parse::<UnicastIpAddr>().unwrap();
        let dst_ip = "5.6.7.8".parse::<IpAddr>().unwrap();
        let src_port = TcpPort::new_checked(1025).unwrap();
        let dst_port = TcpPort::new_checked(2048).unwrap();

        // Create a packet with the right info
        let mut packet = build_test_ipv4_packet_with_transport(100, Some(NextHeader::TCP)).unwrap();
        packet.meta.src_vpcd = Some(src_vpcd);
        packet.set_ip_source(src_ip).unwrap();
        packet.set_ip_destination(dst_ip).unwrap();
        packet.set_tcp_source_port(src_port).unwrap();
        packet.set_tcp_destination_port(dst_port).unwrap();

        // Insert matching flow entry
        let flow_key = FlowKey::try_from(crate::flow_table::flow_key::Uni(&packet)).unwrap();
        let flow_info = FlowInfo::new(Instant::now() + Duration::from_secs(10));
        flow_info.locked.write().unwrap().dst_vpc_info = Some(Box::new(dst_vpcd));
        flow_table.insert(flow_key, flow_info);

        // Ensure packet is tagged
        let mut output_iter = lookup_nf.process(std::iter::once(packet));
        let output = output_iter.next().unwrap();
        assert!(output.meta.flow_info.is_some());
        assert_eq!(output.meta.dst_vpcd, Some(dst_vpcd));
    }
}
