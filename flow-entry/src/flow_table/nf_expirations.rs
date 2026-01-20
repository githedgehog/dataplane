// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network Function specific flow table.

use concurrency::sync::Arc;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::NetworkFunction;

use crate::flow_table::FlowTable;

use tracectl::trace_target;
trace_target!("flow-expiration", LevelFilter::INFO, &["pipeline"]);

/// Network Function that reap expired entries from the flow table for the current thread.
///
/// Note: This only reaps expired entries on the priority queue for the current thread.
/// It does not reap expired entries on other threads.
///
/// This stage should be run after all other pipeline stages to reap any expired entries.
pub struct ExpirationsNF {
    flow_table: Arc<FlowTable>,
}

impl ExpirationsNF {
    pub fn new(flow_table: Arc<FlowTable>) -> Self {
        Self { flow_table }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for ExpirationsNF {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        self.flow_table.reap_expired();
        input
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
    use crate::flow_table::nf_expirations::ExpirationsNF;
    use crate::flow_table::{FlowTable, IpProtoKey, TcpProtoKey};

    #[test]
    fn test_expirations_nf() {
        let flow_table = Arc::new(FlowTable::default());
        let mut expirations_nf = ExpirationsNF::new(flow_table.clone());
        let src_vpcd = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let dst_vpcd = VpcDiscriminant::VNI(Vni::new_checked(200).unwrap());
        let src_ip = "1.2.3.4".parse::<UnicastIpAddr>().unwrap();
        let dst_ip = "5.6.7.8".parse::<IpAddr>().unwrap();
        let src_port = TcpPort::new_checked(1025).unwrap();
        let dst_port = TcpPort::new_checked(2048).unwrap();

        let flow_key = FlowKey::uni(
            Some(src_vpcd),
            src_ip.into(),
            Some(dst_vpcd),
            dst_ip,
            IpProtoKey::Tcp(TcpProtoKey { src_port, dst_port }),
        );

        // Create a dummy packet
        let packet = build_test_ipv4_packet_with_transport(100, Some(NextHeader::TCP)).unwrap();

        // Insert expired flow entry
        let flow_info = FlowInfo::new(Instant::now().checked_sub(Duration::from_secs(10)).unwrap());
        flow_table.insert(flow_key, flow_info);

        let output_iter = expirations_nf.process(std::iter::once(packet));
        assert_eq!(output_iter.count(), 1);

        assert!(flow_table.lookup(&flow_key).is_none());
    }
}
