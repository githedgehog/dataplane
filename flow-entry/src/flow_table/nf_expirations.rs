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
    use net::buffer::TestBuffer;
    use net::ip::UnicastIpAddr;
    use net::packet::Packet;
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;
    use pipeline::NetworkFunction;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::flow_table::FlowTable;
    use crate::flow_table::nf_expirations::ExpirationsNF;
    use crate::flow_table::thread_local_pq::AGRESSIVE_REAP_THRESHOLD;
    use net::{FlowKey, IpProtoKey, TcpProtoKey};

    #[test]
    fn test_expirations_nf() {
        let flow_table = Arc::new(FlowTable::default());
        let mut expirations_nf = ExpirationsNF::new(flow_table.clone());
        let src_vpcd = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let src_ip = "1.2.3.4".parse::<UnicastIpAddr>().unwrap();
        let dst_ip = "5.6.7.8".parse::<IpAddr>().unwrap();
        let src_port = TcpPort::new_checked(1025).unwrap();
        let dst_port = TcpPort::new_checked(2048).unwrap();

        let flow_key = FlowKey::uni(
            Some(src_vpcd),
            src_ip.into(),
            dst_ip,
            IpProtoKey::Tcp(TcpProtoKey { src_port, dst_port }),
        );

        // Insert an already expired flow entry and check that entry is there by looking it up
        let flow_info = FlowInfo::new(Instant::now().checked_sub(Duration::from_secs(10)).unwrap());
        flow_table.insert(flow_key, flow_info);
        assert!(flow_table.lookup(&flow_key).is_some());

        // call process() on the NF (no packet is actually needed). NF should expire entry
        let _output_iter = expirations_nf.process(std::iter::empty::<Packet<TestBuffer>>());
        assert!(flow_table.lookup(&flow_key).is_none());
    }

    #[test]
    fn test_aggressive_expiration() {
        let flow_table = Arc::new(FlowTable::default());
        let mut expirations_nf = ExpirationsNF::new(flow_table.clone());
        let src_vpcd = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let src_ip = "1.2.3.4".parse::<UnicastIpAddr>().unwrap();
        let dst_ip = "5.6.7.8".parse::<IpAddr>().unwrap();

        // create > AGRESSIVE_REAP_THRESHOLD flows
        for src_port in 1..u16::MAX {
            let src_port = TcpPort::new_checked(src_port).unwrap();
            for dst_port in
                1..=u16::try_from(AGRESSIVE_REAP_THRESHOLD.div_ceil(u16::MAX as usize)).unwrap()
            {
                let dst_port = TcpPort::new_checked(dst_port).unwrap();
                let flow_key = FlowKey::uni(
                    Some(src_vpcd),
                    src_ip.into(),
                    dst_ip,
                    IpProtoKey::Tcp(TcpProtoKey { src_port, dst_port }),
                );
                let flow_info =
                    FlowInfo::new(Instant::now().checked_add(Duration::from_mins(10)).unwrap());
                flow_table.insert(flow_key, flow_info);
            }
        }
        // check we inserted more flows than the threshold
        assert!(flow_table.len().unwrap() > AGRESSIVE_REAP_THRESHOLD);

        // expire: no flow should be reaped because all are Active
        let _: Vec<_> = expirations_nf
            .process(std::iter::empty::<Packet<TestBuffer>>())
            .collect();
        assert!(flow_table.len().unwrap() > AGRESSIVE_REAP_THRESHOLD);

        // pretend that all flows -but one- get Cancelled
        for (num, flow_info) in flow_table.table.read().unwrap().iter().enumerate() {
            if num != 13 {
                flow_info
                    .upgrade()
                    .unwrap()
                    .update_status(flow_info::FlowStatus::Cancelled);
            }
        }

        // reap again, only one flow should be there
        let _: Vec<_> = expirations_nf
            .process(std::iter::empty::<Packet<TestBuffer>>())
            .collect();
        assert_eq!(flow_table.len().unwrap(), 1);
    }
}
