// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tracking of flows that neither masquerade nor port forwarding track, for the ACL stage.

mod flow_data;

pub(crate) use flow_data::TrackedFlowData;

use tracectl::trace_target;
trace_target!("flow-tracker", LevelFilter::INFO, &["nat", "pipeline"]);

use crate::common::TIMEOUT_SCALE;
use crate::nat_flows::{HalfFlow, InstallError, NatData, NewFlow, install_pair};
use concurrency::sync::Arc;
use flow_entry::flow_table::table::FlowTable;
use net::buffer::PacketBufferMut;
use net::flow_key::IcmpProtoKey;
use net::flows::FlowInfo;
use net::flows::conn_tracking::{ConnState, advance_flow, transport_proto};
use net::headers::TryTcp;
use net::ip::NextHeader;
use net::packet::Packet;
use net::tcp::Tcp;
use net::{FlowKey, IpProtoKey};
use pipeline::{NetworkFunction, PipelineData};
use std::time::Duration;

#[allow(unused)]
use tracing::{debug, warn};

// Same defaults as for port forwarding: there is no pool of ports to preserve.
const INITIAL_TIMEOUT: Duration = Duration::from_secs(10 * TIMEOUT_SCALE);
const ESTABLISHED_TIMEOUT_TCP: Duration = Duration::from_secs(30 * 60 * TIMEOUT_SCALE);
const ESTABLISHED_TIMEOUT_OTHER: Duration = Duration::from_secs(30 * TIMEOUT_SCALE);

/// Tell if the flow of a packet needs tracking, and if neither masquerade nor port forwarding
/// tracks it.
pub(crate) fn needs_tracking<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    let meta = packet.meta();
    !packet.is_done()
        && meta.is_overlay()
        && meta.has_forced_flow_tracking()
        // Masquerade and port forwarding track their own flows
        && !meta.requires_masquerade()
        && !meta.requires_port_forwarding()
        && !packet.is_icmp_error()
}

// Only open flows for packets that can start a connection: not for TCP segments without SYN,
// nor for non-first fragments or for packets with no transport header we can resolve.
fn can_open_flow<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    match transport_proto(packet) {
        Some(NextHeader::TCP) => packet.try_tcp().is_some_and(Tcp::is_first_segment),
        Some(NextHeader::UDP | NextHeader::ICMP | NextHeader::ICMP6) => true,
        _ => false,
    }
}

/// Create a pair of tracked flows for `packet`, with `state` in both flows, if the packet can
/// open a connection.
///
/// `initial_key` is the key of the packet before any translation: the next packets of the
/// connection hit the flow table with this key. Replies carry the current headers of the packet,
/// after translation, reversed.
pub(crate) fn track_new_flow<Buf: PacketBufferMut, S: NatData>(
    nfi: &str,
    flow_table: &FlowTable,
    packet: &Packet<Buf>,
    initial_key: FlowKey,
    state: impl Fn() -> S,
    genid: i64,
) {
    if !can_open_flow(packet) {
        return;
    }
    let meta = packet.meta();
    let (Some(src_vpcd), Some(dst_vpcd)) = (meta.src_vpcd, meta.dst_vpcd) else {
        debug!("{nfi}: Packet lacks a VPC discriminant, not tracking its flow");
        return;
    };
    let Ok(current_key) = FlowKey::try_from(packet) else {
        debug!("{nfi}: Packet has no flow key, not tracking its flow");
        return;
    };
    if let IpProtoKey::Icmp(icmp) = current_key.proto_key_info()
        && !matches!(icmp, IcmpProtoKey::QueryMsgData(_))
    {
        debug!("{nfi}: ICMP message is not a query, not tracking its flow");
        return;
    }

    let forward = HalfFlow {
        key: initial_key,
        state: state(),
        dst_vpcd,
    };
    let reverse = HalfFlow {
        key: current_key.reverse(Some(dst_vpcd)),
        state: state(),
        dst_vpcd: src_vpcd,
    };

    // Stamp with the generation being installed, which may not yet be published.
    let admit = || Some(genid);
    match install_pair(flow_table, meta, INITIAL_TIMEOUT, forward, reverse, admit) {
        Ok(NewFlow::Installed(flow)) => debug!("{nfi}: Tracking new flow {}", flow.flowkey()),
        Ok(NewFlow::Held(_)) => {}
        // Processing this packet does not depend on the flow: let it through untracked
        Err(e @ InstallError::CapacityExceeded) => {
            warn!("{nfi}: Cannot track flow {initial_key}: {e}");
        }
        Err(e) => debug!("{nfi}: Cannot track flow {initial_key}: {e}"),
    }
}

/// Update the status of a tracked flow after a packet hit it, and extend its lifetime or
/// invalidate it.
pub(crate) fn refresh_tracked_flow<Buf: PacketBufferMut>(packet: &Packet<Buf>, flow: &FlowInfo) {
    advance_flow(packet, flow, |status| match status {
        ConnState::Established => match transport_proto(packet) {
            Some(NextHeader::TCP) => Some(ESTABLISHED_TIMEOUT_TCP),
            _ => Some(ESTABLISHED_TIMEOUT_OTHER),
        },
        _ => Some(INITIAL_TIMEOUT),
    });
}

/// A network function that creates pairs of flows in the flow table for packets that require
/// tracking, for traffic without NAT. Masquerade, port forwarding and static NAT track the flows of
/// their own traffic.
pub struct FlowTracker {
    name: String,
    flow_table: Arc<FlowTable>,
    pipeline_data: Arc<PipelineData>,
}

impl FlowTracker {
    /// Creates a new [`FlowTracker`].
    #[must_use]
    pub fn new(name: &str, flow_table: Arc<FlowTable>) -> Self {
        Self {
            name: name.to_string(),
            flow_table,
            pipeline_data: Arc::from(PipelineData::default()),
        }
    }

    fn process_packet<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) {
        if let Some(flow) = packet.meta().flow_info.as_ref()
            && flow.is_active()
        {
            if TrackedFlowData::try_get(&flow.locked.read()).is_some() {
                refresh_tracked_flow(packet, flow);
            }
            return;
        }
        let Ok(key) = FlowKey::try_from(packet) else {
            debug!(
                "{}: Packet has no flow key, not tracking its flow",
                self.name
            );
            return;
        };
        let genid = self.pipeline_data.staging_genid();
        track_new_flow(
            &self.name,
            &self.flow_table,
            packet,
            key,
            || TrackedFlowData,
            genid,
        );
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowTracker {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        for packet in burst.iter() {
            // The static NAT stage tracks the flows of static NAT traffic
            if needs_tracking(packet) && !packet.meta().requires_static_nat() {
                self.process_packet(packet);
            }
        }
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

#[cfg(test)]
mod test {
    use super::{FlowTracker, TrackedFlowData};
    use crate::nat_flows::NatData;
    use crate::static_nat::probe::build;
    use concurrency::sync::Arc;
    use flow_entry::flow_table::table::FlowTable;
    use net::FlowKey;
    use net::buffer::TestBuffer;
    use net::flows::FlowInfo;
    use net::flows::conn_tracking::{AtomicConnState, ConnState, FlowSide};
    use net::headers::TryTcpMut;
    use net::packet::{Packet, VpcDiscriminant};
    use net::vxlan::Vni;
    use pipeline::NetworkFunction;
    use std::net::IpAddr;

    fn vpcd(id: u32) -> VpcDiscriminant {
        VpcDiscriminant::from_vni(Vni::new_checked(id).unwrap_or_else(|_| unreachable!()))
    }

    fn addr(raw: &str) -> IpAddr {
        raw.parse().unwrap_or_else(|_| unreachable!())
    }

    /// A TCP SYN from vpc 100 to vpc 200, flagged for flow tracking.
    fn syn(src: &str, dst: &str) -> Packet<TestBuffer> {
        let mut packet = build(addr(src), addr(dst), true, 1234, 80);
        let meta = packet.meta_mut();
        meta.set_overlay(true);
        meta.src_vpcd = Some(vpcd(100));
        meta.dst_vpcd = Some(vpcd(200));
        meta.set_forced_flow_tracking(true);
        packet
    }

    fn run(tracker: &mut FlowTracker, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        tracker
            .process(std::iter::once(packet))
            .next()
            .unwrap_or_else(|| unreachable!("the tracker never drops packets"))
    }

    fn side_of(flow: &FlowInfo) -> Option<FlowSide> {
        TrackedFlowData::try_get(&flow.locked.read())?;
        Some(FlowSide::from(flow.get_flags()))
    }

    #[tokio::test]
    async fn a_new_connection_gets_a_tracked_flow_pair() {
        let table = Arc::new(FlowTable::default());
        let mut tracker = FlowTracker::new("tracker", table.clone());
        let packet = syn("10.0.0.5", "20.0.0.5");
        let key = FlowKey::try_from(&packet).unwrap_or_else(|_| unreachable!());

        let out = run(&mut tracker, packet);
        assert!(!out.is_done(), "{:?}", out.get_done());

        let forward = table
            .lookup(&key)
            .unwrap_or_else(|| unreachable!("the connection got no forward flow"));
        let reverse = table
            .lookup(&key.reverse(Some(vpcd(200))))
            .unwrap_or_else(|| unreachable!("the connection got no reverse flow"));
        assert!(forward.is_active() && reverse.is_active());
        assert_eq!(side_of(&forward), Some(FlowSide::Initiator));
        assert_eq!(side_of(&reverse), Some(FlowSide::Responder));
        assert_eq!(forward.get_dst_vpcd(), Some(vpcd(200)));
        assert_eq!(reverse.get_dst_vpcd(), Some(vpcd(100)));
    }

    #[tokio::test]
    async fn a_tcp_segment_without_syn_opens_no_flow() {
        let table = Arc::new(FlowTable::default());
        let mut tracker = FlowTracker::new("tracker", table.clone());
        let mut packet = syn("10.0.0.5", "20.0.0.5");
        let tcp = packet.try_tcp_mut().unwrap_or_else(|| unreachable!());
        tcp.set_syn(false);
        tcp.set_ack(true);
        let key = FlowKey::try_from(&packet).unwrap_or_else(|_| unreachable!());

        let out = run(&mut tracker, packet);
        assert!(!out.is_done(), "{:?}", out.get_done());
        assert!(table.lookup(&key).is_none());
    }

    #[tokio::test]
    async fn masqueraded_packets_are_left_to_masquerade() {
        let table = Arc::new(FlowTable::default());
        let mut tracker = FlowTracker::new("tracker", table.clone());
        let mut packet = syn("10.0.0.5", "20.0.0.5");
        packet.meta_mut().set_masquerade(true);
        let key = FlowKey::try_from(&packet).unwrap_or_else(|_| unreachable!());

        let out = run(&mut tracker, packet);
        assert!(!out.is_done(), "{:?}", out.get_done());
        assert!(table.lookup(&key).is_none());
    }

    #[tokio::test]
    async fn static_nat_packets_are_left_to_static_nat() {
        let table = Arc::new(FlowTable::default());
        let mut tracker = FlowTracker::new("tracker", table.clone());
        let mut packet = syn("10.0.0.5", "20.0.0.5");
        packet.meta_mut().set_static_nat_src(true);
        let key = FlowKey::try_from(&packet).unwrap_or_else(|_| unreachable!());

        let out = run(&mut tracker, packet);
        assert!(!out.is_done(), "{:?}", out.get_done());
        assert!(table.lookup(&key).is_none());
    }

    /// Hit the flow for `key`, as the flow lookup stage does.
    fn hitting(mut packet: Packet<TestBuffer>, table: &FlowTable) -> Packet<TestBuffer> {
        let key = FlowKey::try_from(&packet).unwrap_or_else(|_| unreachable!());
        packet.meta_mut().flow_info = table.lookup(&key);
        assert!(packet.meta().flow_info.is_some(), "no flow for {key}");
        packet
    }

    /// The reply to `syn`, from vpc 200 to vpc 100.
    fn reply(src: &str, dst: &str) -> Packet<TestBuffer> {
        let mut packet = build(addr(src), addr(dst), true, 80, 1234);
        let meta = packet.meta_mut();
        meta.set_overlay(true);
        meta.src_vpcd = Some(vpcd(200));
        meta.dst_vpcd = Some(vpcd(100));
        meta.set_forced_flow_tracking(true);
        packet
    }

    #[tokio::test]
    async fn a_reply_moves_the_status_of_the_pair() {
        let table = Arc::new(FlowTable::default());
        let mut tracker = FlowTracker::new("tracker", table.clone());
        let packet = syn("10.0.0.5", "20.0.0.5");
        let key = FlowKey::try_from(&packet).unwrap_or_else(|_| unreachable!());
        run(&mut tracker, packet);

        let mut syn_ack = reply("20.0.0.5", "10.0.0.5");
        let tcp = syn_ack.try_tcp_mut().unwrap_or_else(|| unreachable!());
        tcp.set_ack(true);
        let out = run(&mut tracker, hitting(syn_ack, &table));
        assert!(!out.is_done(), "{:?}", out.get_done());

        let forward = table.lookup(&key).unwrap_or_else(|| unreachable!());
        let status = forward.conn_state().map(AtomicConnState::load);
        assert_eq!(status, Some(ConnState::TwoWay));
    }

    #[tokio::test]
    async fn a_reset_ends_the_tracking_of_the_pair() {
        let table = Arc::new(FlowTable::default());
        let mut tracker = FlowTracker::new("tracker", table.clone());
        let packet = syn("10.0.0.5", "20.0.0.5");
        let key = FlowKey::try_from(&packet).unwrap_or_else(|_| unreachable!());
        run(&mut tracker, packet);
        let forward = table.lookup(&key).unwrap_or_else(|| unreachable!());

        let mut rst = reply("20.0.0.5", "10.0.0.5");
        let tcp = rst.try_tcp_mut().unwrap_or_else(|| unreachable!());
        tcp.set_syn(false);
        tcp.set_rst(true);
        let out = run(&mut tracker, hitting(rst, &table));
        assert!(!out.is_done(), "{:?}", out.get_done());
        assert!(!forward.is_active(), "a reset connection is still tracked");
    }
}
