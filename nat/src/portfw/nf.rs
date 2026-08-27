// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding stage

use crate::portfw::{PortFwEntry, PortFwKey, PortFwState, PortFwTable, PortFwTableReader};
use concurrency::sync::{Arc, Weak};
use flow_entry::flow_table::table::{FlowTable, Insertion};

use net::buffer::PacketBufferMut;
use net::flows::{ExtractMut, ExtractRef, FlowInfo};
use net::headers::{Transport, TryHeaders, TryIp};
use net::ip::UnicastIpAddr;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::{NetworkFunction, PipelineData};
use std::num::NonZero;

use crate::common::NatAction;
use crate::portfw::flow_state::build_portfw_flow_keys;
use crate::portfw::flow_state::get_packet_port_fw_state;
use crate::portfw::flow_state::refresh_port_fw_entry;
use crate::portfw::flow_state::setup_forward_flow;
use crate::portfw::flow_state::setup_reverse_flow;
use crate::portfw::packet::nat_packet;

#[allow(unused)]
use tracing::{debug, error, trace, warn};

/// A port-forwarding network function
pub struct PortForwarder {
    name: String,
    flow_table: Arc<FlowTable>,
    fwtable: PortFwTableReader,
    pipeline_data: Arc<PipelineData>,
}

impl PortForwarder {
    /// Creates a new [`PortForwarder`]
    #[must_use]
    pub fn new(name: &str, fwtable: PortFwTableReader, flow_table: Arc<FlowTable>) -> Self {
        Self {
            name: name.to_string(),
            flow_table,
            fwtable,
            pipeline_data: Arc::from(PipelineData::default()),
        }
    }

    /// Tell if a packet can be port-forwarded. For that to happen, a packet must be
    /// unicast Ipv4 or IPv6 and carry UDP/TCP payload. In case of TCP, it must be the first segment.
    /// If a packet can be port-forwarded, a `PortFwKey` is returned, along with the
    /// destination address and port.
    fn can_be_port_forwarded<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
    ) -> Option<(PortFwKey, UnicastIpAddr, NonZero<u16>)> {
        debug!("checking packet for port-forwarding ...");

        let Some(src_vpcd) = packet.meta().src_vpcd else {
            error!("packet lacks src vpc annotation: will drop");
            packet.done(DoneReason::InternalFailure);
            return None;
        };

        if let Some((dst_ip, dst_port, proto)) =
            match packet.headers().pat().eth().net().transport().done() {
                Some((_, _net, Transport::Tcp(tcp))) if !tcp.is_first_segment() => {
                    debug!("Ignoring TCP packet: it has no SYN and we have no state for it");
                    None
                }
                Some((_, net, tp))
                    if let Some(dst_port) = tp.dst_port()
                        && let dst_ip = net.dst_addr() =>
                {
                    if let Ok(dst_ip) = UnicastIpAddr::try_from(dst_ip) {
                        debug!("Packet qualifies for port-forwarding");
                        Some((dst_ip, dst_port, net.next_header()))
                    } else {
                        debug!("Ignoring packet: destination IP is not unicast");
                        None
                    }
                }
                _ => {
                    debug!("Ignoring packet: packet type does not qualify");
                    None
                }
            }
        {
            let key = PortFwKey::new(src_vpcd, proto);
            Some((key, dst_ip, dst_port))
        } else {
            None
        }
    }

    fn do_port_forwarding<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        entry: &Arc<PortFwEntry>,
        dst_ip: UnicastIpAddr,
        dst_port: NonZero<u16>,
        new_dst_ip: UnicastIpAddr,
        new_dst_port: NonZero<u16>,
    ) {
        debug!("Will translate {dst_ip}:{dst_port} -> {new_dst_ip}:{new_dst_port} as per {entry}");

        // build keys for the FORWARD and REVERSE flows
        let (fw_key, rev_key) =
            match build_portfw_flow_keys(packet, new_dst_ip, new_dst_port, entry.dst_vpcd) {
                Ok(keys) => keys,
                Err(e) => {
                    warn!(
                        "Failed to build flow keys: \
                         {dst_ip}:{dst_port} -> {new_dst_ip}:{new_dst_port}: {e}"
                    );
                    packet.done(DoneReason::InternalFailure);
                    return;
                }
            };

        // create a pair of related flow entries (outside the flow table). Timeout is set according to the rule matched
        let timeout = clock::now() + entry.init_timeout();
        let Ok((fw_flow, rev_flow)) = FlowInfo::related_pair(
            timeout,
            fw_key,
            packet.meta().compute_flow_flags_forward(),
            rev_key,
            packet.meta().compute_flow_flags_reverse(),
        ) else {
            debug!("Failed to build flow pair for port forwarded flow");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        // set the generation id for the flow
        fw_flow.set_genid_pair(self.pipeline_data.genid());

        // set the flows in the FORWARD & REVERSE direction for subsequent packets
        let status = setup_forward_flow(&fw_key, &fw_flow, entry, new_dst_ip, new_dst_port);
        setup_reverse_flow(&rev_key, &rev_flow, entry, dst_ip, dst_port, status);

        // get the state we just created for the FORWARD direction
        let locked = fw_flow.locked.read();
        let pfw_state = locked
            .port_fw_state
            .extract_ref::<PortFwState>()
            .unwrap_or_else(|| unreachable!());

        // translate destination according to the rule. If this fails, no state will be created
        if let Err(e) = nat_packet(packet, pfw_state) {
            debug!("Failed to port-forward packet (initial):{e}");
            packet.done(DoneReason::InternalFailure);
            return;
        }
        drop(locked);

        let insertion = match self.flow_table.insert_if_absent(&fw_flow) {
            Ok(insertion) => insertion,
            Err(e) => {
                warn!("Failed to insert flow (forward) in the flow table: {e}");
                packet.done(DoneReason::FlowCapacityExceeded);
                return;
            }
        };
        if matches!(insertion, Insertion::Occupied(_)) {
            debug!("Lost the race to create port-forwarding flow {fw_key}; kept the winner's");
            return;
        }

        // The reverse insert is expected to always succeed: capacity enforcement
        // recognises that rev_flow has a related flow (fw_flow) already in the table
        // and admits it unconditionally.  Remove the forward entry on the unlikely
        // event of failure to avoid leaving a one-sided flow.
        if let Err(e) = self.flow_table.insert_from_arc(&rev_flow) {
            fw_flow.invalidate();
            warn!("Failed to insert flow (reverse) in the flow table: {e}");
            packet.done(DoneReason::FlowCapacityExceeded);
            debug_assert!(false, "reverse port-forwarding flow insert failed: {e:?}");
            return;
        }

        debug!("Inserted forward and reverse port-forwarding flow entries");
    }

    fn try_port_forwarding<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        pfwtable: &PortFwTable,
    ) {
        let nfi = &self.name;

        // check if the packet can be port forwarded at all
        let Some((key, dst_ip, dst_port)) = Self::can_be_port_forwarded(packet) else {
            packet.done(DoneReason::NatNotPortForwarded);
            debug!("{nfi}: packet cannot be port-forwarded. Dropping...");
            return;
        };

        // lookup the port-forwarding rule, using the given key, that contains the destination port
        let Some(entry) = pfwtable.lookup_matching_rule(key, dst_ip.inner(), dst_port) else {
            debug!("{nfi}: no rule found for port-forwarding key {key}. Dropping packet...");
            packet.done(DoneReason::NatNotPortForwarded);
            return;
        };

        // map the destination address and port
        let Some((new_dst_ip, new_dst_port)) = entry.map_address_port(dst_ip.inner(), dst_port)
        else {
            debug!("{nfi}: Unable to build usable address or port");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        self.do_port_forwarding(packet, entry, dst_ip, dst_port, new_dst_ip, new_dst_port);
    }

    fn get_rule_from_pkt_fw_path<Buf: PacketBufferMut>(
        packet: &Packet<Buf>,
        dst_vpcd: VpcDiscriminant,
        state: &PortFwState,
        pfwtable: &PortFwTable,
    ) -> Option<Arc<PortFwEntry>> {
        // These could be retrieved from the FlowKey, but we don't have it :( ...
        let src_vpcd = packet.meta().src_vpcd?;
        let proto = packet.upper_layer_proto()?;
        let net = packet.try_ip()?;
        let dst_ip = net.dst_addr();
        let dst_port = packet.transport_dst_port()?;
        let key = PortFwKey::new(src_vpcd, proto);

        let entry = pfwtable.lookup_matching_rule(key, dst_ip, dst_port)?;
        debug!("Found rule ({entry}) to forward to {dst_ip}:{dst_port} ({proto}) from {src_vpcd}");

        let (new_ip, new_port) = entry.map_address_port(dst_ip, dst_port)?;
        debug!(
            "According to rule, traffic should be port-forwarded to {new_ip}:{new_port} at {}",
            entry.dst_vpcd
        );

        // Even if we find a rule that says that the destination ip and port should be port forwarded,
        // we need to check if the current flow DNATs to the same target ip, port and vpc. Otherwise,
        // we should drop the packet and the flow since we'd sending the traffic to the wrong recipient
        // ... and the communication would be broken anyway (e.g. if TCP)
        if state.use_ip() != new_ip || state.use_port() != new_port || entry.dst_vpcd != dst_vpcd {
            debug!(
                "Current state targets a distinct device; {}:{} @ vpc {dst_vpcd}. Will drop",
                state.use_ip(),
                state.use_port()
            );
            None
        } else {
            debug!("Packet conforms to rule {entry}");
            Some(entry.clone())
        }
    }

    fn get_rule_from_pkt_rev_path<Buf: PacketBufferMut>(
        packet: &Packet<Buf>,
        dst_vpcd: VpcDiscriminant,
        state: &PortFwState,
        pfwtable: &PortFwTable,
    ) -> Option<Arc<PortFwEntry>> {
        // get required properties from packet
        let src_vpcd = packet.meta().src_vpcd?;
        let proto = packet.upper_layer_proto()?;
        let net = packet.try_ip()?;
        let src_ip = net.src_addr();
        let src_port = packet.transport_src_port()?;

        // get the ip and port that were port-forwarded in the forward direction when this flow was created.
        // These are the ip and port that the packets in reverse path should be SNATed with.
        let dst_ip = state.use_ip();
        let dst_port = state.use_port();
        let key = PortFwKey::new(dst_vpcd, proto);
        let entry = pfwtable.lookup_matching_rule(key, dst_ip.inner(), dst_port)?;
        debug!("Found compatible port-forwarding rule: {entry}");

        // check how forwarding rule found (presumably newer) would forward the packet
        let (target_ip, target_port) = entry.map_address_port(dst_ip.inner(), dst_port)?;
        let target_ip = target_ip.inner();
        debug!(
            "Traffic should be port-forwarded to {target_ip}:{target_port} at {}",
            entry.dst_vpcd
        );

        // check if the forwarding rule found (presumably newer) would send the traffic to the sender of this packet
        if target_ip != src_ip || target_port != src_port || entry.dst_vpcd != src_vpcd {
            debug!(
                "The latest matching rule for {dst_ip}:{dst_port} ({proto}) from {dst_vpcd} \
                would send traffic to {target_ip}:{target_port} at {} instead of \
                {src_ip}:{src_port} at {src_vpcd}. Will drop this flow.",
                entry.dst_vpcd
            );
            None
        } else {
            debug!("Packet conforms to rule {entry}");
            Some(entry.clone())
        }
    }

    fn reassign_port_fw_rule(flow_info: &FlowInfo, entry: &Arc<PortFwEntry>) {
        let mut flow_info_locked = flow_info.locked.write();
        if let Some(state) = flow_info_locked.port_fw_state.extract_mut::<PortFwState>() {
            state.rule = Arc::downgrade(entry);
        }
    }

    fn get_rule_from_pkt<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        pfwtable: &PortFwTable,
        state: &PortFwState,
    ) -> Option<Arc<PortFwEntry>> {
        let flow_info = packet.meta().flow_info.as_ref()?;
        let dst_vpcd = flow_info.get_dst_vpcd()?;

        // find compatible rule depending on the path this packet lives, forward or reverse
        let entry = match state.action() {
            NatAction::DstNat => Self::get_rule_from_pkt_fw_path(packet, dst_vpcd, state, pfwtable),
            NatAction::SrcNat => {
                Self::get_rule_from_pkt_rev_path(packet, dst_vpcd, state, pfwtable)
            }
        };

        // if we found an entry, let the port-forwarding state of the flow (and the one in the reverse path)
        // point to it so that subsequent packets are fast-forwarded.
        if let Some(entry) = entry.as_ref() {
            Self::reassign_port_fw_rule(flow_info, entry);
            if let Some(related) = flow_info.related.as_ref().and_then(Weak::upgrade) {
                Self::reassign_port_fw_rule(&related, entry);
            }
        }

        // return the entry found to continue processing the packet
        entry
    }

    /// Do port forwarding for the given packet, if it is eligible and there's a rule
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        pfwtable: &PortFwTable,
    ) {
        let genid = self.pipeline_data.genid();

        // fast-path based on the flow table
        if let Some(state) = get_packet_port_fw_state(packet) {
            // packet hit an Active flow with port-forwarding state. Even in that case, it may
            // happen that the state does not refer to a valid rule because: 1) it was removed
            // or 2) the configuration changed and the rule was replaced by another one. In both
            // cases we need to check if the packet, that belongs to a flow that was port-forwarded
            // in the past, should still be allowed with the new configuration, and, if so, how
            // much should we extend the flows' lifetimes.
            let entry = if let Some(entry) = state.rule.upgrade() {
                debug!("Packet hit Active flow referring to VALID port-forwarding rule.");
                entry
            } else {
                debug!("Packet hit Active flow referring to STALE port-forwarding rule.");
                let Some(entry) = Self::get_rule_from_pkt(packet, pfwtable, &state) else {
                    debug!("Packet should no longer be forwarded. Will drop and invalidate flows");
                    packet.done(DoneReason::NatNotPortForwarded);
                    packet.invalidate_flows();
                    return;
                };
                /* we found a port-forwarding rule that grants access to this packet */
                entry
            };

            // nat the packet
            if let Err(e) = nat_packet(packet, &state) {
                error!("Failed to port-forward packet:{e}");
                packet.done(DoneReason::InternalFailure);
                return;
            }

            // refresh flow state and status
            refresh_port_fw_entry(packet, entry.as_ref(), &state, genid);
        } else {
            // Slow path: we did not hit a flow, or, if we did, it was not Active or did not contain port-forwarding state.
            self.try_port_forwarding(packet, pfwtable);
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PortForwarder {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(move |mut packet| {
            if !packet.is_done()
                && packet.meta().requires_port_forwarding()
                && !packet.is_icmp_error()
            {
                if let Some(pfwtable) = self.fwtable.enter() {
                    self.process_packet(&mut packet, pfwtable.as_ref());
                    if packet.is_done() {
                        debug!("Could NOT port-forward packet:\n{packet}");
                    } else {
                        trace!("Port-forwarded packet:\n{packet}");
                    }
                } else {
                    // we were told to port-forward but we couldn't. So, drop the packet
                    packet.done(DoneReason::InternalFailure);
                }
            }
            packet.enforce()
        })
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

#[cfg(test)]
mod race {
    use super::*;
    use crate::portfw::probe::{Arrival, Fabric};
    use crate::static_nat::probe::build;
    use config::external::overlay::vpcpeering::VpcExpose;
    use lpm::prefix::{L4Protocol, PortRange, PrefixWithOptionalPorts};
    use net::buffer::TestBuffer;
    use pipeline::NetworkFunction;
    use std::net::IpAddr;

    fn side(prefix: &str, first: u16, last: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(
            prefix.parse().unwrap_or_else(|_| unreachable!()),
            Some(PortRange::new(first, last).unwrap_or_else(|_| unreachable!())),
        )
    }

    fn fabric() -> Fabric {
        let expose = VpcExpose::empty()
            .make_port_forwarding(None, Some(L4Protocol::Tcp))
            .unwrap_or_else(|e| unreachable!("{e}"))
            .ip(side("10.0.0.0/30", 9000, 9003))
            .as_range(side("172.16.0.0/30", 8000, 8003))
            .unwrap_or_else(|e| unreachable!("{e}"));
        Fabric::build(&[expose]).unwrap_or_else(|| unreachable!("a fixed expose builds"))
    }

    fn entries(fabric: &Fabric) -> Vec<usize> {
        let mut ids: Vec<usize> = fabric
            .flows()
            .snapshot(|_, _| true)
            .map(|flow| Arc::as_ptr(&flow) as usize)
            .collect();
        ids.sort_unstable();
        ids
    }

    #[tokio::test]
    async fn a_second_packet_of_one_burst_keeps_the_first_packets_flow() {
        let fabric = fabric();
        let (mut lookup, mut pfw) = fabric.stages();
        let arrival = Arrival::inbound();

        let peer: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
        let published: IpAddr = "172.16.0.1".parse().unwrap_or_else(|_| unreachable!());
        let packet = || {
            let mut packet: Packet<TestBuffer> = build(peer, published, true, 1234, 8001);
            arrival.stamp(&mut packet);
            packet
        };

        let mut stamped = lookup.process(vec![packet(), packet()].into_iter());
        let mut first = stamped.next().unwrap_or_else(|| unreachable!());
        let mut second = stamped.next().unwrap_or_else(|| unreachable!());
        drop(stamped);
        for packet in [&mut first, &mut second] {
            packet.meta_mut().dst_vpcd = arrival.dst_vpcd.map(VpcDiscriminant::from_vni);
        }

        pfw.process(std::iter::once(first)).for_each(drop);
        let installed = entries(&fabric);
        assert_eq!(
            installed.len(),
            2,
            "the first packet of the burst did not install a pair"
        );

        pfw.process(std::iter::once(second)).for_each(drop);
        assert_eq!(
            entries(&fabric),
            installed,
            "the second packet of the burst replaced the pair the first one installed"
        );
        assert!(
            fabric
                .flows()
                .snapshot(|_, _| true)
                .all(|flow| flow.is_active()),
            "the burst left a half of the pair no longer live"
        );
    }
}
