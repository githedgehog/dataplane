// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding stage

use crate::portfw::{PortFwEntry, PortFwKey, PortFwState, PortFwTable, PortFwTableReader};
use flow_entry::flow_table::FlowTable;

use net::buffer::PacketBufferMut;
use net::flows::{ExtractMut, ExtractRef, FlowInfo};
use net::headers::{TryIp, TryTcp, TryTransport};
use net::ip::{NextHeader, UnicastIpAddr};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::NetworkFunction;
use std::num::NonZero;
use std::sync::Arc;
use std::time::Instant;

use crate::portfw::flow_state::PortFwAction;
use crate::portfw::flow_state::build_portfw_flow_keys;
use crate::portfw::flow_state::get_packet_port_fw_state;
use crate::portfw::flow_state::invalidate_flow_state;
use crate::portfw::flow_state::refresh_port_fw_entry;
use crate::portfw::flow_state::setup_forward_flow;
use crate::portfw::flow_state::setup_reverse_flow;
use crate::portfw::packet::{dnat_packet, nat_packet};

#[allow(unused)]
use tracing::{debug, error, trace, warn};

use tracectl::trace_target;
trace_target!("port-forwarding", LevelFilter::INFO, &["nat", "pipeline"]);

/// A port-forwarding network function
pub struct PortForwarder {
    name: String,
    flow_table: Arc<FlowTable>,
    fwtable: PortFwTableReader,
}

impl PortForwarder {
    /// Creates a new [`PortForwarder`]
    #[must_use]
    pub fn new(name: &str, fwtable: PortFwTableReader, flow_table: Arc<FlowTable>) -> Self {
        Self {
            name: name.to_string(),
            flow_table,
            fwtable,
        }
    }

    /// Tell if a packet can be port-forwarded. For that to happen, a packet must be
    /// unicast Ipv4 or IPv6 and carry UDP/TCP payload. If a packet can be port-forwarded,
    /// a `PortFwKey` is returned, along with the destination address and port to translate.
    fn can_be_port_forwarded<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
    ) -> Option<(PortFwKey, UnicastIpAddr, NonZero<u16>)> {
        debug!("checking packet for port-forwarding ...");

        let Some(src_vpcd) = packet.meta().src_vpcd else {
            error!("packet lacks src vpc annotation: will drop");
            packet.done(DoneReason::InternalFailure);
            return None;
        };
        let Some(net) = packet.try_ip() else {
            debug!("packet is not ipv4/ipv6: will ignore");
            return None;
        };
        let proto = net.next_header();
        if proto != NextHeader::TCP && proto != NextHeader::UDP {
            debug!("packet is not tcp/udp: will ignore");
            return None;
        }
        let dst_ip = net.dst_addr();
        let Ok(dst_ip) = UnicastIpAddr::try_from(dst_ip) else {
            debug!("Packet destination is not unicast: will ignore");
            return None;
        };
        let Some(transport) = packet.try_transport() else {
            error!("can't get packet transport headers: will drop");
            packet.done(DoneReason::InternalFailure);
            return None;
        };
        if let Some(tcp) = packet.try_tcp()
            && (!tcp.syn() || tcp.ack())
        {
            debug!("Dropping TCP segment: it has no SYN (or ack) and we have no state for it");
            packet.done(DoneReason::Filtered);
            return None;
        }
        let Some(dst_port) = transport.dst_port() else {
            error!("can't get dst port from {proto} header: will drop");
            packet.done(DoneReason::InternalFailure);
            return None;
        };
        let key = PortFwKey::new(src_vpcd, proto);
        Some((key, dst_ip, dst_port))
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
            build_portfw_flow_keys(packet, new_dst_ip, new_dst_port, entry.dst_vpcd);

        // create a pair of related flow entries (outside the flow table). Timeout is set according to the rule matched
        let timeout = Instant::now() + entry.init_timeout();
        let (fw_flow, rev_flow) = FlowInfo::related_pair(timeout, fw_key, rev_key);

        // set the flows in the FORWARD & REVERSE direction for subsequent packets
        let status = setup_forward_flow(&fw_key, &fw_flow, entry, new_dst_ip, new_dst_port);
        setup_reverse_flow(&rev_key, &rev_flow, entry, dst_ip, dst_port, status);

        // translate destination according to the rule matched. If this fails, no state will be created
        if !dnat_packet(packet, new_dst_ip.inner(), new_dst_port) {
            packet.done(DoneReason::InternalFailure);
            return;
        }

        // insert the two related flows
        if let Some(prior) = self.flow_table.insert_from_arc(fw_key, &fw_flow) {
            debug!("Replaced flow entry: {prior}");
        }
        if let Some(prior) = self.flow_table.insert_from_arc(rev_key, &rev_flow) {
            debug!("Replaced flow entry: {prior}");
        }
    }

    fn try_port_forwarding<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        pfwtable: &PortFwTable,
    ) {
        let nfi = &self.name;

        // check if the packet can be port forwarded at all
        let Some((key, dst_ip, dst_port)) = Self::can_be_port_forwarded(packet) else {
            packet.done(DoneReason::Filtered);
            let reason = packet.get_done().unwrap_or_else(|| unreachable!());
            debug!("{nfi}: packet cannot be port-forwarded. Dropping it (reason:{reason})");
            return;
        };

        // lookup the port-forwarding rule, using the given key, that contains the destination port
        let Some(entry) = pfwtable.lookup_matching_rule(key, dst_ip.inner(), dst_port) else {
            debug!("{nfi}: no rule found for port-forwarding key {key}. Dropping packet.");
            packet.done(DoneReason::Filtered);
            return;
        };

        // map the destination address and port
        let Some((new_dst_ip, new_dst_port)) = entry.map_address_port(dst_ip.inner(), dst_port)
        else {
            debug!("{nfi}: Unable to build usable address and port"); // FIXME:
            packet.done(DoneReason::Filtered);
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
        let net = packet.try_ip()?;
        let proto = net.next_header();
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
        let net = packet.try_ip()?;
        let proto = net.next_header();
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
        let mut flow_info_locked = flow_info.locked.write().unwrap();
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
        let flow_info_locked = flow_info.locked.read().unwrap();
        let dst_vpcd = *flow_info_locked
            .dst_vpcd
            .as_ref()
            .extract_ref::<VpcDiscriminant>()?;
        drop(flow_info_locked);

        // find compatible rule depending on the path this packet lives, forward or reverse
        let entry = match state.action() {
            PortFwAction::DstNat => {
                Self::get_rule_from_pkt_fw_path(packet, dst_vpcd, state, pfwtable)
            }
            PortFwAction::SrcNat => {
                Self::get_rule_from_pkt_rev_path(packet, dst_vpcd, state, pfwtable)
            }
        };

        // if we found an entry, let the port-forwarding state of the flow (and the one in the reverse path)
        // point to it so that subsequent packets are fast-forwarded.
        if let Some(entry) = entry.as_ref() {
            Self::reassign_port_fw_rule(flow_info, entry);
            if let Some(related) = flow_info
                .related
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
            {
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
                    debug!("Packet should no longer be forwarded. Will drop and invalidate state");
                    packet.done(DoneReason::Filtered);
                    invalidate_flow_state(packet);
                    return;
                };
                /* we found a port-forwarding rule that grants access to this packet */
                entry
            };

            // nat the packet
            if !nat_packet(packet, &state) {
                error!("Failed to nat port-forwarded packet");
                packet.done(DoneReason::InternalFailure);
                return;
            }

            // refresh flow state and status
            refresh_port_fw_entry(packet, entry.as_ref(), &state);
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
}
