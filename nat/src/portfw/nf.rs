// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding stage

use crate::portfw::{PortFwEntry, PortFwKey, PortFwTable, PortFwTableReader};
use flow_entry::flow_table::FlowInfo;
use flow_entry::flow_table::FlowTable;
use net::buffer::PacketBufferMut;
use net::headers::{TryIp, TryTcp, TryTransport};
use net::ip::{NextHeader, UnicastIpAddr};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;
use std::num::NonZero;
use std::sync::Arc;
use std::time::Instant;

use crate::portfw::flow_state::get_packet_port_fw_state;
use crate::portfw::flow_state::refresh_port_fw_entry;
use crate::portfw::flow_state::setup_forward_flow;
use crate::portfw::flow_state::setup_reverse_flow;
use crate::portfw::packet::{dnat_packet, nat_packet};

#[allow(unused)]
use tracing::{debug, error, warn};

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
    /// a `PortFwKey` is returned, along with the destination port to translate.
    fn can_be_port_forwarded<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
    ) -> Option<(PortFwKey, NonZero<u16>)> {
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
            debug!("Ignoring TCP segment without SYN flag");
            packet.done(DoneReason::Filtered);
            return None;
        }
        let Some(dst_port) = transport.dst_port() else {
            error!("can't get dst port from {proto} header: will drop");
            packet.done(DoneReason::InternalFailure);
            return None;
        };
        let key = PortFwKey::new(src_vpcd, dst_ip, proto);
        debug!("packet can be port-forwarded, key is {key}");
        Some((key, dst_port))
    }

    fn do_port_forwarding<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        entry: &Arc<PortFwEntry>,
        orig_dst_port: NonZero<u16>,
        new_dst_port: NonZero<u16>,
    ) {
        debug!("Will map port {orig_dst_port} -> {new_dst_port} according to rule: {entry}");

        // crate a pair of related flow entries (outside the flow table). Timeout is set according to the rule
        let (forward, reverse) = FlowInfo::related_pair(Instant::now() + entry.init_timeout());

        // set up a flow in the forward direction for subsequent packets
        let (key_fw, status) = setup_forward_flow(&forward, packet, entry, new_dst_port);

        // translate destination according to the rule matched. If this fails, no state will be created
        if !dnat_packet(packet, entry.dst_ip.inner(), new_dst_port) {
            packet.done(DoneReason::InternalFailure);
            return;
        }

        // set up a flow for the reverse path
        let key_rev = setup_reverse_flow(&reverse, packet, entry, orig_dst_port, status);

        // insert the two related flows
        if let Some(prior) = self.flow_table.insert_from_arc(key_fw, &forward) {
            debug!("Replaced flow entry: {prior}");
        }
        if let Some(prior) = self.flow_table.insert_from_arc(key_rev, &reverse) {
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
        let Some((key, dst_port)) = Self::can_be_port_forwarded(packet) else {
            packet.done(DoneReason::Filtered);
            let reason = packet.get_done().unwrap_or_else(|| unreachable!());
            debug!("{nfi}: packet cannot be port-forwarded. Dropping it (reason:{reason})");
            return;
        };

        // lookup the port-forwarding rule, using the given key, that contains the destination port
        let Some(entry) = pfwtable.lookup_matching_rule(&key, dst_port) else {
            debug!("{nfi}: no rule found for port-forwarding key {key}. Dropping packet.");
            packet.done(DoneReason::Filtered);
            return;
        };

        // map the destination port. This can't fail since we found a rule containing the port.
        let new_dst_port = entry
            .ext_ports
            .map_port_to(dst_port, entry.dst_ports)
            .unwrap_or_else(|| unreachable!());
        self.do_port_forwarding(packet, entry, dst_port, new_dst_port);
    }

    /// Do port forwarding for the given packet, if it is eligible and there's a rule
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        pfwtable: &PortFwTable,
    ) {
        if let Some(pfw_state) = get_packet_port_fw_state(packet) {
            // this is the fast-path based on the flow table
            if !nat_packet(packet, &pfw_state) {
                error!("Failed to nat port-forwarded packet");
                packet.done(DoneReason::InternalFailure);
                return;
            }
            // refresh the state. Packet may still be dropped here
            refresh_port_fw_entry(packet, &pfw_state);
        } else {
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
            if !packet.is_done() && packet.meta().requires_port_forwarding() {
                if let Some(pfwtable) = self.fwtable.enter() {
                    self.process_packet(&mut packet, pfwtable.as_ref());
                } else {
                    // we were told to port-forward but we couldn't. So, drop the packet
                    packet.done(DoneReason::InternalFailure);
                }
            }
            packet.enforce()
        })
    }
}
