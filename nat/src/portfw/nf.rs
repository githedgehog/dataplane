// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding stage

use crate::portfw::{PortFwEntry, PortFwKey, PortFwTable, PortFwTableReader};
use flow_entry::flow_table::FlowTable;
use net::buffer::PacketBufferMut;
use net::headers::{TryIp, TryTcp, TryTransport};
use net::ip::{NextHeader, UnicastIpAddr};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;
use std::num::NonZero;
use std::sync::Arc;

use crate::portfw::flow_state::{
    create_port_fw_forward_entry, create_port_fw_reverse_entry, get_packet_port_fw_state,
    refresh_port_fw_entry,
};
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

        // create flow entry for subsequent packets in the forward path
        let status = create_port_fw_forward_entry(&self.flow_table, packet, entry, new_dst_port);

        // translate destination according to port-forwarding entry
        if !dnat_packet(packet, entry.dst_ip.inner(), new_dst_port) {
            packet.done(DoneReason::InternalFailure);
            return;
        }

        // crate a flow entry for the reverse path
        create_port_fw_reverse_entry(&self.flow_table, packet, entry, orig_dst_port, status);
    }

    fn try_port_forwarding<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        pfwtable: &PortFwTable,
    ) {
        let nfi = &self.name;
        let Some((key, dst_port)) = Self::can_be_port_forwarded(packet) else {
            if let Some(reason) = packet.get_done() {
                debug!("{nfi}: packet cannot be port-forwarded. Dropping it (reason:{reason})");
            } else {
                debug!("{nfi}: packet cannot be port-forwarded. Releasing it.");
            }
            return;
        };

        // lookup the port-forwarding rule with the given key that contains the given port
        let Some(entry) = pfwtable.lookup_matching_rule(&key, dst_port) else {
            debug!("{nfi}: no rule found for port-forwarding key {key}. Releasing packet...");
            return;
        };

        // map the destination port
        let ext_ports = entry.ext_ports;
        let Some(new_dst_port) = entry.ext_ports.map_port_to(dst_port, entry.dst_ports) else {
            debug!("{nfi}: port {dst_port} is not in {ext_ports}. Releasing packet...",);
            return;
        };
        self.do_port_forwarding(packet, entry, dst_port, new_dst_port);
    }

    /// Do port forwarding for the given packet, if it is eligible and there's a rule
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        pfwtable: &PortFwTable,
    ) {
        if let Some(pfw_state) = get_packet_port_fw_state(packet) {
            if !nat_packet(packet, &pfw_state) {
                error!("Failed to nat port-forwarded packet");
                packet.done(DoneReason::InternalFailure);
                return;
            }
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
            // FIXME: here we'll attempt to process all packets
            // If flow-filter can identify if packets have to be port-forwarded
            // here we can filter out with packet.meta().requires_port_forwarding().
            #[allow(clippy::collapsible_if)]
            if !packet.is_done() {
                if let Some(pfwtable) = self.fwtable.enter() {
                    self.process_packet(&mut packet, pfwtable.as_ref());
                }
            }
            packet.enforce()
        })
    }
}
