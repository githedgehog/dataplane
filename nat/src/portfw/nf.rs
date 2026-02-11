// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding stage

use crate::portfw::portfwtable::PortFwTableRw;
use crate::portfw::{PortFwEntry, PortFwKey, PortFwTable};

use flow_entry::flow_table::FlowTable;
use net::buffer::PacketBufferMut;
use net::headers::{TryIp, TryTransport};
use net::ip::{NextHeader, UnicastIpAddr};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;
use std::sync::Arc;

use crate::portfw::flow_state::{
    check_packet_port_fw_state, create_port_fw_forward_entry, create_port_fw_reverse_entry,
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
    fwtable: PortFwTableRw,
}

impl PortForwarder {
    /// Creates a new [`PortForwarder`]
    #[must_use]
    pub fn new(name: &str, fwtable: PortFwTableRw, flow_table: Arc<FlowTable>) -> Self {
        Self {
            name: name.to_string(),
            flow_table,
            fwtable,
        }
    }

    /// Tell if a packet can be port-forwarded. For that to happen, a packet must be
    /// unicast Ipv4 or IPv6 and carry UDP/TCP payload.
    fn can_be_port_forwarded<Buf: PacketBufferMut>(packet: &mut Packet<Buf>) -> Option<PortFwKey> {
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
        let Some(dst_port) = transport.dst_port() else {
            error!("can't get dst port from {proto} header: will drop");
            packet.done(DoneReason::InternalFailure);
            return None;
        };
        let key = PortFwKey::new(src_vpcd, dst_ip, proto, dst_port);
        debug!("packet can be port-forwarded, key is {key}");
        Some(key)
    }

    fn do_port_forwarding<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        entry: &Arc<PortFwEntry>,
    ) {
        debug!("performing port-forwarding with rule: {entry}");

        // create flow entry for subsequent packets in the forward path
        create_port_fw_forward_entry(&self.flow_table, packet, entry);

        // translate destination according to port-forwarding entry
        if !dnat_packet(packet, entry.dst_ip.inner(), entry.dst_port) {
            packet.done(DoneReason::InternalFailure);
            return;
        }

        // crate a flow entry for the reverse path
        create_port_fw_reverse_entry(&self.flow_table, packet, entry);
    }

    fn try_port_forwarding<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        pfwtable: &PortFwTable,
    ) {
        let nfi = &self.name;
        let Some(key) = Self::can_be_port_forwarded(packet) else {
            if let Some(reason) = packet.get_done() {
                debug!("{nfi}: packet cannot be port-forwarded. Dropping it (reason:{reason})");
            } else {
                debug!("{nfi}: packet cannot be port-forwarded. Releasing it.");
            }
            return;
        };
        let Some(pfw_entry) = pfwtable.lookup_rule(&key) else {
            debug!("{nfi}: no rule found for port-forwarding key {key}. Releasing packet...");
            return;
        };
        self.do_port_forwarding(packet, pfw_entry);
    }

    /// Do port forwarding for the given packet, if it is eligible and there's a rule
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        pfwtable: &PortFwTable,
    ) {
        if let Some(pfw_state) = check_packet_port_fw_state(packet) {
            debug!("Packet hit port-forwarding state: {pfw_state}");
            if !nat_packet(packet, &pfw_state) {
                error!("Failed to nat port-forwarded packet");
                packet.done(DoneReason::InternalFailure);
                return;
            }
            // refresh the flow entry hit by the packet
            refresh_port_fw_entry(packet, &pfw_state);
        } else {
            // Packet did not hit any flow entry with port forwarding state.
            // Check if it can and needs to be port-forwarded.
            self.try_port_forwarding(packet, pfwtable);
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PortForwarder {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        let guard = self.fwtable.load();
        input.filter_map(move |mut packet| {
            // FIXME: here we'll attempt to process all packets
            // If flow-filter can identify if packets have to be port-forwarded
            // here we can filter out with packet.meta().requires_port_forwarding().
            #[allow(clippy::collapsible_if)]
            if !packet.is_done() {
                if let Some(pfwtable) = guard.as_ref() {
                    self.process_packet(&mut packet, pfwtable);
                }
            }
            packet.enforce()
        })
    }
}
