// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Overlay routing NF

use flow_entry::flow_table::FlowTable;
use net::buffer::PacketBufferMut;
use net::headers::TryIp;
use net::ip::NextHeader;
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;
use std::sync::Arc;

use tracing::debug;

use super::access::OverlayRoutingRW;
use super::routing::{Action, OverlayRouting, PacketSummary};

pub struct OverlayRouter {
    flow_table: Arc<FlowTable>,
    ort: OverlayRoutingRW,
}

impl OverlayRouter {
    #[must_use]
    pub fn new(flow_table: Arc<FlowTable>, ort: OverlayRoutingRW) -> Self {
        Self { flow_table, ort }
    }

    fn validate_packet<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<PacketSummary> {
        let net = packet.try_ip()?;
        let s = PacketSummary {
            src_vpcd: packet.meta().src_vpcd?,
            src_addr: net.src_addr(),
            dst_addr: net.dst_addr(),
            proto: net.next_header(),
            src_port: packet.transport_src_port(),
            dst_port: packet.transport_dst_port(),
        };
        if (s.proto == NextHeader::UDP || s.proto == NextHeader::TCP)
            && (s.src_port.is_none() || s.dst_port.is_none())
        {
            debug!("Failed to retrieve UDP/TCP port information!");
            return None;
        }
        Some(s)
    }

    fn set_pkt_actions<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        local: Action,
        remote: Action,
    ) {
        match local {
            Action::Drop => packet.done(DoneReason::Filtered),
            Action::Masquerade => packet.meta_mut().set_stateful_nat(true),
            Action::StaticNat => packet.meta_mut().set_stateless_nat(true),
            Action::Forward => {}
            Action::PortForward => unreachable!(),
        }
        match remote {
            Action::Drop => packet.done(DoneReason::Filtered),
            Action::PortForward => packet.meta_mut().set_port_forwarding(true),
            Action::StaticNat => packet.meta_mut().set_stateless_nat(true),
            Action::Forward => {}
            Action::Masquerade => unreachable!(),
        }
    }

    fn process_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>, ort: &OverlayRouting) {
        let Some(s) = Self::validate_packet(packet) else {
            debug!("Dropping packet since we could not validate it:\n{packet}");
            packet.done(DoneReason::Unroutable);
            return;
        };
        let Some((dst_vpcd, loc_action, rem_action)) = ort.lookup(&s) else {
            packet.done(DoneReason::Filtered);
            return;
        };
        packet.meta_mut().dst_vpcd = Some(dst_vpcd);
        Self::set_pkt_actions(packet, loc_action, rem_action);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for OverlayRouter {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        let guard = self.ort.load();
        input.filter_map(move |mut packet| {
            if !packet.is_done()
                && packet.meta().is_overlay()
                && let Some(ort) = guard.as_ref()
            {
                self.process_packet(&mut packet, ort);
            }

            packet.enforce()
        })
    }
}
