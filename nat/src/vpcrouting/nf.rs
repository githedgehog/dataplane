// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Overlay routing NF

use flow_entry::flow_table::FlowTable;
use net::buffer::PacketBufferMut;
use net::headers::TryIp;
use net::ip::NextHeader;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::NetworkFunction;
use std::sync::Arc;

use tracing::debug;

use super::access::OverlayRoutingRW;
use super::routing::{Action, OverlayRouting, PacketSummary};

pub struct OverlayRouter {
    #[allow(unused)]
    flow_table: Arc<FlowTable>,
    ort: OverlayRoutingRW,
}

struct BypassData {
    dst_vpcd: VpcDiscriminant,
    masquerade: bool,
    port_forwarding: bool,
}

impl OverlayRouter {
    #[must_use]
    pub fn new(flow_table: Arc<FlowTable>, ort: OverlayRoutingRW) -> Self {
        Self { flow_table, ort }
    }

    fn process_with_flow_state<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
    ) -> Option<BypassData> {
        let flow = packet.meta().flow_info.as_ref()?;
        let locked = flow.locked.read().ok()?;
        let dst_vpcd = locked.dst_vpcd?;
        let masquerade = locked.nat_state.is_some();
        let port_forwarding = locked.port_fw_state.is_some();
        Some(BypassData {
            dst_vpcd,
            masquerade,
            port_forwarding,
        })
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

    #[allow(clippy::unused_self)]
    fn process_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>, ort: &OverlayRouting) {
        // bypass if packet matched flow
        if let Some(bypass) = Self::process_with_flow_state(packet) {
            packet.meta_mut().dst_vpcd = Some(bypass.dst_vpcd);
            if bypass.masquerade {
                packet.meta_mut().set_stateful_nat(true);
            }
            if bypass.port_forwarding {
                packet.meta_mut().set_port_forwarding(true);
            }
            return;
        }

        let Some(s) = Self::validate_packet(packet) else {
            debug!("Dropping packet since we could not validate it:\n{packet}");
            packet.done(DoneReason::Unroutable);
            return;
        };
        let Some((dst_vpcd, loc_action, rem_action)) = ort.lookup(&s) else {
            if packet.is_icmp_error() {
                debug!("Letting ICMP error handler process this packet");
            } else {
                packet.done(DoneReason::Filtered);
            }
            return;
        };
        // fixme: if dst_vcpd is known but there is no PF or masq, set the vpcd
        if packet.is_icmp_error() {
            debug!("Letting ICMP error handler process this packet. dst-vpcd is {dst_vpcd:?}");
            return;
        }
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
