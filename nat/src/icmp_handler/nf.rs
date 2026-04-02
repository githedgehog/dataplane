// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A network function to process icmp error packets

use flow_entry::flow_table::FlowTable;
use net::buffer::PacketBufferMut;
use net::checksum::Checksum;
use net::headers::{
    EmbeddedTransport, TryEmbeddedHeaders, TryEmbeddedTransport, TryIcmpAny, TryInnerIp,
    TryInnerIpv4, TryIp,
};
use net::icmp_any::{IcmpAnyChecksumPayload, TruncatedIcmpAny};
use net::ip::NextHeader;
use net::packet::{DoneReason, Packet};
use net::{FlowKey, IcmpProtoKey, IpProtoKey, TcpProtoKey, UdpProtoKey};

use pipeline::NetworkFunction;
use std::sync::Arc;
use tracing::{debug, warn};

use tracectl::trace_target;

use crate::portfw::icmp_handling::handle_icmp_error_port_forwarding;
use crate::stateful::icmp_handling::handle_icmp_error_masquerading;

trace_target!("icmp-errors", LevelFilter::INFO, &["nat", "pipeline"]);

pub struct IcmpErrorHandler {
    flow_table: Arc<FlowTable>,
}

impl IcmpErrorHandler {
    /// Creates a new `IcmpErrorHandler`
    #[must_use]
    pub fn new(flow_table: Arc<FlowTable>) -> Self {
        Self { flow_table }
    }
}

/// Validate the checksums for an ICMP packet.
///
/// From REQ-3 from RFC 5508, "NAT Behavioral Requirements for ICMP".
/// NAT should silently discard packet if:
///    - ICMP checksum fails to validate
///    - ICMP checksum for embedded packet fails to validate
///
/// This function is a variant of `validate_checksums_icmp` that marks packets to be dropped in place.
/// This function is valid for any ICMP packet, whether it embeds a packet fragment or not, but we only
/// use it for packets containing ICMP errors and assume that those packets must always include a fragment
/// of the offending packet.
/// FIXME(fredi): unify the two functions
fn icmp_checksums_ok<Buf: PacketBufferMut>(packet: &mut Packet<Buf>) -> bool {
    debug_assert!(packet.is_icmp());
    let icmp = packet.try_icmp_any().unwrap_or_else(|| unreachable!());

    let embedded = packet.embedded_headers();
    let payload = packet.payload().as_ref();
    let icmp_payload = icmp.get_payload_for_checksum(embedded, payload);

    let net = packet.try_ip().unwrap_or_else(|| unreachable!());
    let checksum_payload = IcmpAnyChecksumPayload::from_net(net, icmp_payload.as_ref());
    if icmp.validate_checksum(&checksum_payload).is_err() {
        debug!("Checksum failed for ICMP message");
        packet.done(net::packet::DoneReason::InvalidChecksum);
        return false;
    }

    // validate inner packet for icmp error messages
    if icmp.is_error_message() {
        let Some(embedded_ip) = packet.embedded_headers() else {
            debug!("Dropping ICMP error packet: embedded packet missing");
            packet.done(net::packet::DoneReason::IcmpErrorIncomplete);
            return false;
        };
        if let Some(inner_ipv4) = embedded_ip.try_inner_ipv4()
            && inner_ipv4.validate_checksum(&()).is_err()
        {
            debug!("Dropping ICMP error packet: embedded packet checksum failed");
            packet.done(net::packet::DoneReason::InvalidChecksum);
            return false;
        }
    }
    true
}

/// Build a `FlowKey` for the embedded "offending" packet within an ICMP error packet
fn get_icmp_inner_pkt_flowkey<Buf: PacketBufferMut>(packet: &mut Packet<Buf>) -> Option<FlowKey> {
    // get the data for the embedded, offending packet
    let Some(inner) = packet.embedded_headers() else {
        debug!("ICMP error message does not contain inner packet");
        return None;
    };

    let net = inner.try_inner_ip()?;
    let src_ip = net.src_addr();
    let dst_ip = net.dst_addr();
    let proto = net.next_header();

    let embedded_transport = inner.try_embedded_transport()?;

    // FIXME(fredi): see if we should do a TryFrom<EmbeddedTransport> for IpProtoKey
    // as suggested by Quentin
    let proto_key = match embedded_transport {
        EmbeddedTransport::Tcp(tcp) => {
            debug_assert_eq!(proto, NextHeader::TCP);
            IpProtoKey::Tcp(TcpProtoKey::from((tcp.source(), tcp.destination())))
        }
        EmbeddedTransport::Udp(udp) => {
            debug_assert_eq!(proto, NextHeader::UDP);
            IpProtoKey::Udp(UdpProtoKey::from((udp.source(), udp.destination())))
        }
        EmbeddedTransport::Icmp4(icmp) => {
            debug_assert_eq!(proto, NextHeader::ICMP);
            // Icmp errors are not sent for icmp errors
            let icmp_id = icmp.identifier()?;
            IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(icmp_id))
        }
        EmbeddedTransport::Icmp6(icmp6) => {
            debug_assert_eq!(proto, NextHeader::ICMP6);
            // Icmp errors are not sent for icmp errors
            let icmp_id = icmp6.identifier()?;
            IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(icmp_id))
        }
    };
    if proto == NextHeader::TCP || proto == NextHeader::UDP {
        let src_port = embedded_transport.source()?;
        let dst_port = embedded_transport.destination()?;
        debug!("ICMP offending packet: ({proto}) src:{src_ip}:{src_port} dst:{dst_ip}:{dst_port}");
    } else if proto == NextHeader::ICMP || proto == NextHeader::ICMP6 {
        let id = embedded_transport.icmp_identifier()?;
        debug!("ICMP offending packet: ({proto}) src:{src_ip} dst:{dst_ip} id: {id}");
    }
    let flow_key = FlowKey::uni(None, src_ip, dst_ip, proto_key);
    Some(flow_key)
}

impl IcmpErrorHandler {
    /// Handle an ICMP error packet. This processing follows requirements REQ-4 and REQ-5
    /// of RFC 5508, "NAT Behavioral Requirements for ICMP".
    fn handle_icmp_error_msg<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) {
        // where does this ICMP come from?
        let Some(icmp_src_vpcd) = packet.meta().src_vpcd else {
            debug!("Got ICMP packet without src vpc discriminant. Will drop");
            packet.done(DoneReason::Unroutable);
            return;
        };
        debug!("Got ICMP error packet from {icmp_src_vpcd}");

        // drop packet if icmp checksums are not okay. We compute the checksum before we actually
        // know if we'll be able to process the packet. This is wasteful if we will drop it. OTH,
        // if the packet has been altered, our lookup in the flow table may provide either no flow or,
        // worse, a wrong flow. So, we do it here, with the hope that this will later be HW offloaded.
        if !icmp_checksums_ok(packet) {
            return;
        }

        // Okay, so we got an ICMP error packet from some VPC, which should include some "offending"
        // packet inside. That offending packet is something we've -presumably- sent. If we were
        // NATing (masquerading or port-forwarding), that offending packet may have addresses and/or
        // ports which we may have translated, and which differ from the original packet we mangled.
        // Now, given that we (presumably) sent the offending packet, we can't expect to find a flow
        // for it (because we modified it), but we should have a flow in the reverse direction to tell
        // us how to handle the "reply" we would get had the offending packet made it successfully to
        // its recipient. So, here, we:
        //    1) build a flow key for the offending packet and REVERSE it
        //    2) look up the flow table for a flow in the reverse path of the offending packet.

        let Some(flow_key) = get_icmp_inner_pkt_flowkey(packet) else {
            debug!("Could not build flow key for ICMP-error embedded packet");
            packet.done(DoneReason::IcmpErrorIncomplete);
            return;
        };

        // reverse the flow key and look up for a flow in the flow table.
        let rev_flow_key = flow_key.reverse(Some(icmp_src_vpcd));
        let Some(flow) = self.flow_table.lookup(&rev_flow_key) else {
            debug!("Found no flow for key={rev_flow_key}");
            packet.done(DoneReason::Filtered);
            return;
        };
        debug!("Found flow, {}", flow.logfmt());
        let flow_info_locked = flow.locked.read().unwrap();
        let Some(dst_vpcd) = flow_info_locked.dst_vpcd else {
            warn!("Flow-info for {rev_flow_key} has no dst VPC discriminant. This is a bug");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        // burn the dst vpcd in the packet. This NF offloads the flow-filter from doing that
        packet.meta_mut().dst_vpcd = Some(dst_vpcd);

        // process the packet depending on the state of the flow
        if flow_info_locked.nat_state.is_some() {
            handle_icmp_error_masquerading(packet, flow.as_ref());
        } else if flow_info_locked.port_fw_state.is_some() {
            handle_icmp_error_port_forwarding(packet, flow.as_ref());
        } else {
            debug!("Found no specific NAT state to process ICMP error message. Dropping...");
            // This can't happen atm since the only NFs that create flows are stateful NAT
            // and port-forwarding. If we hit a flow that does not have either of those set
            // that's, atm, a bug in either of them.
            packet.done(DoneReason::InternalFailure);
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for IcmpErrorHandler {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(move |mut packet| {
            if !packet.is_done() && packet.meta().is_overlay() && packet.is_icmp_error() {
                if packet.meta().requires_stateless_nat() {
                    // don't process icmp errors for stateless NAT or if we know dst-vpcd
                    debug!("ICMP error will be handled by static NAT NF:\n{packet}");
                } else if packet.meta().dst_vpcd.is_some() {
                    // NOTE: this assumes that the flow-filter will NOT mark icmp errors
                    // for port-forwarding or masquerading
                    debug!("Dst-vpcd for ICMP error packet is known.",);
                } else {
                    // last chance. If packet was triggered by a masqueraded or port forwarded
                    // packet, we should be able to process it here.
                    self.handle_icmp_error_msg(&mut packet);
                }
            }
            packet.enforce()
        })
    }
}
