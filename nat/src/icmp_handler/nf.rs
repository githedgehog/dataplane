// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A network function to process icmp error packets in the overlay
//! if those correspond to port-forwarding or masquerading

use flow_entry::flow_table::FlowTable;
use net::buffer::PacketBufferMut;
use net::checksum::Checksum;
use net::flow_key::flowkey_embedded_in_icmp_error;
use net::headers::{TryEmbeddedHeaders, TryIcmpAny, TryInnerIpv4, TryIp};
use net::icmp_any::IcmpAnyChecksumPayload;
use net::packet::{DoneReason, Packet};

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

impl IcmpErrorHandler {
    fn handle_icmp_error_msg<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) {
        // check origin of icmp error packet
        let Some(src_vpcd) = packet.meta().src_vpcd else {
            debug!("Dropping ICMP error packet: no src vpc discriminant");
            packet.done(DoneReason::Unroutable);
            return;
        };
        debug!("Processing ICMP error packet from {src_vpcd}");

        // drop packet if icmp checksums are not correct
        if !icmp_checksums_ok(packet) {
            return;
        }

        // Okay, so we got an ICMP error packet from some VPC, which should include some "offending"
        // packet inside. That offending packet is something we've -presumably- sent. If we were
        // NATing (masquerading or port-forwarding), that offending packet may have addresses and/or
        // ports which we may have translated, and which differ from the original packet we mangled.
        // Now, given that we (presumably) sent the offending packet, we can't expect to find a flow
        // for it (because we modified it), but we should have a flow in the reverse direction to tell
        // us how to handle the "reply" we would get had the offending packet made it to its recipient.
        // So, here, we:
        //    1) build a flow key for the offending packet and REVERSE it
        //    2) look up the flow table for a flow in the reverse path of the offending packet.

        let flow_key = match flowkey_embedded_in_icmp_error(packet) {
            Ok(flow_key) => flow_key,
            Err(e) => {
                debug!("Could not build flow key for ICMP-error inner packet: {e}");
                packet.done(DoneReason::IcmpErrorIncomplete);
                return;
            }
        };
        // reverse the flow key and set src vpc
        let rev_flow_key = flow_key.reverse(Some(src_vpcd));

        // look up a flow in the flow table for such a key
        let Some(flow) = self.flow_table.lookup(&rev_flow_key) else {
            debug!("Found no flow for key={rev_flow_key}. Letting packet through...");
            // There is no flow for the provided flow key. This is not necessarily an error since the
            // ICMP error packet could correspond to a flow that uses static NAT or no NAT at all. It
            // could correspond to a masqueraded / port-forwarded flow that was just expired (unlikely).
            // In either case, leave the packet through so that the flow filter deals with it.
            return;
        };

        debug!("Found flow, {}", flow.logfmt());
        let flow_info_locked = flow.locked.read().unwrap();
        let Some(dst_vpcd) = flow_info_locked.dst_vpcd else {
            warn!("Flow for {rev_flow_key} has no dst VPC discriminant set. This is a bug");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        // set the dst vpcd in the packet for the flow filter to ignore the packet
        packet.meta_mut().dst_vpcd = Some(dst_vpcd);

        // process the packet depending on the flow info
        let result = if flow_info_locked.nat_state.is_some() {
            debug!("Icmp error is for vpc {dst_vpcd}. Will process with masquerade state");
            handle_icmp_error_masquerading(packet, flow.as_ref())
        } else if flow_info_locked.port_fw_state.is_some() {
            debug!("Icmp error is for vpc {dst_vpcd}. Will process with port-forwarding state");
            handle_icmp_error_port_forwarding(packet, flow.as_ref())
        } else {
            warn!("Found no NAT state to process ICMP error message. Dropping...");
            Err(DoneReason::Filtered)
        };

        // drop packet if could not translate it
        if let Err(reason) = result {
            packet.done(reason);
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
                self.handle_icmp_error_msg(&mut packet);
            }
            packet.enforce()
        })
    }
}
