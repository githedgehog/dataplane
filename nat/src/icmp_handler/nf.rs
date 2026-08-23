// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A network function to process icmp error packets in the overlay
//! if those correspond to port-forwarding or masquerading

use flow_entry::flow_table::FlowTable;
use net::buffer::PacketBufferMut;
use net::headers::{EmbeddedTransport, TryEmbeddedTransport, TryIcmpAny};
use net::icmp_any::IcmpAny;
use net::icmp4::{Icmp4DestUnreachable, Icmp4Type};
use net::icmp6::Icmp6Type;
use net::packet::icmp_err::IcmpErrorPacket;
use net::packet::{DoneReason, Packet};

use concurrency::sync::Arc;
use pipeline::NetworkFunction;
use strum::EnumMessage;
use tracectl::trace_target;
use tracing::{debug, warn};

use crate::common::NatFlowStatus;
use crate::masquerade::icmp_handling::handle_icmp_error_masquerading;
use crate::portfw::icmp_handling::handle_icmp_error_port_forwarding;

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

/// Tell if the given ICMP error packet is "unrecoverable" in the sense that any flow related to it *may*
/// be removed because the source may no longer send packets after receiving the error message.
fn is_icmp_unrecoverable<Buf: PacketBufferMut>(packet: &mut Packet<Buf>) -> (bool, Option<&str>) {
    let Some(icmp) = packet.try_icmp_any() else {
        return (false, None);
    };
    debug_assert!(icmp.is_error_message());
    match icmp {
        IcmpAny::V4(icmp4) if let Icmp4Type::DestUnreachable(unreach) = icmp4.icmp_type() => {
            let unrec = !matches!(unreach, Icmp4DestUnreachable::FragmentationNeeded { .. });
            (unrec, unreach.get_message())
        }
        IcmpAny::V6(icmp6) if let Icmp6Type::DestUnreachable(unreach) = icmp6.icmp_type() => {
            (true, unreach.get_message())
        }
        // Not `unrecoverable`, and neither is the fallback below, so this arm decides nothing --
        // it names the reason for the log line. Its guard is therefore an equivalent mutant in
        // both directions, and that is a property of the shape rather than a gap: IPv6 splits
        // Path MTU Discovery out into its own type, where IPv4 hides it in a Destination
        // Unreachable code that the arm above has to look at.
        IcmpAny::V6(icmp6) if let Icmp6Type::PacketTooBig(_) = icmp6.icmp_type() => {
            (false, Some("Packet too big"))
        }
        _ => (false, None),
    }
}

/// Tell whether the offending packet embedded in this ICMP error is itself an ICMP Query -- an
/// Echo or a Timestamp, or either of their replies.
///
/// This is the narrowest thing whose mutation would violate REQ-6: the invalidation below is the
/// only place the ICMP path deletes a NAT Session, and this predicate is the only thing standing
/// between it and a Query session. The requirement exists because an ICMP error is trivial to
/// spoof, and the session it names is one an attacker chose; deleting it on request hands them a
/// way to break a ping they cannot see, and -- since masquerade releases the allocation with the
/// flow -- a way to churn the port pool.
///
/// Scoped to Query payloads because that is the scope of the requirement. RFC 5382 leaves the
/// same question open for TCP ("NAT behavior for handling RST packets ... is left unspecified"),
/// so the optimization stands for TCP and UDP.
//= https://www.rfc-editor.org/rfc/rfc5508#section-4.3
//# REQ-6: While processing an ICMP Error packet pertaining to an ICMP
//# Query or Query response message, a NAT device MUST NOT refresh
//# or delete the NAT Session that pertains to the embedded
//# payload within the ICMP Error packet.
fn embeds_icmp_query<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    match packet.try_embedded_transport() {
        Some(EmbeddedTransport::Icmp4(icmp4)) => icmp4.is_query_message(),
        Some(EmbeddedTransport::Icmp6(icmp6)) => icmp6.is_query_message(),
        _ => false,
    }
}

impl IcmpErrorHandler {
    fn handle_icmp_error_msg<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) {
        let Some(icmp_error_packet) = IcmpErrorPacket::new(packet) else {
            debug!("Dropping ICMP error packet: could not parse it as ICMP error");
            packet.done(DoneReason::IcmpErrorIncomplete);
            return;
        };

        // check origin of icmp error packet
        let Some(src_vpcd) = packet.meta().src_vpcd else {
            debug!("Dropping ICMP error packet: no src vpc discriminant");
            packet.done(DoneReason::Unroutable);
            return;
        };
        debug!("Processing ICMP error packet from {src_vpcd}");

        // From REQ-3 from RFC 5508, "NAT Behavioral Requirements for ICMP".
        // NAT should silently discard packet if:
        //
        //    - ICMP checksum fails to validate
        //    - ICMP checksum for embedded packet fails to validate
        //
        // Drop packet if ICMP checksums are not correct
        if let Err(e) = icmp_error_packet.validate_checksums() {
            debug!("Checksum validation failed for ICMP packet: {e}");
            packet.done(DoneReason::InvalidChecksum);
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

        let flow_key = match icmp_error_packet.embedded_flowkey() {
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

        // if the inner packet matched a flow, but it is not active, drop the ICMP error packet.
        // This should very seldom happen as flows stay very little in the flow table once no longer valid.
        if !flow.is_active() {
            debug!("Matched flow is not active. Dropping ICMP error packet");
            packet.done(DoneReason::Filtered);
            return;
        }

        // Read what is needed and release the lock *before* dispatching, rather than holding the
        // guard across the call.
        //
        // Both handlers take `flow_info.locked.read()` themselves, and so does the `Display` for
        // the `logfmt()` in their debug lines, so a guard held across the call is a recursive read
        // on the same `RwLock`. `parking_lot` does not make that safe: a writer arriving between
        // the two acquisitions is served first, and the inner read then waits on a writer that is
        // waiting on the guard this thread already holds. Writers on this very lock are ordinary
        // data-path traffic -- `masquerade::nf` and `portfw::nf` take one per packet they handle --
        // so the window needs only an ICMP error about a flow that is still sending.
        //
        // Worse, one of the two acquisitions is a *log line*, so the deadlock appears when tracing
        // is turned up and not otherwise. Compare the reentrancy note on `dpdk::acl::context`.
        //
        // Found by `dataplane::packet_processor::fuzz::model::
        // an_icmp_teardown_leaves_another_workers_flow_alone` under shuttle, which refuses a
        // recursive acquisition outright. Real threads had passed it every time.
        //
        // The snapshot means the state could change before the handler re-reads it. That is not a
        // new race and not a worse one: the handlers already treat a missing NAT state as an error
        // rather than assuming the caller's view still holds.
        let (dst_vpcd, masquerading, port_forwarding) = {
            let flow_info_locked = flow.locked.read();
            (
                flow_info_locked.dst_vpcd,
                flow_info_locked.nat_state.is_some(),
                flow_info_locked.port_fw_state.is_some(),
            )
        };

        let Some(dst_vpcd) = dst_vpcd else {
            warn!("Flow for {rev_flow_key} has no dst VPC discriminant set. This is a bug");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        // set the dst vpcd in the packet for the flow filter to ignore the packet
        packet.meta_mut().dst_vpcd = Some(dst_vpcd);

        // process the packet depending on the flow info
        let result = if masquerading {
            debug!("Icmp error is for vpc {dst_vpcd}. Will process with masquerade state");
            handle_icmp_error_masquerading(packet, flow.as_ref())
        } else if port_forwarding {
            debug!("Icmp error is for vpc {dst_vpcd}. Will process with port-forwarding state");
            handle_icmp_error_port_forwarding(packet, flow.as_ref())
        } else {
            warn!("Found no NAT state to process ICMP error message. Dropping...");
            Err(DoneReason::Filtered)
        };

        // drop packet if could not translate it
        let status = match result {
            Ok(status) => status,
            Err(reason) => {
                packet.done(reason);
                return;
            }
        };

        // If processing the ICMP error succeeded, drop the flows associated to the offending packet
        // if the problem is hardly recoverable. This expedites removing those flows, which would probably
        // be never hit again and, in case of masquerading, releases the allocated ports sooner.
        // This optimization is only applied if the `NatFlowStatus` is one-way.
        // Read before `is_icmp_unrecoverable`, which borrows the packet mutably and hands back a
        // reason string that keeps the borrow alive to the end of the block.
        let embeds_query = embeds_icmp_query(packet);
        let (unrecoverable, reason) = is_icmp_unrecoverable(packet);
        let reason = reason.unwrap_or("unspecified");
        if unrecoverable && status == NatFlowStatus::OneWay && !embeds_query {
            debug!("Invalidating flows due to ICMP error (reason={reason} flow-status={status})");
            flow.invalidate_pair();
        } else {
            debug!("Will not invalidate flows (reason={reason} flow-status={status})");
        }

        // We may also need to apply static NAT to the packet, if static NAT is used on the other
        // end of the peering.
        packet.meta_mut().set_static_nat_src(true);
        packet.meta_mut().set_static_nat_dst(true);
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
