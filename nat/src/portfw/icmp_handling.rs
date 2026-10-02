// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::doc_markdown)]

//! Handling of ICMP errors in port-forwarded traffic.
//! ```text
//! Sketch of ICMP error processing with port forwarding. The arrow indicates the
//! direction of the ICMP error.
//!
//!                    ICMP-error                                 ICMP-error
//!               ───┬────────────────┬─►                    ───┬────────────────┬─►
//!                  │                │                         │                │
//!              ◄───▼──                                    ◄───▼──
//!             offending packet      │                    offending packet      │
//!            (embedded in ICMP                          (embedded in ICMP
//!             error packet)         │                    error packet)         │
//!
//!                                   │                                          │
//!                     ┌──────────┐                               ┌──────────┐
//!                 ◄───┼   DNAT   │  │                        ◄───┼   SNAT   │  │
//!                     └──────────┘                               └──────────┘
//!                     ┌──────────┐  ▼                            ┌──────────┐  ▼
//!                (*)  │   SNAT   ┼───►                      (*)  │   DNAT   ┼───►
//!                     └──────────┘                               └──────────┘
//!
//! If the offending packet was port-forwarded           If the offending packet was in the reverse
//! (DNATed) we must SNAT the ICMP packet                sense of port-forwarding (was SNATed), we
//! and undo the DNATing of the innner packet.           must DNAT the ICMP packet and undo the
//!                                                      SNATing of the inner packet.
//!
//! Wether we get an ICMP error in the forward or reverse direction of port-forwarding
//! we need to treat the ICMP packet (outer) according to the rule that would be used to process
//! the traffic in the reverse direction of the offending packet.
//! ```

use net::buffer::PacketBufferMut;
use net::packet::Packet;

use super::flow_state::PortFwState;
use super::packet::{NatPacketError, nat_packet};
use crate::icmp_handler::flow_state::IcmpErrorTranslation;
use crate::{NatEndpoint, NatPort, NatTranslationData};

impl IcmpErrorTranslation for PortFwState {
    const MODE: &'static str = "port-forwarding";

    type Error = NatPacketError;

    // Translate the inner packet depending on the port-forwarding state associated to the reverse
    // flow of the offending packet.
    fn quoted_translation(&self) -> NatTranslationData {
        let endpoint =
            NatEndpoint::with_port(self.use_ip().inner(), NatPort::Port(self.use_port()));
        NatTranslationData::reverse_of(self.action, endpoint)
    }

    // NAT the ICMP packet according to the port-fw state of the reverse flow of the offending
    // packet.
    fn translate<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) -> Result<(), Self::Error> {
        nat_packet(packet, self).map(|_| ())
    }
}
