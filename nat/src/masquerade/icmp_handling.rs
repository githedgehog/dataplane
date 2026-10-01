// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Handling of ICMP errors in masquerade

use crate::NatTranslationData;
use crate::icmp_handler::flow_state::IcmpErrorTranslation;
use crate::masquerade::packet::{NatPacketError, masquerade};
use crate::masquerade::state::MasqueradeState;
use net::buffer::PacketBufferMut;
use net::packet::Packet;

impl IcmpErrorTranslation for MasqueradeState {
    const MODE: &'static str = "masquerade";

    type Error = NatPacketError;

    fn quoted_translation(&self) -> NatTranslationData {
        self.reverse_translation_data()
    }

    fn translate<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) -> Result<(), Self::Error> {
        masquerade(packet, &self.as_translate())
    }
}
