// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a port advertises, and the frames that carry it.

use net::eth::Eth;
use net::eth::mac::{DestinationMac, SourceMac};
use net::lldp::{
    ChassisId, ETHTYPE, Lldpdu, LldpduTooLong, NEAREST_BRIDGE, OptionalTlv, PortId, TimeToLive,
};
use net::parse::DeParse;

/// The shortest Ethernet frame, without its frame check sequence.
///
/// Shorter frames are padded with zeroes, which an LLDP parser ignores after the end marker.
const MIN_FRAME_LEN: usize = 60;

/// Everything one port advertises.
///
/// Built once per change, then turned into frames for as long as it is current.
/// Construction is where an advertisement too long for one frame is refused, so building a frame from
/// one never fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    source: SourceMac,
    pdu: Lldpdu,
}

impl Advertisement {
    /// Advertise `chassis` and `port` with the `optional` TLVs, from the port whose MAC is `source`.
    ///
    /// # Errors
    ///
    /// Fails if the LLDPDU would not fit in one frame.
    pub fn new(
        source: SourceMac,
        chassis: ChassisId,
        port: PortId,
        optional: impl IntoIterator<Item = OptionalTlv>,
    ) -> Result<Advertisement, LldpduTooLong> {
        // The time to live is fixed length, so the placeholder sizes the LLDPDU exactly.
        let mut pdu = Lldpdu::new(chassis, port, TimeToLive::new(0));
        for tlv in optional {
            pdu.try_push(tlv)?;
        }
        Ok(Advertisement { source, pdu })
    }

    /// The LLDPDU this advertises; its time to live is a placeholder, set per frame.
    #[must_use]
    pub fn lldpdu(&self) -> &Lldpdu {
        &self.pdu
    }

    /// Whether `other` advertises the same chassis and port.
    ///
    /// A neighbour keys what it has heard on these two, so changing either one is, to the neighbour,
    /// a new neighbour rather than news about an old one.
    pub(crate) fn same_identity(&self, other: &Advertisement) -> bool {
        self.pdu.chassis_id() == other.pdu.chassis_id() && self.pdu.port_id() == other.pdu.port_id()
    }

    /// The frame that advertises this, valid for `ttl`.
    #[must_use]
    pub fn frame(&self, ttl: TimeToLive) -> Vec<u8> {
        let mut pdu = self.pdu.clone();
        pdu.set_ttl(ttl);
        self.frame_of(&pdu)
    }

    /// The frame that tells neighbours to forget this now.
    ///
    /// IEEE 802.1AB-2016 §9.2.7.7: a shutdown LLDPDU carries only the mandatory TLVs, with a time to live
    /// of zero.
    pub(crate) fn shutdown_frame(&self) -> Vec<u8> {
        let pdu = Lldpdu::new(
            self.pdu.chassis_id().clone(),
            self.pdu.port_id().clone(),
            TimeToLive::new(0),
        );
        self.frame_of(&pdu)
    }

    fn frame_of(&self, pdu: &Lldpdu) -> Vec<u8> {
        let destination =
            DestinationMac::new(NEAREST_BRIDGE).unwrap_or_else(|_| unreachable!("a group address"));
        let eth = Eth::new(self.source, destination, ETHTYPE);
        let len = usize::from(eth.size().get()) + usize::from(pdu.size().get());
        let mut frame = vec![0; len.max(MIN_FRAME_LEN)];
        let written = eth
            .deparse(&mut frame)
            .unwrap_or_else(|e| unreachable!("the frame is sized for its headers: {e:?}"));
        pdu.deparse(&mut frame[usize::from(written.get())..])
            .unwrap_or_else(|e| unreachable!("the frame is sized for its LLDPDU: {e:?}"));
        frame
    }
}
