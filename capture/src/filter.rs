// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Which packets a capture records.

use crate::record::Direction;
use net::buffer::PacketBufferMut;
use net::headers::{TryHeaders, TryVxlan};
use net::packet::{Packet, VpcDiscriminant};

/// One end of a [`CaptureFilter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpcMatch {
    /// Any packet, including one with no VPC at all.
    Any,
    /// Only packets of this VPC.
    Vpc(VpcDiscriminant),
}

impl VpcMatch {
    fn matches(self, vpcd: Option<VpcDiscriminant>) -> bool {
        match self {
            VpcMatch::Any => true,
            VpcMatch::Vpc(wanted) => vpcd == Some(wanted),
        }
    }
}

/// Which packets a capture records.
///
/// Where a packet is captured decides what is known about it.
/// On ingress the packet is still encapsulated, so its VPC is the VNI of its VXLAN header and its
/// destination is not yet known.
/// On egress routing has run, so both its source and destination VPC are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFilter {
    /// Every packet, in both directions.
    Everything,
    /// Packets entering the pipeline from a VPC.
    Ingress(VpcMatch),
    /// Packets leaving the pipeline towards a VPC.
    Egress(VpcMatch),
    /// Packets going from one VPC to another.
    ///
    /// Matched at egress only: it is the first point where both ends are known.
    Conversation {
        /// The VPC the packets come from.
        from: VpcMatch,
        /// The VPC the packets go to.
        to: VpcMatch,
    },
}

impl CaptureFilter {
    /// Whether this filter records anything going in `direction`.
    pub(crate) fn includes(self, direction: Direction) -> bool {
        match self {
            CaptureFilter::Everything => true,
            CaptureFilter::Ingress(_) => direction == Direction::Ingress,
            CaptureFilter::Egress(_) | CaptureFilter::Conversation { .. } => {
                direction == Direction::Egress
            }
        }
    }

    /// Whether to record `packet`, which is going in a direction this filter [includes].
    ///
    /// [includes]: CaptureFilter::includes
    pub(crate) fn matches<Buf: PacketBufferMut>(self, packet: &Packet<Buf>) -> bool {
        let meta = packet.meta();
        match self {
            CaptureFilter::Everything => true,
            CaptureFilter::Ingress(from) => from.matches(
                packet
                    .headers()
                    .try_vxlan()
                    .map(|vxlan| VpcDiscriminant::VNI(vxlan.vni())),
            ),
            CaptureFilter::Egress(to) => to.matches(meta.dst_vpcd),
            CaptureFilter::Conversation { from, to } => {
                from.matches(meta.src_vpcd) && to.matches(meta.dst_vpcd)
            }
        }
    }
}
