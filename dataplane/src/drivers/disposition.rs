// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a driver does with a packet the pipeline has finished with: transmit it, punt it to the
//! kernel, or drop it.

use net::buffer::PacketBufferMut;
use net::packet::{DoneReason, Packet};
use tracing::error;

/// How a driver should treat a packet output by the pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Transmit it on the interface the pipeline chose.
    Transmit,
    /// Hand it to the kernel through the tap of the port it arrived on.
    Punt,
    /// Free it.
    Drop,
}

/// Map a pipeline verdict to what the driver does with the packet.
///
/// Only `Local` reaches the control plane; every other verdict except `Delivered` is dropped.
impl From<DoneReason> for Disposition {
    fn from(done: DoneReason) -> Self {
        // Exhaustive on purpose. A new `DoneReason` is a new decision about whether the kernel
        // should see that packet, and this is where it has to be made; a wildcard would answer
        // "no" silently.
        match done {
            DoneReason::Delivered => Disposition::Transmit,
            DoneReason::Local => Disposition::Punt,

            // Decisions the datapath made, and failures the kernel cannot do anything about.
            DoneReason::Unhandled
            | DoneReason::NotIp
            | DoneReason::RouteFailure
            | DoneReason::InternalFailure
            | DoneReason::InterfaceUnknown
            | DoneReason::InterfaceDetached
            | DoneReason::InterfaceAdmDown
            | DoneReason::InterfaceOperDown
            | DoneReason::InterfaceUnsupported
            | DoneReason::NotEthernet
            | DoneReason::MacNotForUs
            | DoneReason::InvalidDstMac
            | DoneReason::MissingEtherType
            | DoneReason::RouteDrop
            | DoneReason::HopLimitExceeded
            | DoneReason::MissL2resolution
            | DoneReason::VxlanDecapFailure
            | DoneReason::VxlanEncapFailure
            | DoneReason::VxlanNotForUs
            | DoneReason::Filtered
            | DoneReason::AclDropped
            | DoneReason::NatOutOfResources
            | DoneReason::FlowCapacityExceeded
            | DoneReason::NatUnsupportedProto
            | DoneReason::NatFailure
            | DoneReason::NatNotPortForwarded
            | DoneReason::Malformed
            | DoneReason::Unroutable
            | DoneReason::InvalidChecksum
            | DoneReason::IcmpErrorIncomplete
            | DoneReason::InternalDrop
            | DoneReason::DeparseError
            | DoneReason::NoHeadRoom => Disposition::Drop,
        }
    }
}

impl Disposition {
    /// Determine the disposition of a packet given its `DoneReason`.
    /// If no `DoneReason` has been set (that's a bug), drop the packet.
    pub(crate) fn of<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Self {
        packet.get_done().map_or_else(
            || {
                error!("Packet returned without a terminal verdict; dropping it (pipeline bug)");
                Disposition::Drop
            },
            Disposition::from,
        )
    }
}

#[cfg(test)]
mod test {
    use super::Disposition;
    use net::packet::DoneReason;
    use net::packet::test_utils::build_test_ipv4_packet;
    use strum::EnumCount as _;

    /// The whole punt policy, verdict by verdict.
    ///
    /// Written out rather than derived from [`Disposition::from`] on purpose: a test that recomputed the
    /// policy would agree with any policy at all. This is the statement of what the control plane
    /// is entitled to see, and changing [`Disposition::from`] should have to change it here too.
    ///
    /// Break-tested: inverting any single arm below (say, making `AclDropped` punt, or making
    /// `Local` drop) fails this test.
    // The table below is data, not logic: every arm is one verdict, and the point is that all of
    // them are written out. Splitting it to satisfy a line count would only hide that.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn punt_policy_table() {
        // (verdict, disposition)
        let table: &[(DoneReason, Disposition)] = &[
            // The pipeline forwarded it.
            (DoneReason::Delivered, Disposition::Transmit),
            // The pipeline said so explicitly: the only verdict that reaches the control plane.
            (DoneReason::Local, Disposition::Punt),
            // Everything else is a decision the datapath already made.
            (DoneReason::Unhandled, Disposition::Drop),
            (DoneReason::NotIp, Disposition::Drop),
            (DoneReason::RouteFailure, Disposition::Drop),
            (DoneReason::InternalFailure, Disposition::Drop),
            (DoneReason::InterfaceUnknown, Disposition::Drop),
            (DoneReason::InterfaceDetached, Disposition::Drop),
            (DoneReason::InterfaceAdmDown, Disposition::Drop),
            (DoneReason::InterfaceOperDown, Disposition::Drop),
            (DoneReason::InterfaceUnsupported, Disposition::Drop),
            (DoneReason::NotEthernet, Disposition::Drop),
            (DoneReason::MacNotForUs, Disposition::Drop),
            (DoneReason::InvalidDstMac, Disposition::Drop),
            (DoneReason::MissingEtherType, Disposition::Drop),
            (DoneReason::RouteDrop, Disposition::Drop),
            (DoneReason::HopLimitExceeded, Disposition::Drop),
            (DoneReason::MissL2resolution, Disposition::Drop),
            (DoneReason::VxlanDecapFailure, Disposition::Drop),
            (DoneReason::VxlanEncapFailure, Disposition::Drop),
            (DoneReason::VxlanNotForUs, Disposition::Drop),
            (DoneReason::Filtered, Disposition::Drop),
            (DoneReason::AclDropped, Disposition::Drop),
            (DoneReason::NatOutOfResources, Disposition::Drop),
            (DoneReason::FlowCapacityExceeded, Disposition::Drop),
            (DoneReason::NatUnsupportedProto, Disposition::Drop),
            (DoneReason::NatFailure, Disposition::Drop),
            (DoneReason::NatNotPortForwarded, Disposition::Drop),
            (DoneReason::Malformed, Disposition::Drop),
            (DoneReason::Unroutable, Disposition::Drop),
            (DoneReason::InvalidChecksum, Disposition::Drop),
            (DoneReason::IcmpErrorIncomplete, Disposition::Drop),
            (DoneReason::InternalDrop, Disposition::Drop),
            (DoneReason::DeparseError, Disposition::Drop),
            (DoneReason::NoHeadRoom, Disposition::Drop),
        ];

        for (verdict, expected) in table {
            assert_eq!(
                Disposition::from(*verdict),
                *expected,
                "wrong disposition for {verdict:?}"
            );
        }

        // The table has to name every verdict, not merely the interesting ones. Without this a
        // verdict added later would default to whatever the policy's author decided, with no
        // test asserting that the control plane was considered at all.
        assert_eq!(
            table.len(),
            DoneReason::COUNT,
            "the punt policy table has drifted from `DoneReason`: every verdict is a decision \
             about whether the control plane may see that packet, so a new one has to be made \
             here as well as in `From<DoneReason> for Disposition`"
        );
    }

    #[test]
    fn a_packet_with_no_verdict_is_dropped() {
        let packet = build_test_ipv4_packet(64).unwrap();
        assert_eq!(packet.get_done(), None);
        assert_eq!(Disposition::of(&packet), Disposition::Drop);
    }
}
