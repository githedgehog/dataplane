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

/// Convert/Map `DoneReqason` to `Disposition`
impl From<DoneReason> for Disposition {
    fn from(done: DoneReason) -> Self {
        match done {
            DoneReason::Delivered => Disposition::Transmit,
            DoneReason::Local => Disposition::Punt,
            _ => Disposition::Drop,
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
    use strum::IntoEnumIterator as _;

    /// The whole punt policy: the pipeline's forwarding verdict is transmitted, `Local` reaches
    /// the control plane, and every other verdict -- including any added later -- is dropped.
    ///
    /// Written out rather than derived from [`Disposition::from`] on purpose: a test that
    /// recomputed the policy would agree with any policy at all.
    ///
    /// Break-tested: making any verdict other than `Local` punt (say, `AclDropped`), or making
    /// `Local` drop, fails this test.
    #[test]
    fn punt_policy_table() {
        for verdict in DoneReason::iter() {
            let expected = match verdict {
                DoneReason::Delivered => Disposition::Transmit,
                DoneReason::Local => Disposition::Punt,
                _ => Disposition::Drop,
            };
            assert_eq!(
                Disposition::from(verdict),
                expected,
                "wrong disposition for {verdict:?}"
            );
        }
    }

    #[test]
    fn a_packet_with_no_verdict_is_dropped() {
        let packet = build_test_ipv4_packet(64).unwrap();
        assert_eq!(packet.get_done(), None);
        assert_eq!(Disposition::of(&packet), Disposition::Drop);
    }
}
