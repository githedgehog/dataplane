// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Traps: where hardware leaves a packet to software.
//!
//! Contract: `notes/match-action-dag/TRAP-RESUME.md`. A trap is `(N, stamp, bytes, M_N)`: the
//! node it enters at (which has not executed), the generation it was classified under, the
//! packet as it is now, and N's declared trap-edge metadata (T1, T2). Hardware writes the node,
//! the stamp and the metadata in MARK ([`net::packet::Mark`] has the layout); no MARK is the
//! root, unstamped. Slice 1, step 4: the software side, with hardware emulated.
//!
//! A composite declares its trap targets (T6) and splits each burst by where its packets enter
//! ([`Burst::enter`]): each target's entries join that node's other inbound edges, decoded
//! under the packet's generation (T5).

use crate::burst::{Burst, Sel};
use crate::meta::State;
use net::buffer::PacketBufferMut;
use std::num::NonZero;

/// A selection split by where its packets enter ([`Burst::enter`]).
#[must_use = "entries hold packets: route each to its node"]
pub struct Entries<'b, S, const N: usize> {
    /// Not trapped: they enter at the root.
    pub root: Sel<'b, S>,
    /// Trapped at each target, in the order given.
    pub at: [Sel<'b, S>; N],
    /// Trapped at a node that is no target here.
    pub unknown: Sel<'b, S>,
}

impl<'b, Buf: PacketBufferMut> Burst<'b, Buf> {
    /// Split `sel` by where each packet enters: the root, one of the composite's trap `targets`,
    /// or an unknown node (T6: only declared targets can be entered; the caller drops the rest).
    /// One walk; with offload off nothing is trapped, and every packet is at the root.
    pub fn enter<S: State, const N: usize>(
        &self,
        sel: Sel<'b, S>,
        targets: [NonZero<u8>; N],
    ) -> Entries<'b, S, N> {
        let (mut root, mut at, mut unknown) = (0u64, [0u64; N], 0u64);
        for i in sel {
            match self.packets[i.index()].meta().trap() {
                None => root |= i.bit(),
                Some(trap) => match targets.iter().position(|t| *t == trap.node()) {
                    Some(k) => at[k] |= i.bit(),
                    None => unknown |= i.bit(),
                },
            }
        }
        Entries {
            root: Sel::new(root),
            at: at.map(Sel::new),
            unknown: Sel::new(unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use net::packet::{Bank, Mark, MarkError, Stamp, Trap};
    use std::num::NonZero;

    #[test]
    fn every_trap_survives_its_mark() {
        bolero::check!()
            .with_type::<(u8, u16, bool, u64)>()
            .for_each(|&(node, payload, bank, generation)| {
                let trap = NonZero::new(node % Mark::RESERVED_NODE)
                    .map(|node| Trap::new(node, payload & Mark::PAYLOAD_MAX));
                let stamp = Stamp::new(if bank { Bank::B } else { Bank::A }, generation);
                let mark = Mark::new(stamp, trap);
                let bits = mark.to_bits();
                assert!(
                    bits <= 0x00ff_ffef,
                    "MARK {bits:#x} in the PMD's reserved range"
                );
                assert_eq!(Mark::from_bits(bits), Ok(mark));
                assert_eq!((mark.stamp(), mark.trap()), (stamp, trap));
            });
    }

    #[test]
    fn every_mark_decodes_or_is_refused() {
        bolero::check!()
            .with_type::<u32>()
            .for_each(|&bits| match Mark::from_bits(bits) {
                Ok(mark) => {
                    assert_eq!(mark.to_bits(), bits);
                    assert_eq!(Mark::new(mark.stamp(), mark.trap()), mark);
                }
                Err(MarkError::Reserved) => assert!(bits >> 19 >= 31),
                Err(MarkError::RootPayload) => {
                    assert_eq!(bits >> 19, 0);
                    assert_ne!(bits & u32::from(Mark::PAYLOAD_MAX), 0);
                }
            });
    }

    #[test]
    fn a_stamp_survives_its_nibble() {
        for bank in [Bank::A, Bank::B] {
            for generation in 0..64 {
                let stamp = Stamp::new(bank, generation);
                assert_eq!(Stamp::from_nibble(stamp.to_nibble()), stamp);
                assert_eq!(stamp.bank(), bank);
            }
        }
    }
}
