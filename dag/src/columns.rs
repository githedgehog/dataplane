// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Presence columns: per burst, which packets carry each kind, built by walking the packets.
//!
//! Kinds live in [`PacketMeta`](net::packet::PacketMeta) fields, shared with legacy stages, so
//! nothing is copied in or out of typed code. What a composite needs is presence as one bitset per
//! kind, so that guards are bit operations: built once when a burst enters (fused with the walk
//! that picks the live packets), and rebuilt, for the kinds it declares, after a hosted legacy
//! stage (fused with the walk that finds its drops). Typed writes keep the columns in step.

use crate::burst::Burst;
use crate::meta::kind;
use crate::presence::Presence;
use net::buffer::PacketBufferMut;
use net::packet::Packet;

/// The packets of `bits`, lowest index first.
fn indices(mut bits: u64) -> impl Iterator<Item = usize> {
    std::iter::from_fn(move || {
        if bits == 0 {
            return None;
        }
        let index = bits.trailing_zeros() as usize;
        bits &= bits - 1;
        Some(index)
    })
}

impl<Buf: PacketBufferMut> Burst<'_, Buf> {
    /// One walk over the packets of `bits`: rebuild the columns of `kinds` for all of them, and
    /// return those for which `pred` holds.
    #[inline]
    pub(crate) fn walk(
        &mut self,
        bits: u64,
        kinds: Presence,
        mut pred: impl FnMut(&Packet<Buf>) -> bool,
    ) -> u64 {
        let mut columns = [0u64; kind::COUNT];
        let mut held = 0u64;
        for index in indices(bits) {
            let packet = &self.packets[index];
            held |= u64::from(pred(packet)) << index;
            transpose(&mut columns, kind::presence(packet.meta()), index);
        }
        self.store(bits, kinds, columns);
        held
    }

    /// One walk over the packets of `bits`: return those for which `pred` holds, and rebuild the
    /// columns of `kinds` for those only.
    #[inline]
    pub(crate) fn walk_where(
        &mut self,
        bits: u64,
        kinds: Presence,
        mut pred: impl FnMut(&Packet<Buf>) -> bool,
    ) -> u64 {
        let mut columns = [0u64; kind::COUNT];
        let mut held = 0u64;
        for index in indices(bits) {
            let packet = &self.packets[index];
            if pred(packet) {
                held |= 1 << index;
                transpose(&mut columns, kind::presence(packet.meta()), index);
            }
        }
        self.store(held, kinds, columns);
        held
    }

    fn store(&mut self, bits: u64, kinds: Presence, columns: [u64; kind::COUNT]) {
        for (k, column) in columns.into_iter().enumerate() {
            if u64::from(kinds.bits()) >> k & 1 == 1 {
                self.columns[k] = (self.columns[k] & !bits) | column;
            }
        }
    }

    /// Check that the columns of `kinds` agree with the packets of `bits`.
    #[cfg(debug_assertions)]
    pub(crate) fn check_columns(&self, bits: u64, kinds: Presence) {
        for index in indices(bits) {
            let present = kind::presence(self.packets[index].meta());
            for (k, column) in self.columns.iter().enumerate() {
                if u64::from(kinds.bits()) >> k & 1 == 1 {
                    assert_eq!(
                        u64::from(present.bits()) >> k & 1,
                        column >> index & 1,
                        "packet {index}: kind {k} changed presence outside typed code, undeclared"
                    );
                }
            }
        }
    }
}

/// Note one packet's presence word in per-kind columns.
#[inline]
fn transpose(columns: &mut [u64; kind::COUNT], present: Presence, index: usize) {
    let present = u64::from(present.bits());
    for (k, column) in columns.iter_mut().enumerate() {
        *column |= (present >> k & 1) << index;
    }
}
