// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bits of an ICMP header that its parsed message type does not keep.

use crate::checksum::incremental_update;

/// The bits of an ICMP header's bytes 4 to 7 that its parsed message type does not keep.
///
/// etherparse models those bytes per message type and writes zeros for whatever it does not
/// model: the RFC 4884 length, reserved bytes, flags it does not know. A header must leave as it
/// arrived, or its checksum stops matching it, so these bits go back when the header is written.
/// They go back only while the header keeps the type and code it arrived with: a stage that
/// changes those rewrites the whole header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DroppedBits {
    type_and_code: [u8; 2],
    bits: [u8; 4],
}

impl DroppedBits {
    /// Compare a header as it arrived with what its parsed message type writes.
    pub(crate) fn new(arrived: &[u8], modeled: &[u8]) -> DroppedBits {
        let (Some(arrived), Some(modeled)) =
            (arrived.first_chunk::<8>(), modeled.first_chunk::<8>())
        else {
            return DroppedBits::default();
        };
        let bits = std::array::from_fn(|i| arrived[4 + i] ^ modeled[4 + i]);
        if bits == [0; 4] {
            return DroppedBits::default();
        }
        DroppedBits {
            type_and_code: [modeled[0], modeled[1]],
            bits,
        }
    }

    /// Put the dropped bits back into a header written by its parsed message type.
    pub(crate) fn restore(self, header: &mut [u8]) {
        let Some(header) = header.first_chunk_mut::<8>() else {
            return;
        };
        if header[..2] != self.type_and_code {
            return;
        }
        for (byte, bits) in header[4..].iter_mut().zip(self.bits) {
            *byte ^= bits;
        }
    }

    /// Adjust a checksum computed over a header written by its parsed message type to cover the
    /// dropped bits too.
    ///
    /// Only words that differ are folded in: folding in a word that did not change would turn the
    /// `0xffff` of all-zero data into `0x0000`.
    pub(crate) fn adjust(self, checksum: u16, modeled: &[u8]) -> u16 {
        let Some(modeled) = modeled.first_chunk::<8>() else {
            return checksum;
        };
        let mut restored = *modeled;
        self.restore(&mut restored);
        [4, 6].into_iter().fold(checksum, |checksum, i| {
            let old = u16::from_be_bytes([modeled[i], modeled[i + 1]]);
            let new = u16::from_be_bytes([restored[i], restored[i + 1]]);
            if old == new {
                checksum
            } else {
                incremental_update(checksum, old, new)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::DroppedBits;

    #[test]
    fn bits_go_back_only_under_the_type_and_code_they_arrived_with() {
        bolero::check!()
            .with_type::<([u8; 8], [u8; 8], [u8; 2])>()
            .for_each(|(arrived, modeled, other)| {
                // The type, code and checksum are modeled exactly.
                let mut modeled = *modeled;
                modeled[..4].copy_from_slice(&arrived[..4]);
                let dropped = DroppedBits::new(arrived, &modeled);
                let mut written = modeled;
                dropped.restore(&mut written);
                assert_eq!(written, *arrived);

                let mut retyped = modeled;
                retyped[..2].copy_from_slice(other);
                let mut written = retyped;
                dropped.restore(&mut written);
                if *other == arrived[..2] {
                    assert_eq!(written, *arrived);
                } else {
                    assert_eq!(written, retyped);
                }
            });
    }

    #[test]
    fn a_header_written_as_it_arrived_drops_nothing() {
        bolero::check!().with_type::<[u8; 8]>().for_each(|arrived| {
            assert_eq!(DroppedBits::new(arrived, arrived), DroppedBits::default());
        });
    }
}
