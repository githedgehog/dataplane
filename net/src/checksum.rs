// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Traits for checksum calculation and manipulation

use std::fmt::Debug;

/// A trait for checksum calculation and manipulation.
///
/// This trait is used to calculate and manipulate checksums in various headers.
pub trait Checksum {
    /// The error type for the header.
    ///
    /// This is used to represent the error type in case of failure.
    type Error;
    /// The payload type for the header.
    ///
    /// This is used to calculate the checksum.
    type Payload<'a>: ?Sized
    where
        Self: 'a;
    /// The checksum type.
    ///
    /// This is used to represent the checksum value.
    type Checksum: Eq + Copy + Sized + Debug + From<u16> + Into<u16>;

    /// Get the checksum value from the header
    ///
    /// # Returns
    ///
    /// Returns `None` if the checksum is not present.
    fn checksum(&self) -> Option<Self::Checksum>;

    /// Compute the checksum value from the header and payload
    ///
    /// # Errors
    ///
    /// Returns a [`ChecksumError`] if checksum computation fails.
    fn compute_checksum(&self, payload: &Self::Payload<'_>) -> Result<Self::Checksum, Self::Error>;

    /// Set the checksum value in the header.
    ///
    /// # Safety
    ///
    /// The validity of the checksum is not checked.
    ///
    /// The contract of the [`Checksum`] trait _does not_ require that the implementation of this
    /// function be free of panics.
    /// "Normal" input should never cause this trait to panic, but truly exceptional conditions
    /// such as wildly out of the ordinary MTU values (e.g., 2^32) may not be possible to handle
    /// without a panic.
    ///
    /// # Errors
    ///
    /// Returns a [`ChecksumError`] if checksum computation fails or if the checksum is invalid.
    fn set_checksum(&mut self, checksum: Self::Checksum) -> Result<&mut Self, Self::Error>;

    /// Validate the checksum value in the header.
    ///
    /// # Errors
    ///
    /// Returns a [`ChecksumError`] if checksum computation fails or if the checksum is invalid.
    fn validate_checksum(
        &self,
        payload: &Self::Payload<'_>,
    ) -> Result<Self::Checksum, ChecksumError<Self>> {
        let checksum_result = self.compute_checksum(payload);
        let expected = match checksum_result {
            Ok(checksum) => checksum,
            Err(error) => return Err(ChecksumError::Compute { error }),
        };
        let Some(actual) = self.checksum() else {
            return Err(ChecksumError::NotPresent);
        };
        if expected == actual {
            Ok(expected)
        } else {
            Err(ChecksumError::Mismatch { expected, actual })
        }
    }

    /// Update the checksum value in the header.
    ///
    /// The post-condition of this function is that the checksum is valid.
    /// I.e., the `validate_checksum` function will not return an `Err` variant when given the same
    /// value for `payload` as was passed into this function.
    ///
    /// # Errors
    ///
    /// Returns a [`ChecksumError`] if checksum computation fails, if setting the checksum fails,
    /// or if the checksum is invalid.
    fn update_checksum(&mut self, payload: &Self::Payload<'_>) -> Result<&mut Self, Self::Error> {
        let ret = self.set_checksum(self.compute_checksum(payload)?)?;
        #[cfg(debug_assertions)]
        #[allow(clippy::panic)] // this is basically a debug_assert
        match ret.validate_checksum(payload) {
            Ok(_) => {}
            Err(ChecksumError::Mismatch { expected, actual }) => {
                panic!(
                    "checksum implementation is faulty: expected: {expected:?}, actual: {actual:?}",
                );
            }
            Err(ChecksumError::Compute { error }) => {
                return Err(error);
            }
            Err(ChecksumError::NotPresent) => {
                unreachable!() // We managed to compute the checksum at the beginning of the function
            }
        }
        Ok(ret)
    }

    /// Perform an incremental update of the checksum in the header, to account for the change of a
    /// 16-bit value in the header, without recomputing the whole checksum but using the algorithm
    /// described in RFC 1624 "Computation of the Internet Checksum via Incremental Update"
    //
    // Implement this as a default method rather than relying on individual's Self::Checksum types
    // implementations, because etherparse currendly doesn't offer a way to compute incremental
    // updates for checksums.
    fn increment_update_checksum(
        &mut self,
        current_checksum: Self::Checksum,
        old_value: u16,
        new_value: u16,
    ) -> Self::Checksum {
        // From RFC 1624:
        //
        // Given the following notation:
        //
        //     HC  - old checksum in header
        //     C   - one's complement sum of old header
        //     HC' - new checksum in header
        //     C'  - one's complement sum of new header
        //     m   - old value of a 16-bit field
        //     m'  - new value of a 16-bit field
        //
        // [...]
        //
        //     HC' = ~(C + (-m) + m')    --    [Eqn. 3]
        //         = ~(~HC + ~m + m')
        //
        // [...] the two additional instructions can be eliminated by subtracting complements with
        // borrow [...]:
        //
        //     HC' = HC - ~m - m'    --    [Eqn. 4]

        incremental_update(current_checksum.into(), old_value, new_value).into()
    }
}

/// An error resulting from a checksum mismatch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChecksumError<T: Checksum + ?Sized> {
    /// The checksum in the header does not match the computed checksum.
    #[error("checksum mismatch: expected {expected:?}, actual {actual:?}")]
    Mismatch {
        /// The expected (computed) checksum.
        expected: T::Checksum,
        /// The actual checksum in the header.
        actual: T::Checksum,
    },
    /// The checksum computation failed.
    #[error("checksum computation failed: {error:?}")]
    Compute {
        /// The error that occurred during checksum computation.
        error: T::Error,
    },
    /// The checksum is not present in the header.
    #[error("checksum not present")]
    NotPresent,
}

/// One's-complement sum of `bytes` as big-endian 16-bit words, an odd octet padded with zero. It is
/// `0` only for all-zero `bytes`. Over everything a checksum covers, the checksum included, it is
/// `0xffff` when the checksum is valid.
#[must_use]
pub fn ones_complement_sum(bytes: &[u8]) -> u16 {
    // Convert etherparse's native-endian sum to network byte order.
    !etherparse::checksum::Sum16BitWords::new()
        .add_slice(bytes)
        .ones_complement()
        .to_be()
}

/// RFC 1624 Eqn. 4: the checksum `current` becomes once a 16-bit field it covers changes from
/// `old_value` to `new_value`, computed as `HC - ~m - m'` with end-around borrows.
#[must_use]
pub(crate) fn incremental_update(current: u16, old_value: u16, new_value: u16) -> u16 {
    // First subtraction: HC - ~m
    let (mut tmp, borrow) = current.overflowing_sub(!old_value);
    if borrow {
        tmp = tmp.wrapping_sub(1);
    }

    // Second subtraction: tmp - m'
    let (mut result, borrow) = tmp.overflowing_sub(new_value);
    if borrow {
        result = result.wrapping_sub(1);
    }
    result
}

/// A reference model of one's-complement arithmetic (RFC 1071), for proofs.
///
/// [`ones_complement_sum`] is proven to agree with [`model::sum`], so proofs elsewhere can state
/// what a checksum covers in terms of the model, without pushing etherparse's 64-bit accumulator
/// through the solver for every header.
#[cfg(kani)]
pub(crate) mod model {
    /// One's-complement addition: add, then fold the carry back in.
    #[allow(clippy::cast_possible_truncation)] // the folded sum fits in 16 bits
    pub(crate) fn add(a: u16, b: u16) -> u16 {
        let sum = u32::from(a) + u32::from(b);
        ((sum & 0xffff) + (sum >> 16)) as u16
    }

    /// The one's-complement sum of `bytes` as big-endian 16-bit words, an odd octet padded with
    /// zero.
    pub(crate) fn sum(bytes: &[u8]) -> u16 {
        bytes.chunks(2).fold(0, |sum, word| {
            add(
                sum,
                u16::from_be_bytes([word[0], word.get(1).copied().unwrap_or(0)]),
            )
        })
    }
}

#[cfg(kani)]
mod proofs {
    use super::model::{add, sum};
    use super::{incremental_update, ones_complement_sum};

    /// The model's addition is a commutative monoid, so the sum of a run of words does not depend
    /// on their order or grouping: any one word can be pulled out as `add(rest, word)`. That is
    /// what lets the proofs below speak of a single changing word in a buffer of any length.
    #[kani::proof]
    fn add_is_a_commutative_monoid() {
        let (a, b, c): (u16, u16, u16) = kani::any();
        assert_eq!(add(a, b), add(b, a));
        assert_eq!(add(add(a, b), c), add(a, add(b, c)));
        assert_eq!(add(a, 0), a);
    }

    /// The sum is `0` only for all-zero data (as [`ones_complement_sum`] documents): adding never
    /// reaches `0` from anything else.
    #[kani::proof]
    fn add_reaches_zero_only_from_zeros() {
        let (a, b): (u16, u16) = kani::any();
        assert!(add(a, b) != 0 || (a == 0 && b == 0));
    }

    /// [`ones_complement_sum`] computes the model's sum.
    ///
    /// Bounded at 8 bytes of any length, which takes every path through etherparse's accumulator
    /// once: an 8-byte chunk, a 4-byte tail, a 2-byte tail and an odd last byte. Longer buffers
    /// repeat the 8-byte step; the solver struggles with the modular arithmetic beyond this bound
    /// (20 bytes did not finish in 30 minutes).
    #[kani::proof]
    #[kani::unwind(10)]
    fn ones_complement_sum_matches_model() {
        let bytes: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        assert_eq!(ones_complement_sum(&bytes[..len]), sum(&bytes[..len]));
    }

    /// RFC 1624: an incremental update gives exactly the checksum a full recompute would, for every
    /// checksum, old and new value, except when the update leaves the covered data all zero. A
    /// full recompute then gives `0xffff` (the complement of `+0`) and the update `0x0000` (of
    /// `-0`), RFC 1624's section 3 case.
    ///
    /// `rest` is the sum of every other covered word, so this holds for data of any length.
    #[kani::proof]
    fn incremental_update_matches_full_recompute() {
        let (rest, old, new): (u16, u16, u16) = kani::any();
        let updated = incremental_update(!add(rest, old), old, new);
        let recomputed = !add(rest, new);
        if rest == 0 && new == 0 {
            assert_eq!((updated, recomputed), (0x0000, 0xffff));
        } else {
            assert_eq!(updated, recomputed);
        }
    }

    /// An update carries whatever error the checksum had through exactly: the sum over the data
    /// and the checksum, which is `0xffff` for a valid checksum, does not change. This is what lets
    /// a router rewrite fields of a header without repairing (or breaking) a checksum it never
    /// checked.
    ///
    /// It needs the covered data to be nonzero both before and after (by
    /// [`add_reaches_zero_only_from_zeros`], `rest` or the changing word nonzero). Otherwise the
    /// sum can flip between `0x0000` and `0xffff`, e.g. `rest = 0`, `old = 0xffff`, `new = 0` with
    /// checksum `0`. Callers only fold in words that changed, so `old != new`.
    #[kani::proof]
    fn incremental_update_carries_the_checksum_error() {
        let (rest, old, new, checksum): (u16, u16, u16, u16) = kani::any();
        kani::assume(old != new);
        kani::assume(add(rest, old) != 0 && add(rest, new) != 0);
        let before = add(add(rest, old), checksum);
        let after = add(add(rest, new), incremental_update(checksum, old, new));
        assert_eq!(before, after);
    }
}
