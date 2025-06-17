// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Traits for checksum calculation and manipulation

use std::fmt::Debug;

/// A trait for checksum calculation and manipulation.
///
/// This trait is used to calculate and manipulate checksums in various headers.
pub trait Checksum {
    /// The payload type for the header.
    ///
    /// This is used to calculate the checksum.
    type Payload<'a>: ?Sized
    where
        Self: 'a;
    /// The checksum type.
    ///
    /// This is used to represent the checksum value.
    type Checksum: Eq + Copy + Sized + Debug;

    /// Get the checksum value from the header
    fn checksum(&self) -> Self::Checksum;

    /// Compute the checksum value from the header and payload
    fn compute_checksum(&self, payload: &Self::Payload<'_>) -> Self::Checksum;

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
    fn set_checksum(&mut self, checksum: Self::Checksum) -> &mut Self;

    /// Validate the checksum value in the header.
    ///
    /// # Errors
    ///
    /// Returns a [`ChecksumError`] if the checksum is invalid.
    fn validate_checksum(
        &self,
        payload: &Self::Payload<'_>,
    ) -> Result<Self::Checksum, ChecksumError<Self>> {
        let expected = self.compute_checksum(payload);
        let actual = self.checksum();
        if expected == actual {
            Ok(expected)
        } else {
            Err(ChecksumError { expected, actual })
        }
    }

    /// Update the checksum value in the header.
    ///
    /// The post-condition of this function is that the checksum is valid.
    /// I.e., the `validate_checksum` function will not return an `Err` variant when given the same
    /// value for `payload` as was passed into this function.
    fn update_checksum(&mut self, payload: &Self::Payload<'_>) -> &mut Self {
        let ret = self.set_checksum(self.compute_checksum(payload));
        #[cfg(debug_assertions)]
        #[allow(clippy::panic)] // this is basically a debug_assert
        match ret.validate_checksum(payload) {
            Ok(_) => {}
            Err(err) => {
                panic!(
                    "checksum implementation is faulty: expected: {expected:?}, actual: {actual:?}",
                    expected = err.expected,
                    actual = err.actual
                );
            }
        }
        ret
    }
}

/// An error resulting from a checksum mismatch.
#[derive(Debug, thiserror::Error)]
#[error("checksum mismatch: expected {expected:?}, actual {actual:?}")]
pub struct ChecksumError<T: Checksum + ?Sized> {
    expected: T::Checksum,
    actual: T::Checksum,
}
