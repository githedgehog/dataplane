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
    type Checksum: Eq + Copy + Sized + Debug + From<u16> + Into<u16>;

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

        // First subtraction: HC - ~m
        let (mut tmp, borrow) = current_checksum.into().overflowing_sub(!old_value);
        if borrow {
            tmp = tmp.wrapping_sub(1);
        }

        // Second subtraction: tmp - m'
        let (mut result, borrow) = tmp.overflowing_sub(new_value);
        if borrow {
            result = result.wrapping_sub(1);
        }

        result.into()
    }

    /// Perform an incremental update of the checksum in the header, like `increment_update_checksum`
    /// but for a 32-bit value change.
    fn increment_update_checksum_32bit(
        &mut self,
        current_checksum: Self::Checksum,
        old_value: u32,
        new_value: u32,
    ) -> Self::Checksum {
        let old_value_first_half = (old_value >> 16) as u16;
        #[allow(clippy::cast_possible_truncation)] // truncation is intentional
        let old_value_second_half = old_value as u16;
        let new_value_first_half = (new_value >> 16) as u16;
        #[allow(clippy::cast_possible_truncation)] // truncation is intentional
        let new_value_second_half = new_value as u16;

        let intermediary_checksum = self.increment_update_checksum(
            current_checksum,
            old_value_first_half,
            new_value_first_half,
        );
        self.increment_update_checksum(
            intermediary_checksum,
            old_value_second_half,
            new_value_second_half,
        )
    }
}

/// An error resulting from a checksum mismatch.
#[derive(Debug, thiserror::Error)]
#[error("checksum mismatch: expected {expected:?}, actual {actual:?}")]
pub struct ChecksumError<T: Checksum + ?Sized> {
    expected: T::Checksum,
    actual: T::Checksum,
}

#[cfg(test)]
mod tests {
    use crate::checksum::Checksum;
    use crate::ipv4::Ipv4;
    use std::net::Ipv4Addr;

    fn update_and_check_checksum(ipv4: &Ipv4, new_len_value: u16, new_addr_value: u32) {
        let mut ipv4 = ipv4.clone();

        // Set and validate checksum
        ipv4.update_checksum(&());
        ipv4.validate_checksum(&())
            .expect("expected valid checksum after initial update");

        // Update 16-bit "total length" field
        let checksum = ipv4.checksum();
        let old_value = ipv4.0.total_len;
        ipv4.0.total_len = new_len_value;

        // Update and validate checksum
        let new_checksum = ipv4.increment_update_checksum(checksum, old_value, new_len_value);
        ipv4.set_checksum(new_checksum);
        ipv4.validate_checksum(&())
            .expect("expected valid checksum after total length field change");

        // Update 32-bit destination address
        let checksum = ipv4.checksum();
        let old_value = ipv4.destination().into();
        let new_ip = Ipv4Addr::from(new_addr_value);
        ipv4.set_destination(new_ip);

        // Update and validate checksum
        let new_checksum =
            ipv4.increment_update_checksum_32bit(checksum, old_value, new_addr_value);
        ipv4.set_checksum(new_checksum);
        ipv4.validate_checksum(&())
            .expect("expected valid checksum after destination address change");
    }

    #[test]
    fn test_increment_update_checksum() {
        bolero::check!()
            .with_type()
            .for_each(|(header, len, addr)| {
                update_and_check_checksum(header, *len, *addr);
            });
    }
}
