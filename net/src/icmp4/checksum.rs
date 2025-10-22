// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv4` checksum type and methods

use crate::checksum::Checksum;
use crate::icmp4::Icmp4;
use crate::icmp4::TruncatedIcmp4;
use core::fmt::{Display, Formatter};
use std::fmt::Debug;

/// A icmp [checksum]
///
/// [checksum]: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Icmp4Checksum(pub(crate) u16);

impl Display for Icmp4Checksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#06X}", self.0)
    }
}

impl Icmp4Checksum {
    /// Map a raw value to a [`Icmp4Checksum`]
    #[must_use]
    pub const fn new(raw: u16) -> Icmp4Checksum {
        Icmp4Checksum(raw)
    }
}

impl AsRef<u16> for Icmp4Checksum {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl AsMut<u16> for Icmp4Checksum {
    fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }
}

impl From<u16> for Icmp4Checksum {
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl From<Icmp4Checksum> for u16 {
    fn from(checksum: Icmp4Checksum) -> Self {
        checksum.0
    }
}

impl Checksum for Icmp4 {
    type Error = ();
    type Payload<'a> = [u8];
    type Checksum = Icmp4Checksum;

    /// Get the [`Icmp4`] checksum of the header
    ///
    /// # Returns
    ///
    /// Always returns `Some`.
    fn checksum(&self) -> Option<Icmp4Checksum> {
        Some(Icmp4Checksum(self.0.checksum))
    }

    /// Compute the icmp v4 header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    ///
    /// # Errors
    ///
    /// Always returns `Ok`.
    fn compute_checksum(&self, payload: &[u8]) -> Result<Icmp4Checksum, Self::Error> {
        Ok(Icmp4Checksum(self.0.icmp_type.calc_checksum(payload)))
    }

    /// Set the checksum field of the header
    ///
    /// # Errors
    ///
    /// Always returns `Ok`.
    fn set_checksum(&mut self, checksum: Icmp4Checksum) -> Result<&mut Self, Self::Error> {
        self.0.checksum = checksum.0;
        Ok(self)
    }
}

/// Errors which can occur when attempting to compute a `ICMPv4` checksum for a truncated `ICMPv4` header.
#[derive(Debug, thiserror::Error)]
pub enum TruncatedIcmp4ChecksumError {
    /// The header is truncated, checksum operations are not available.
    #[error("header is truncated")]
    Truncated,
}

impl Checksum for TruncatedIcmp4 {
    type Error = TruncatedIcmp4ChecksumError;
    type Payload<'a> = [u8];
    type Checksum = Icmp4Checksum;

    /// Get the [`Icmp4`] checksum of the header
    ///
    /// # Returns
    ///
    /// * `Some` if the header is a full header. The `ICMPv4` payload may be truncated, so it may be
    ///   impossible to compute the checksum.
    /// * `None` if the header is a truncated header. Note that the checksum may be present in the
    ///   truncated header, but given that the header is truncated, it is irrelevant because there
    ///   is no way to validate it, so we return `None` in that case.
    fn checksum(&self) -> Option<Self::Checksum> {
        match self {
            TruncatedIcmp4::FullHeader(icmp) => icmp.checksum(),
            TruncatedIcmp4::PartialHeader(_) => None,
        }
    }

    /// Compute the `ICMPv4` header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    ///
    /// # Errors
    ///
    /// * [`TruncatedIcmp4ChecksumError::Truncated`] if the header is a truncated header
    ///
    /// <div class="warning">
    /// If the header is full, we perform the computation although there is no guarantee that the
    /// `ICMPv4` _payload_ is full. It is the responsibility of the caller to ensure that the `ICMPv4`
    /// payload is full, _and_ that the payload passed as an argument is exempt from ICMP Extension
    /// Structures and padding.
    /// </div>
    fn compute_checksum(&self, payload: &Self::Payload<'_>) -> Result<Self::Checksum, Self::Error> {
        match self {
            TruncatedIcmp4::FullHeader(icmp) => Ok(icmp
                .compute_checksum(payload)
                .unwrap_or_else(|()| unreachable!())), // ICMPv4 checksum computation never fails
            TruncatedIcmp4::PartialHeader(_) => Err(TruncatedIcmp4ChecksumError::Truncated),
        }
    }

    /// Set the checksum field of the header.
    ///
    /// The validity of the checksum is not checked.
    ///
    /// # Errors
    ///
    /// * [`TruncatedIcmp4ChecksumError::Truncated`] if the header is a truncated header
    fn set_checksum(&mut self, checksum: Self::Checksum) -> Result<&mut Self, Self::Error> {
        match self {
            TruncatedIcmp4::FullHeader(icmp) => {
                icmp.set_checksum(checksum)
                    .unwrap_or_else(|()| unreachable!()); // Setting the ICMPv4 checksum never fails
                Ok(self)
            }
            TruncatedIcmp4::PartialHeader(_) => Err(TruncatedIcmp4ChecksumError::Truncated),
        }
    }
}
