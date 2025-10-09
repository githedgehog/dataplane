// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv6` checksum type and methods

use crate::checksum::Checksum;
use crate::icmp6::Icmp6;
use core::fmt::{Display, Formatter};
use etherparse::Icmpv6Header;
use std::fmt::Debug;
use std::net::Ipv6Addr;

/// An icmp6 [checksum]
///
/// [checksum]: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Icmp6Checksum(pub(crate) u16);

impl Display for Icmp6Checksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#06X}", self.0)
    }
}

impl Icmp6Checksum {
    /// Map a raw value to a [`Icmp6Checksum`]
    #[must_use]
    pub const fn new(raw: u16) -> Icmp6Checksum {
        Icmp6Checksum(raw)
    }
}

impl AsRef<u16> for Icmp6Checksum {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl AsMut<u16> for Icmp6Checksum {
    fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }
}

impl From<u16> for Icmp6Checksum {
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl From<Icmp6Checksum> for u16 {
    fn from(checksum: Icmp6Checksum) -> Self {
        checksum.0
    }
}

/// The payload over which to compute an validate [`Icmp6`] checksums.
pub struct Icmp6ChecksumPayload<'a> {
    // NOTE: arguably, this should be scoped to unicast.
    // I decided that it is useful to allow for checksum validation of multicast source addresses
    // even if they are illegal.  This may help if we receive malformed / malicious packets.
    src: Ipv6Addr,
    dst: Ipv6Addr,
    contents: &'a [u8],
}

impl<'a> Icmp6ChecksumPayload<'a> {
    /// Create a new [`Icmp6ChecksumPayload`]
    ///
    /// # Safety
    ///
    /// It is undefined behavior of the payload length to be greater than the maximum allowed by
    /// the [`Icmp6`] header (2^32 bytes - 8 bytes for the header itself).
    ///
    /// This is a very unlikely event, and as such is only checked if debug assertions are enabled.
    #[must_use]
    pub fn new(src: Ipv6Addr, dst: Ipv6Addr, payload: &'a [u8]) -> Self {
        debug_assert!(
            payload.len() <= ((u32::MAX as usize) - Icmpv6Header::MIN_LEN),
            "illegal payload length"
        );
        Self {
            src,
            dst,
            contents: payload,
        }
    }
}

impl Checksum for Icmp6 {
    type Payload<'a> = Icmp6ChecksumPayload<'a>;
    type Checksum = Icmp6Checksum;

    /// Get the [`Icmp6`] checksum of the header
    fn checksum(&self) -> Icmp6Checksum {
        Icmp6Checksum(self.0.checksum)
    }

    /// Compute the icmp v6 header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    fn compute_checksum(&self, payload: &Icmp6ChecksumPayload) -> Icmp6Checksum {
        Icmp6Checksum(
            self.0
                .icmp_type
                .calc_checksum(payload.src.octets(), payload.dst.octets(), payload.contents)
                .unwrap_or_else(|e| unreachable!("{:?}", e)),
        )
    }

    /// Set the checksum field of the header.
    ///
    /// The validity of the checksum is not checked.
    fn set_checksum(&mut self, checksum: Icmp6Checksum) -> &mut Self {
        self.0.checksum = checksum.0;
        self
    }
}
