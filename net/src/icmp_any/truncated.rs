// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Common logic for `ICMPv4` and `ICMPv6` potentially-truncated headers.
//!
//! We do not reimplement an enum `TruncatedIcmpAny` (like [`IcmpAny`](super::IcmpAny) for
//! [`Icmp4`](super::Icmp4) and [`Icmp6`](super::Icmp6)), instead we simply define a trait for use
//! with generic functions in the NAT logic.

/// Trait for common methods of truncated ICMP headers (v4 and v6)
pub trait TruncatedIcmpAny {
    /// Error type returned by [`TruncatedIcmpAny::try_set_identifier`]
    type Error;

    /// Get the identifier of the ICMP Query message header, if any.
    #[must_use]
    fn identifier(&self) -> Option<u16>;

    /// Set the identifier of the ICMP Query message header.
    ///
    /// # Errors
    ///
    /// Returns an error on failure to set the identifier, either because the ICMP header is not of
    /// a type that supports identifiers, or because the header is truncated.
    fn try_set_identifier(&mut self, identifier: u16) -> Result<(), Self::Error>;
}
