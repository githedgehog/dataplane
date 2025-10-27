// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Common logic for `ICMPv4` and `ICMPv6`

use crate::headers::{AbstractEmbeddedHeaders, Transport};
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;

mod checksum;
mod truncated;

pub use checksum::*;
pub use truncated::*;

/// Error type for [`IcmpAny`] and [`IcmpAnyMut`]
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum IcmpAnyError {
    /// The transport layer is not `ICMPv4` or `ICMPv6`
    #[error("this transport layer is neither ICMPv4 nor ICMPv6")]
    NotIcmp,
}

/// Enum representing an immutable [`Icmp4`] or [`Icmp6`].
pub enum IcmpAny<'a> {
    /// A [`Icmp4`]
    V4(&'a Icmp4),
    /// A [`Icmp6`]
    V6(&'a Icmp6),
}

impl<'a> TryFrom<&'a Transport> for IcmpAny<'a> {
    type Error = IcmpAnyError;
    fn try_from(value: &'a Transport) -> Result<Self, Self::Error> {
        match value {
            Transport::Icmp4(icmp4) => Ok(IcmpAny::V4(icmp4)),
            Transport::Icmp6(icmp6) => Ok(IcmpAny::V6(icmp6)),
            _ => Err(IcmpAnyError::NotIcmp),
        }
    }
}

impl IcmpAny<'_> {
    /// Returns `true` if this is an ICMP Error message, `false` otherwise.
    #[must_use]
    pub fn is_error_message(&self) -> bool {
        match self {
            IcmpAny::V4(icmp4) => icmp4.is_error_message(),
            IcmpAny::V6(icmp6) => icmp6.is_error_message(),
        }
    }

    /// Returns the payload for checksum computation.
    #[must_use]
    pub fn get_payload_for_checksum(
        &self,
        embedded_headers: Option<&impl AbstractEmbeddedHeaders>,
        payload: &[u8],
    ) -> Vec<u8> {
        match self {
            IcmpAny::V4(icmp4) => icmp4.get_payload_for_checksum(embedded_headers, payload),
            IcmpAny::V6(icmp6) => icmp6.get_payload_for_checksum(embedded_headers, payload),
        }
    }
}

/// Enum representing a mutable [`Icmp4`] or [`Icmp6`].
pub enum IcmpAnyMut<'a> {
    /// A [`Icmp4`]
    V4(&'a mut Icmp4),
    /// A [`Icmp6`]
    V6(&'a mut Icmp6),
}

impl<'a> TryFrom<&'a mut Transport> for IcmpAnyMut<'a> {
    type Error = IcmpAnyError;
    fn try_from(value: &'a mut Transport) -> Result<Self, Self::Error> {
        match value {
            Transport::Icmp4(icmp4) => Ok(IcmpAnyMut::V4(icmp4)),
            Transport::Icmp6(icmp6) => Ok(IcmpAnyMut::V6(icmp6)),
            _ => Err(IcmpAnyError::NotIcmp),
        }
    }
}
