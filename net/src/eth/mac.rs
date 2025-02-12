// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Mac address type and logic.

use crate::eth::{DestinationMacAddressError, SourceMacAddressError};
use std::fmt::Display;

/// A [MAC Address] type.
///
/// `Mac` is a transparent wrapper around `[u8; 6]` which provides a
/// small collection of methods and type safety.
///
/// [MAC Address]: https://en.wikipedia.org/wiki/MAC_address
#[repr(transparent)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Mac(pub [u8; 6]);

impl From<[u8; 6]> for Mac {
    fn from(value: [u8; 6]) -> Self {
        Mac(value)
    }
}

impl From<Mac> for [u8; 6] {
    fn from(value: Mac) -> Self {
        value.0
    }
}

impl AsRef<[u8; 6]> for Mac {
    #[must_use]
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl AsMut<[u8; 6]> for Mac {
    #[must_use]
    fn as_mut(&mut self) -> &mut [u8; 6] {
        &mut self.0
    }
}

impl Mac {
    /// The broadcast `Mac`
    pub const BROADCAST: Mac = Mac([u8::MAX; 6]);
    /// The zero `Mac`.
    ///
    /// `ZERO` is illegal as a source or destination `Mac` in most contexts.
    pub const ZERO: Mac = Mac([0; 6]);

    /// Returns true iff the binary representation of the [`Mac`] is exclusively ones.
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self == &Mac::BROADCAST
    }

    /// Returns true iff the least significant bit of the first octet of the `[Mac]` is one.
    #[must_use]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 == 0x01
    }

    /// Returns true iff the least significant bit of the first octet of the `[Mac]` is zero.
    #[must_use]
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Returns true iff the binary representation of the [`Mac`] is exclusively zeros.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self == &Mac::ZERO
    }

    /// Returns true iff the second least significant bit of the first octet is one.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Returns true iff the second least significant bit of the first octet is zero.
    #[must_use]
    pub fn is_universal(&self) -> bool {
        !self.is_local()
    }

    /// Returns true if the [`Mac`] is reserved for link local usage.
    ///
    /// Link local usage includes [spanning tree protocol] and [LACP].
    ///
    /// [spanning tree protocol]: https://en.wikipedia.org/wiki/Spanning_Tree_Protocol
    /// [LACP]: https://en.wikipedia.org/wiki/Link_aggregation#Link_Aggregation_Control_Protocol
    #[must_use]
    pub fn is_link_local(&self) -> bool {
        let bytes = self.as_ref();
        (bytes[0..5] == [0x01, 0x80, 0xc2, 0x00, 0x00]) && (bytes[5] & 0x0f == bytes[5])
    }

    /// Returns true iff the [`Mac`] is a legal source `Mac`.
    ///
    /// Multicast and zero are not legal source [`Mac`].
    #[must_use]
    pub fn is_valid_src(&self) -> bool {
        !self.is_zero() && !self.is_multicast()
    }

    /// Returns true iff the [`Mac`] is a legal destination [`Mac`].
    #[must_use]
    pub fn is_valid_dst(&self) -> bool {
        self.is_valid()
    }

    /// Return true iff the [`Mac`] is not zero.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_zero()
    }
}

impl Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:<02X}:{:<02X}:{:<02X}:{:<02X}:{:<02X}:{:<02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}
/// A [`Mac`] which is legal as a source in an ethernet header.
#[repr(transparent)]
pub struct SourceMac(Mac);

impl SourceMac {
    // TODO: proof of non-panic behavior
    /// Map a [`Mac`] to a [`SourceMac`]
    ///
    /// # Errors
    ///
    /// Will return a [`SourceMacAddressError`] if the supplied [`Mac`] is not a legal source [`Mac`].
    pub fn new(inner: Mac) -> Result<SourceMac, SourceMacAddressError> {
        if inner.is_valid_src() {
            Ok(SourceMac(inner))
        } else if inner.is_zero() {
            Err(SourceMacAddressError::ZeroSource(inner))
        } else if inner.is_multicast() {
            Err(SourceMacAddressError::MulticastSource(inner))
        } else {
            unreachable!()
        }
    }

    /// Map the [`SourceMac`] back to an unqualified [`Mac`]
    #[must_use]
    pub const fn inner(self) -> Mac {
        self.0
    }
}

/// A [`Mac`] which is legal as a destination in an ethernet header.
#[repr(transparent)]
pub struct DestinationMac(Mac);

impl DestinationMac {
    // TODO: proof of non-panic behavior
    /// Map a [`Mac`] to a [`DestinationMac`]
    ///
    /// # Errors
    ///
    /// Will return a [`DestinationMacAddressError`] if the supplied [`Mac`] is not legal as a
    /// destination.
    pub fn new(inner: Mac) -> Result<DestinationMac, DestinationMacAddressError> {
        if inner.is_valid_dst() {
            Ok(DestinationMac(inner))
        } else if inner.is_zero() {
            Err(DestinationMacAddressError::ZeroDestination(inner))
        } else {
            unreachable!()
        }
    }

    /// Map the [`DestinationMac`] back to an unqualified [`Mac`]
    #[must_use]
    pub const fn inner(self) -> Mac {
        self.0
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::eth::mac::{DestinationMac, Mac, SourceMac};
    use arbitrary::{Arbitrary, Unstructured};

    impl<'a> Arbitrary<'a> for SourceMac {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut mac: Mac = u.arbitrary()?;
            mac.0[0] &= 0b1111_1110;
            if mac.is_zero() {
                mac.0[5] = 1;
            }
            Ok(SourceMac(mac))
        }
    }

    impl<'a> Arbitrary<'a> for DestinationMac {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut mac: Mac = u.arbitrary()?;
            if mac.is_zero() {
                mac.0[5] = 1;
            }
            Ok(DestinationMac(mac))
        }
    }
}
