// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Helper methods and types which are common between IPv4 and IPv6

use etherparse::IpNumber;

/// Thin wrapper around [`IpNumber`]
///
/// This exists to allow us to implement `TypeGenerator` without violating rust's orphan rules.
#[repr(transparent)]
#[derive(PartialEq, Eq, Clone, Copy, Hash, Ord, PartialOrd)]
pub struct NextHeader(pub(crate) IpNumber);

impl From<NextHeader> for IpNumber {
    fn from(value: NextHeader) -> Self {
        value.0
    }
}

impl NextHeader {
    /// TCP next header
    pub const TCP: NextHeader = NextHeader(IpNumber::TCP);

    /// UDP next header
    pub const UDP: NextHeader = NextHeader(IpNumber::UDP);

    /// ICMP next header
    pub const ICMP: NextHeader = NextHeader(IpNumber::ICMP);

    /// Get the inner (wrapped) `etherparse` [`IpNumber`] type
    pub(crate) fn inner(self) -> IpNumber {
        self.0
    }

    /// Generate a new [`NextHeader`]
    #[must_use]
    pub fn new(inner: u8) -> Self {
        Self(IpNumber::from(inner))
    }

    /// Return the [`NextHeader`] represented as a `u8`
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        self.0 .0
    }

    /// Set the value of this [`NextHeader`] to an arbitrary `u8`
    pub fn set_u8(&mut self, inner: u8) {
        self.0 = IpNumber::from(inner);
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ip::NextHeader;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for NextHeader {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(NextHeader::new(driver.gen()?))
        }
    }
}
