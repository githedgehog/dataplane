// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Helper methods and types which are common between IPv4 and IPv6

use etherparse::IpNumber;

/// Thin wrapper around [`IpNumber`]
///
/// This exists to allow us to implement [`Arbitrary`] without violating rust's orphan rules.
#[repr(transparent)]
pub struct NextHeader {
    inner: IpNumber,
}

impl From<NextHeader> for IpNumber {
    fn from(value: NextHeader) -> Self {
        value.inner
    }
}

impl NextHeader {
    /// Generate a new [`NextHeader`]
    #[must_use]
    pub fn new(inner: u8) -> Self {
        Self {
            inner: IpNumber::from(inner),
        }
    }

    /// Return the [`NextHeader`] represented as a `u8`
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        self.inner.0
    }

    /// Set the value of this [`NextHeader`] to an arbitrary `u8`
    pub fn set_u8(&mut self, inner: u8) {
        self.inner = IpNumber::from(inner);
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ip::NextHeader;
    use arbitrary::{Arbitrary, Unstructured};

    impl<'a> Arbitrary<'a> for NextHeader {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(NextHeader::new(u.arbitrary()?))
        }

        fn size_hint(_depth: usize) -> (usize, Option<usize>) {
            (1, Some(1))
        }
    }
}
