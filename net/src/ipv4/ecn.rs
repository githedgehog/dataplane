// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ECN type and contract

use etherparse::Ipv4Ecn;

/// Explicit congestion notification value
#[repr(transparent)]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ecn(pub(crate) Ipv4Ecn);

/// Errors which may occur relating to illegal [`Ecn`] values
#[derive(Debug, thiserror::Error)]
pub enum InvalidEcnError {
    /// Two bit value of [`Ecn`] exceeded
    #[error("{0} is too large to be a legal ECN (two bits max)")]
    TooLarge(u8),
}

impl Ecn {
    /// Create an [`Ecn`] from a raw u8.
    ///
    /// # Errors
    ///
    /// Will return an [`InvalidEcnError`] if the supplied value is larger than two bits
    pub fn new(raw: u8) -> Result<Ecn, InvalidEcnError> {
        Ok(Ecn(
            Ipv4Ecn::try_new(raw).map_err(|e| InvalidEcnError::TooLarge(e.actual))?
        ))
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ipv4::ecn::Ecn;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for Ecn {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Ecn::new(driver.r#gen::<u8>()? & 0b0000_0011).unwrap_or_else(|_| unreachable!()))
        }
    }
}
