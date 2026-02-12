// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP ECN type and contract
//!
//! ECN is a 2-bit value carried alongside DSCP (IPv4 DS field / IPv6 Traffic Class).

// IpEcn is a wrapper over ipv4/ipv6 ECN values, no need to have explicitly separate types for each version of IP.
// This also allows us to implement `TypeGenerator` for `Ecn` without violating orphan rules,
// which is useful for testing and fuzzing.
use etherparse::IpEcn;

/// Explicit congestion notification value
#[repr(transparent)]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ecn(pub(crate) IpEcn);

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
    #[allow(dead_code)]
    pub fn new(raw: u8) -> Result<Ecn, InvalidEcnError> {
        Ok(Ecn(
            IpEcn::try_new(raw).map_err(|e| InvalidEcnError::TooLarge(e.actual))?
        ))
    }

    /// Return the underlying 2-bit ECN value as a `u8`.
    ///
    /// This returns only the ECN portion (0..=3). It does **not** include DSCP bits.
    #[must_use]
    pub fn value(self) -> u8 {
        self.0.value()
    }
}

impl From<IpEcn> for Ecn {
    fn from(v: IpEcn) -> Self {
        Ecn(v)
    }
}

impl From<Ecn> for IpEcn {
    fn from(v: Ecn) -> Self {
        v.0
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::Ecn;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for Ecn {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Ecn::new(driver.produce::<u8>()? & 0b0000_0011).unwrap_or_else(|_| unreachable!()))
        }
    }
}
