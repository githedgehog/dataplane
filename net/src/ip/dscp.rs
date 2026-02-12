// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP [DSCP] (Differentiated Services Code Point)
//!
//! DSCP is a 6-bit value carried in the IPv4 DS field (formerly TOS) and in the IPv6 Traffic Class.
//!
//! [DSCP]: https://en.wikipedia.org/wiki/Differentiated_services

// IpDscp is a wrapper over ipv4/ipv6 DSCP values, no need to have explicitly separate
// types for each version of IP.
use etherparse::IpDscp;

/// IP DSCP (Differentiated Services Code Point)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Dscp(pub(crate) IpDscp);

/// Errors related to invalid [`Dscp`] states
#[derive(Debug, thiserror::Error)]
pub enum InvalidDscpError {
    /// 6 bit value of [`Dscp`] exceeded
    #[error("DSCP value {0} too large")]
    TooBig(u8),
}

impl Dscp {
    /// The minimum legal [`Dscp`] value
    pub const MIN: Dscp = Dscp(IpDscp::ZERO);
    /// The maximum legal [`Dscp`] value
    #[allow(unsafe_code)] // trivially sound constant eval
    pub const MAX: Dscp = Dscp(unsafe { IpDscp::new_unchecked(IpDscp::MAX_U8) });

    /// Create a new [`Dscp`]
    ///
    /// # Errors
    ///
    /// Will return an [`InvalidDscpError`] if the supplied value for `raw` exceeds 6-bits.
    #[allow(dead_code)]
    pub fn new(raw: u8) -> Result<Dscp, InvalidDscpError> {
        Ok(Dscp(
            IpDscp::try_new(raw).map_err(|e| InvalidDscpError::TooBig(e.actual))?,
        ))
    }

    /// Return the underlying 6-bit DSCP value as a `u8`.
    ///
    /// This returns only the DSCP portion (0..=63). It does **not** include ECN bits.
    #[must_use]
    pub fn value(self) -> u8 {
        self.0.value()
    }
}

impl From<IpDscp> for Dscp {
    fn from(v: IpDscp) -> Self {
        Dscp(v)
    }
}

impl From<Dscp> for IpDscp {
    fn from(v: Dscp) -> Self {
        v.0
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::Dscp;
    use bolero::{Driver, TypeGenerator};
    use etherparse::IpDscp;

    impl TypeGenerator for Dscp {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let raw = driver.produce::<u8>()? & Dscp::MAX.0.value();
            Some(Dscp(
                IpDscp::try_new(raw).unwrap_or_else(|_| unreachable!()),
            ))
        }
    }
}
