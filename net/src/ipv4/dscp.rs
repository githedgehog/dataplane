// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ipv4 [DSCP] (Differentiated Services Code Point)
//!
//! [DSCP]: https://en.wikipedia.org/wiki/Type_of_service

use etherparse::Ipv4Dscp;

/// [`Ipv4`] [DSCP] (Differentiated Services Code Point)
///
/// [`Ipv4`]: crate::ipv4::Ipv4
/// [DSCP]: https://en.wikipedia.org/wiki/Type_of_service
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Dscp(pub(crate) Ipv4Dscp);

/// Errors related to invalid [`Dscp`] states
#[derive(Debug, thiserror::Error)]
pub enum InvalidDscpError {
    /// 6 bit value of [`Dscp`] exceeded
    #[error("DSCP value {0} too large")]
    TooBig(u8),
}

impl Dscp {
    /// The minimum legal [`Dscp`] value
    pub const MIN: Dscp = Dscp(Ipv4Dscp::ZERO);
    /// The maximum legal [`Dscp`] value
    #[allow(unsafe_code)] // trivially sound constant eval
    pub const MAX: Dscp = Dscp(unsafe { Ipv4Dscp::new_unchecked(Ipv4Dscp::MAX_U8) });

    /// Create a new [`Dscp`]
    ///
    /// # Errors
    ///
    /// Will return an [`InvalidDscpError`] if the supplied value for `raw` exceeds 6-bits.
    fn new(raw: u8) -> Result<Dscp, InvalidDscpError> {
        Ok(Dscp(
            Ipv4Dscp::try_new(raw).map_err(|e| InvalidDscpError::TooBig(e.actual))?,
        ))
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ipv4::dscp::Dscp;
    use bolero::{Driver, TypeGenerator};
    use etherparse::Ipv4Dscp;

    impl TypeGenerator for Dscp {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let raw = driver.gen::<u8>()? & Dscp::MAX.0.value();
            Some(Dscp(
                Ipv4Dscp::try_new(raw).unwrap_or_else(|_| unreachable!()),
            ))
        }
    }
}
