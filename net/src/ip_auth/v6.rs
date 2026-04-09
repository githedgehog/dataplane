// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv6-context IP Authentication Header.
//!
//! This is a [`repr(transparent)`] newtype over [`IpAuth`] that marks the
//! header as appearing in an IPv6 extension chain.  The builder uses this
//! type to restrict `Within` impls so that `Ipv6Auth` can only follow
//! IPv6-legal parents (e.g. `Ipv6`, `Fragment`, `Routing`).

use crate::ip_auth::IpAuth;
use crate::parse::{DeParse, DeParseError, Parse, ParseError};
use std::num::NonZero;
use std::ops::Deref;

/// IP Authentication Header in an IPv6 context ([RFC 4302]).
///
/// Structurally identical to [`IpAuth`] on the wire -- the type distinction
/// exists purely to give the builder different `Within` bounds for IPv4
/// vs IPv6 extension header chains.
///
/// [RFC 4302]: https://datatracker.ietf.org/doc/html/rfc4302
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Auth(IpAuth);

impl Ipv6Auth {
    /// Wrap an [`IpAuth`] as an IPv6-context authentication header.
    #[must_use]
    pub fn new(inner: IpAuth) -> Self {
        Self(inner)
    }

    /// Unwrap into the inner [`IpAuth`].
    #[must_use]
    pub fn into_inner(self) -> IpAuth {
        self.0
    }
}

impl Deref for Ipv6Auth {
    type Target = IpAuth;

    fn deref(&self) -> &IpAuth {
        &self.0
    }
}

impl From<IpAuth> for Ipv6Auth {
    fn from(inner: IpAuth) -> Self {
        Self(inner)
    }
}

impl From<Ipv6Auth> for IpAuth {
    fn from(outer: Ipv6Auth) -> Self {
        outer.0
    }
}

impl Parse for Ipv6Auth {
    type Error = <IpAuth as Parse>::Error;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let (inner, consumed) = IpAuth::parse(buf)?;
        Ok((Self(inner), consumed))
    }
}

impl DeParse for Ipv6Auth {
    type Error = <IpAuth as DeParse>::Error;

    fn size(&self) -> NonZero<u16> {
        self.0.size()
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        self.0.deparse(buf)
    }
}
