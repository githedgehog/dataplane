// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv4-context IP Authentication Header.
//!
//! This is a [`repr(transparent)`] newtype over [`IpAuth`] that marks the
//! header as appearing in an IPv4 extension chain.  The builder uses this
//! type to restrict `Within` impls so that `Ipv4Auth` can only follow
//! IPv4-legal parents (e.g. `Ipv4`), preventing it from being stacked
//! after IPv6-only extension headers like `HopByHop`.

use crate::ip_auth::IpAuth;
use crate::parse::{DeParse, DeParseError, Parse, ParseError};
use std::num::NonZero;
use std::ops::{Deref, DerefMut};

/// IP Authentication Header in an IPv4 context ([RFC 4302]).
///
/// Structurally identical to [`IpAuth`] on the wire -- the type distinction
/// exists purely to give the builder different `Within` bounds for IPv4
/// vs IPv6 extension header chains.
///
/// [RFC 4302]: https://datatracker.ietf.org/doc/html/rfc4302
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Auth(IpAuth);

impl Ipv4Auth {
    /// Wrap an [`IpAuth`] as an IPv4-context authentication header.
    #[must_use]
    pub fn new(inner: IpAuth) -> Self {
        Self(inner)
    }

    /// Unwrap into the inner [`IpAuth`].
    #[must_use]
    pub fn into_inner(self) -> IpAuth {
        self.0
    }

    /// Parse the next header after this one (IPv4 context).
    pub(crate) fn parse_payload(
        &self,
        cursor: &mut crate::parse::Reader,
    ) -> Option<crate::headers::Header> {
        use crate::headers::Header;
        use crate::icmp4::Icmp4;
        use crate::parse::ParseHeader;
        use crate::tcp::Tcp;
        use crate::udp::Udp;
        use etherparse::IpNumber;
        use tracing::trace;

        match self.next_header().into() {
            IpNumber::TCP => cursor.parse_header::<Tcp, Header>(),
            IpNumber::UDP => cursor.parse_header::<Udp, Header>(),
            IpNumber::ICMP => cursor.parse_header::<Icmp4, Header>(),
            IpNumber::AUTHENTICATION_HEADER => cursor.parse_header::<Ipv4Auth, Header>(),
            _ => {
                trace!("unsupported protocol: {:?}", self.next_header());
                None
            }
        }
    }

    /// Parse the next header in an ICMP-embedded context (IPv4).
    pub(crate) fn parse_embedded_payload(
        &self,
        cursor: &mut crate::parse::Reader,
    ) -> Option<crate::headers::EmbeddedHeader> {
        use crate::headers::EmbeddedHeader;
        use crate::parse::ParseHeader;
        use crate::tcp::TruncatedTcp;
        use crate::udp::TruncatedUdp;
        use etherparse::IpNumber;
        use tracing::trace;

        match self.next_header().into() {
            IpNumber::TCP => cursor.parse_header::<TruncatedTcp, EmbeddedHeader>(),
            IpNumber::UDP => cursor.parse_header::<TruncatedUdp, EmbeddedHeader>(),
            IpNumber::AUTHENTICATION_HEADER => cursor.parse_header::<Ipv4Auth, EmbeddedHeader>(),
            _ => {
                trace!("unsupported protocol: {:?}", self.next_header());
                None
            }
        }
    }
}

impl Deref for Ipv4Auth {
    type Target = IpAuth;

    fn deref(&self) -> &IpAuth {
        &self.0
    }
}

impl DerefMut for Ipv4Auth {
    fn deref_mut(&mut self) -> &mut IpAuth {
        &mut self.0
    }
}

impl From<IpAuth> for Ipv4Auth {
    fn from(inner: IpAuth) -> Self {
        Self(inner)
    }
}

impl From<Ipv4Auth> for IpAuth {
    fn from(outer: Ipv4Auth) -> Self {
        outer.0
    }
}

impl Parse for Ipv4Auth {
    type Error = <IpAuth as Parse>::Error;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let (inner, consumed) = IpAuth::parse(buf)?;
        Ok((Self(inner), consumed))
    }
}

impl DeParse for Ipv4Auth {
    type Error = <IpAuth as DeParse>::Error;

    fn size(&self) -> NonZero<u16> {
        self.0.size()
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        self.0.deparse(buf)
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::Ipv4Auth;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for Ipv4Auth {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Ipv4Auth::new(driver.produce()?))
        }
    }
}
