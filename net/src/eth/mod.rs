// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ethernet types

pub mod ethtype;
pub mod mac;

use crate::eth::ethtype::EthType;
use crate::eth::mac::{
    DestinationMac, DestinationMacAddressError, Mac, SourceMac, SourceMacAddressError,
};
use crate::headers::Header;
use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError, ParsePayload, Reader};
use crate::vlan::Vlan;
use etherparse::{EtherType, Ethernet2Header};
use std::num::NonZero;
use tracing::{debug, trace};

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "arbitrary"))]
pub use contract::*;

/// An [ethernet header]
///
/// [ethernet header]: https://en.wikipedia.org/wiki/Ethernet_frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eth(Ethernet2Header);

/// An error which may occur in the event of an invalid ethernet header.
#[derive(Debug, thiserror::Error)]
pub enum EthError {
    /// Source [`Mac`] is invalid.
    #[error(transparent)]
    InvalidSource(SourceMacAddressError),
    /// Dest [`Mac`] is invalid.
    #[error(transparent)]
    InvalidDestination(DestinationMacAddressError),
}

impl Eth {
    /// The length (in bytes) of an [`Eth`] header
    #[allow(clippy::unwrap_used)] // trivially safe const eval
    pub const HEADER_LEN: NonZero<u16> = NonZero::new(14).unwrap();

    /// Create a new [Eth] header.
    #[must_use]
    pub fn new(source: SourceMac, destination: DestinationMac, ether_type: EthType) -> Eth {
        Eth(Ethernet2Header {
            source: source.inner().0,
            destination: destination.inner().0,
            ether_type: ether_type.0,
        })
    }

    /// Get the source [`Mac`] of the header.
    #[must_use]
    pub fn source(&self) -> SourceMac {
        #[allow(unsafe_code)] // checked in ctor and parse methods
        unsafe {
            SourceMac::new_unchecked(Mac(self.0.source))
        }
    }

    /// Get the destination [`Mac`] of the header.
    #[must_use]
    pub fn destination(&self) -> DestinationMac {
        #[allow(unsafe_code)] // checked in ctor and parse methods
        unsafe {
            DestinationMac::new_unchecked(Mac(self.0.destination))
        }
    }

    /// Get the [`EthType`] of the header.
    #[must_use]
    pub fn ether_type(&self) -> EthType {
        EthType(self.0.ether_type)
    }

    /// Set the source [`Mac`] of the ethernet header.
    pub fn set_source(&mut self, source: SourceMac) -> &mut Self {
        self.0.source = source.inner().0;
        self
    }

    /// Set the destination [`Mac`] of the ethernet header.
    pub fn set_destination(&mut self, destination: DestinationMac) -> &mut Self {
        self.0.destination = destination.inner().0;
        self
    }

    /// Set the ethertype of the header.
    pub(crate) fn set_ether_type(&mut self, ether_type: EthType) -> &mut Self {
        self.0.ether_type = ether_type.0;
        self
    }
}

impl Parse for Eth {
    type Error = EthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = Ethernet2Header::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::Length(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        let new = Self(inner);
        // integrity check for ethernet header
        new.destination()
            .inner()
            .valid_dst()
            .map_err(|e| ParseError::Invalid(EthError::InvalidDestination(e)))?;
        new.source()
            .inner()
            .valid_src()
            .map_err(|e| ParseError::Invalid(EthError::InvalidSource(e)))?;
        Ok((new, consumed))
    }
}

impl DeParse for Eth {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // Eth headers have fixed length
        NonZero::new(self.0.header_len() as u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let len = buf.len();
        if buf.len() > u16::MAX as usize {
            return Err(DeParseError::BufferTooLong(len));
        }
        let unused = self.0.write_to_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            DeParseError::Length(LengthError {
                expected,
                actual: len,
            })
        })?;
        assert!(
            unused.len() < len,
            "unused.len() >= buf.len() ({unused} >= {len})",
            unused = unused.len(),
        );
        #[allow(clippy::cast_possible_truncation)] // buffer len upper bounded already
        let consumed = NonZero::new((len - unused.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok(consumed)
    }
}

pub(crate) fn parse_from_ethertype(ether_type: EtherType, cursor: &mut Reader) -> Option<EthNext> {
    match ether_type {
        EtherType::IPV4 => cursor
            .parse::<Ipv4>()
            .map_err(|e| {
                debug!("failed to parse ipv4: {:?}", e);
            })
            .map(|(ipv4, _)| EthNext::Ipv4(ipv4))
            .ok(),
        EtherType::IPV6 => cursor
            .parse::<Ipv6>()
            .map_err(|e| {
                debug!("failed to parse ipv6: {:?}", e);
            })
            .map(|(ipv6, _)| EthNext::Ipv6(ipv6))
            .ok(),
        EtherType::VLAN_TAGGED_FRAME
        | EtherType::VLAN_DOUBLE_TAGGED_FRAME
        | EtherType::PROVIDER_BRIDGING => cursor
            .parse::<Vlan>()
            .map_err(|e| {
                debug!("failed to parse vlan: {:?}", e);
            })
            .map(|(vlan, _)| EthNext::Vlan(vlan))
            .ok(),
        _ => {
            trace!("unsupported ether type: {:?}", ether_type);
            None
        }
    }
}

pub(crate) enum EthNext {
    Vlan(Vlan),
    Ipv4(Ipv4),
    Ipv6(Ipv6),
}

impl ParsePayload for Eth {
    type Next = EthNext;
    fn parse_payload(&self, cursor: &mut Reader) -> Option<EthNext> {
        parse_from_ethertype(self.0.ether_type, cursor)
    }
}

impl From<EthNext> for Header {
    fn from(value: EthNext) -> Self {
        match value {
            EthNext::Vlan(x) => Header::Vlan(x),
            EthNext::Ipv4(x) => Header::Ipv4(x),
            EthNext::Ipv6(x) => Header::Ipv6(x),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::eth::Eth;
    use crate::eth::ethtype::EthType;
    use crate::eth::mac::{DestinationMac, SourceMac};
    use bolero::{Driver, TypeGenerator, ValueGenerator};

    /// Generate an [`Eth`] with a specific [`EthType`]
    #[repr(transparent)]
    pub struct GenWithEthType(pub EthType);

    impl ValueGenerator for GenWithEthType {
        type Output = Eth;
        /// Generate an [`Eth`] with the [`EthType`] specified in `Self`
        fn generate<D: Driver>(&self, u: &mut D) -> Option<Self::Output> {
            let source_mac: SourceMac = u.r#gen()?;
            let destination_mac: DestinationMac = u.r#gen()?;
            let eth = Eth::new(source_mac, destination_mac, self.0);
            Some(eth)
        }
    }

    impl TypeGenerator for Eth {
        /// Generate an arbitrary [`Eth`] header
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            GenWithEthType(u.r#gen()?).generate(u)
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)] // valid in test code for unreachable cases
#[cfg(test)]
mod test {
    const HEADER_LEN_USIZE: usize = Eth::HEADER_LEN.get() as usize;
    use crate::eth::{DestinationMacAddressError, Eth, EthError, SourceMacAddressError};
    use crate::parse::{DeParse, IntoNonZeroUSize, Parse, ParseError};

    #[test]
    fn parse_back() {
        bolero::check!().with_type().for_each(|eth: &Eth| {
            assert!(eth.source().inner().valid_src().is_ok());
            assert!(eth.destination().inner().valid_dst().is_ok());
            let mut buf = [0u8; HEADER_LEN_USIZE];
            eth.deparse(&mut buf).unwrap();
            let (eth2, consumed) = Eth::parse(&buf).unwrap();
            assert_eq!(eth, &eth2);
            assert_eq!(consumed, Eth::HEADER_LEN);
        });
    }

    fn parse_buffer_of_fixed_length<const LEN: usize>(buf: &[u8; LEN]) {
        let outcome = Eth::parse(buf);
        match outcome {
            Ok((eth, consumed)) => {
                assert!(buf.len() >= Eth::HEADER_LEN.into_non_zero_usize().get());
                assert_eq!(consumed, Eth::HEADER_LEN);
                assert!(eth.source().inner().valid_src().is_ok());
                assert!(eth.destination().inner().valid_dst().is_ok());
                let mut buf2 = [0u8; HEADER_LEN_USIZE];
                eth.deparse(&mut buf2).unwrap();
                let (eth2, consumed2) = Eth::parse(&buf2).unwrap();
                assert_eq!(eth, eth2);
                assert_eq!(consumed2, Eth::HEADER_LEN);
            }
            Err(ParseError::Length(e)) => {
                assert_eq!(e.expected, Eth::HEADER_LEN.into_non_zero_usize());
                assert_eq!(e.actual, buf.len());
                assert!(buf.len() < Eth::HEADER_LEN.into_non_zero_usize().get());
            }
            Err(ParseError::Invalid(
                EthError::InvalidDestination(DestinationMacAddressError::ZeroDestination(z))
                | EthError::InvalidSource(SourceMacAddressError::ZeroSource(z)),
            )) => {
                assert!(buf.len() >= Eth::HEADER_LEN.into_non_zero_usize().get());
                assert!(z.is_zero());
            }
            Err(ParseError::Invalid(EthError::InvalidSource(
                SourceMacAddressError::MulticastSource(m),
            ))) => {
                assert!(buf.len() >= Eth::HEADER_LEN.into_non_zero_usize().get());
                assert!(m.is_multicast());
            }
            Err(ParseError::BufferTooLong(e)) => {
                assert_eq!(e, buf.len());
            }
        }
    }

    #[test]
    fn parse_arbitrary_bytes() {
        bolero::check!()
            .with_type()
            .for_each(parse_buffer_of_fixed_length::<{ HEADER_LEN_USIZE }>);
    }

    #[test]
    fn parse_prop_test_buffer_too_short() {
        bolero::check!()
            .with_type()
            .for_each(parse_buffer_of_fixed_length::<{ HEADER_LEN_USIZE - 1 }>);
    }

    #[test]
    fn parse_prop_test_excess_buffer() {
        bolero::check!()
            .with_type()
            .for_each(parse_buffer_of_fixed_length::<{ HEADER_LEN_USIZE + 1 }>);
    }
}
