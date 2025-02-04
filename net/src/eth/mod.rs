// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ethernet types

pub mod ethertype;
pub mod mac;

use crate::eth::ethertype::EthType;
use crate::eth::mac::{DestinationMac, Mac, SourceMac};
use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::packet::Header;
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError, ParsePayload, Reader};
use crate::vlan::Vlan;
use etherparse::{EtherType, Ethernet2Header};
use std::num::NonZero;
use tracing::{debug, trace};

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "arbitrary"))]
pub use contract::*;

/// An ethernet header.
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

/// Errors which can occur while setting the source [`Mac`] of a [`Packet`]
#[derive(Debug, thiserror::Error)]
pub enum SourceMacAddressError {
    /// Multicast [`Macs`] are not legal as source [`Mac`]
    #[error("invalid source mac address: multicast macs are illegal as source macs")]
    MulticastSource(Mac),
    /// Zero is not a legal source
    #[error("invalid source mac address: zero mac is illegal as source mac")]
    ZeroSource(Mac),
}

/// Errors which can occur while setting the destination [`Mac`] of a [`Packet`]
#[derive(Debug, thiserror::Error)]
pub enum DestinationMacAddressError {
    /// Zero is not a legal source
    #[error("invalid destination mac address: zero mac is illegal as destination mac")]
    ZeroDestination(Mac),
}

impl Eth {
    /// The length (in bytes) of an [`Eth`] header
    pub const HEADER_LEN: usize = 14;

    /// Create a new [Eth] header.
    ///
    /// # Errors
    ///
    /// This function will return an error if the specified source or dest [Mac] are invalid.
    pub fn new(source: Mac, destination: Mac, ether_type: EthType) -> Result<Eth, EthError> {
        let mut header = Eth(Ethernet2Header {
            source: source.0,
            destination: destination.0,
            ether_type: ether_type.0,
        });
        header
            .set_source_checked(source)
            .map_err(EthError::InvalidSource)?;
        header
            .set_destination(destination)
            .map_err(EthError::InvalidDestination)?;
        Ok(header)
    }

    /// Get the source [Mac] of the header.
    #[must_use]
    pub fn source(&self) -> Mac {
        Mac(self.0.source)
    }

    /// Get the destination [Mac] of the header.
    #[must_use]
    pub fn destination(&self) -> Mac {
        Mac(self.0.destination)
    }

    /// Get the ethertype of the header.
    #[must_use]
    pub fn ether_type(&self) -> EthType {
        EthType(self.0.ether_type)
    }

    /// Set the source [Mac] of the ethernet header.
    ///
    /// # Errors
    ///
    /// Will refuse to set an invalid source [`Mac`] (e.g., multicast or zero).
    pub fn set_source(&mut self, source: SourceMac) -> Result<&mut Eth, SourceMacAddressError> {
        #[allow(unsafe_code)] // check immediately above
        Ok(unsafe { self.set_source_unchecked(source.inner()) })
    }

    /// Set the source [Mac] of the ethernet header.
    ///
    /// # Errors
    ///
    /// Will refuse to set an invalid source [`Mac`] (e.g., multicast or zero).
    pub fn set_source_checked(&mut self, source: Mac) -> Result<&mut Eth, SourceMacAddressError> {
        if source.is_zero() {
            return Err(SourceMacAddressError::ZeroSource(source));
        }
        if source.is_multicast() {
            return Err(SourceMacAddressError::MulticastSource(source));
        }
        #[allow(unsafe_code)] // check immediately above
        Ok(unsafe { self.set_source_unchecked(source) })
    }

    /// Set the destination [Mac] of the ethernet header.
    ///
    /// # Errors
    ///
    /// Will refuse to set zero as the dest [Mac].
    pub fn set_destination(
        &mut self,
        destination: Mac,
    ) -> Result<&mut Eth, DestinationMacAddressError> {
        if !destination.is_valid_dst() {
            return Err(DestinationMacAddressError::ZeroDestination(destination));
        }
        Ok(self.set_destination_unchecked(destination))
    }

    /// Set the source [Mac] of the header.
    ///
    /// # Safety
    ///
    /// This method does not check that the [Mac] is a valid source [Mac].
    #[allow(unsafe_code)] // documented unsafe
    pub unsafe fn set_source_unchecked(&mut self, source: Mac) -> &mut Eth {
        debug_assert!(source.is_valid_src());
        self.0.source = source.0;
        self
    }

    /// Set the destination [Mac] of the header.
    ///
    /// # Safety
    ///
    /// This method does not check that the [Mac] is a valid dest [Mac].
    pub fn set_destination_unchecked(&mut self, destination: Mac) -> &mut Eth {
        debug_assert!(destination.is_valid_dst());
        self.0.destination = destination.0;
        self
    }

    /// Set the ethertype of the header.
    pub fn set_ether_type(&mut self, ether_type: EtherType) -> &mut Eth {
        self.0.ether_type = ether_type;
        self
    }
}

impl Parse for Eth {
    type Error = EthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
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
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        let new = Self(inner);
        // integrity check for ethernet header (slightly hacky)
        SourceMac::new(new.source())
            .map_err(|e| ParseError::Invalid(EthError::InvalidSource(e)))?;
        DestinationMac::new(new.destination())
            .map_err(|e| ParseError::Invalid(EthError::InvalidDestination(e)))?;
        Ok((new, consumed))
    }
}

impl DeParse for Eth {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.0.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
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
        let consumed = NonZero::new(len - unused.len()).ok_or_else(|| unreachable!())?;
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
    use crate::eth::ethertype::EthType;
    use crate::eth::mac::{DestinationMac, SourceMac};
    use crate::eth::Eth;
    use arbitrary::{Arbitrary, Unstructured};

    impl<'a> Arbitrary<'a> for Eth {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let source_mac: SourceMac = u.arbitrary()?;
            let destination_mac: DestinationMac = u.arbitrary()?;
            let ether_type: EthType = u.arbitrary()?;
            let eth = Eth::new(source_mac.inner(), destination_mac.inner(), ether_type)
                .unwrap_or_else(|e| unreachable!("{e:?}"));
            Ok(eth)
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)] // valid in test code for unreachable cases
#[cfg(test)]
mod test {
    use crate::eth::{DestinationMacAddressError, Eth, EthError, SourceMacAddressError};
    use crate::parse::{DeParse, Parse, ParseError};

    #[test]
    fn eth_parse_back() {
        bolero::check!().with_arbitrary().for_each(|eth: &Eth| {
            assert!(eth.source().is_valid_src());
            assert!(eth.destination().is_valid_dst());
            let mut buf = [0u8; Eth::HEADER_LEN];
            eth.deparse(&mut buf).unwrap();
            let (eth2, consumed) = Eth::parse(&buf).unwrap();
            assert_eq!(eth, &eth2);
            assert_eq!(consumed.get(), Eth::HEADER_LEN);
        });
    }

    fn parse_buffer_of_fixed_length<const LEN: usize>(buf: &[u8; LEN]) {
        let outcome = Eth::parse(buf);
        match outcome {
            Ok((eth, consumed)) => {
                assert!(buf.len() >= Eth::HEADER_LEN);
                assert_eq!(consumed.get(), Eth::HEADER_LEN);
                assert!(eth.source().is_valid_src());
                assert!(eth.destination().is_valid_dst());
                let mut buf2 = [0u8; 14];
                eth.deparse(&mut buf2).unwrap();
                let (eth2, consumed2) = Eth::parse(&buf2).unwrap();
                assert_eq!(eth, eth2);
                assert_eq!(consumed2.get(), Eth::HEADER_LEN);
            }
            Err(ParseError::Length(e)) => {
                assert_eq!(e.expected.get(), Eth::HEADER_LEN);
                assert_eq!(e.actual, buf.len());
                assert!(buf.len() < Eth::HEADER_LEN);
            }
            Err(ParseError::Invalid(
                EthError::InvalidDestination(DestinationMacAddressError::ZeroDestination(z))
                | EthError::InvalidSource(SourceMacAddressError::ZeroSource(z)),
            )) => {
                assert!(buf.len() >= Eth::HEADER_LEN);
                assert!(z.is_zero());
            }
            Err(ParseError::Invalid(EthError::InvalidSource(
                SourceMacAddressError::MulticastSource(m),
            ))) => {
                assert!(buf.len() >= Eth::HEADER_LEN);
                assert!(m.is_multicast());
            }
        }
    }

    #[test]
    fn parse_prop_test_basic() {
        bolero::check!()
            .with_arbitrary()
            .for_each(parse_buffer_of_fixed_length::<{ Eth::HEADER_LEN }>);
    }

    #[test]
    fn parse_prop_test_buffer_too_short() {
        bolero::check!()
            .with_arbitrary()
            .for_each(parse_buffer_of_fixed_length::<{ Eth::HEADER_LEN - 1 }>);
    }

    #[test]
    fn parse_prop_test_excess_buffer() {
        bolero::check!()
            .with_arbitrary()
            .for_each(parse_buffer_of_fixed_length::<{ Eth::HEADER_LEN + 1 }>);
    }
}
