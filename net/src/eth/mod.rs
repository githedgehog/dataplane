//! Ethernet types

pub mod mac;

use crate::eth::mac::{DestinationMacAddressError, EthError, Mac, SourceMacAddressError};
use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::packet::Header;
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError, Reader, Step};
use crate::vlan::Vlan;
use etherparse::{EtherType, Ethernet2Header};
use std::num::NonZero;
use tracing::{debug, trace};

/// An ethernet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eth {
    inner: Ethernet2Header,
}

impl Eth {
    /// Create a new [Eth] header.
    ///
    /// # Errors
    ///
    /// This function will return an error if the specified source or dest [Mac] are invalid.
    pub fn new(source: Mac, destination: Mac, ether_type: EtherType) -> Result<Eth, EthError> {
        let mut header = Eth {
            inner: Ethernet2Header {
                source: source.0,
                destination: destination.0,
                ether_type,
            },
        };
        header.set_source(source).map_err(EthError::InvalidSource)?;
        header
            .set_destination(destination)
            .map_err(EthError::InvalidDestination)?;
        Ok(header)
    }

    /// Get the source [Mac] of the header.
    pub fn source(&self) -> Mac {
        Mac(self.inner.source)
    }

    /// Get the destination [Mac] of the header.
    pub fn destination(&self) -> Mac {
        Mac(self.inner.destination)
    }

    /// Get the ethertype of the header.
    #[must_use]
    pub fn ether_type(&self) -> EtherType {
        self.inner.ether_type
    }

    /// Set the source [Mac] of the ethernet header.
    ///
    /// # Errors
    ///
    /// Will refuse to set an invalid source [`Mac`] (e.g., multicast or zero).
    pub fn set_source(&mut self, source: Mac) -> Result<&mut Eth, SourceMacAddressError> {
        if source.is_zero() {
            return Err(SourceMacAddressError::ZeroSource);
        }
        if source.is_multicast() {
            return Err(SourceMacAddressError::MulticastSource);
        }
        Ok(self.set_source_unchecked(source))
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
        if destination.is_valid_dst() {
            return Err(DestinationMacAddressError::ZeroDestination);
        }
        Ok(self.set_destination_unchecked(destination))
    }

    /// Set the source [Mac] of the header.
    ///
    /// # Safety
    ///
    /// This method does not check that the [Mac] is a valid source [Mac].
    pub fn set_source_unchecked(&mut self, source: Mac) -> &mut Eth {
        debug_assert!(!source.is_valid_src());
        self.inner.source = source.0;
        self
    }

    /// Set the destination [Mac] of the header.
    ///
    /// # Safety
    ///
    /// This method does not check that the [Mac] is a valid dest [Mac].
    pub fn set_destination_unchecked(&mut self, destination: Mac) -> &mut Eth {
        debug_assert!(!destination.is_valid_dst());
        self.inner.destination = destination.0;
        self
    }

    /// Set the ethertype of the header.
    pub fn set_ether_type(&mut self, ether_type: EtherType) -> &mut Eth {
        self.inner.ether_type = ether_type;
        self
    }
}

impl Parse for Eth {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Ethernet2Header::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::LengthError(LengthError {
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
        Ok((Self { inner }, consumed))
    }
}

impl DeParse for Eth {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.inner.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn write(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        let unused = self.inner.write_to_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            DeParseError::LengthError(LengthError {
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

impl Step for Eth {
    type Next = EthNext;
    fn step(&self, cursor: &mut Reader) -> Option<EthNext> {
        parse_from_ethertype(self.inner.ether_type, cursor)
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
