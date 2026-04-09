// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP authentication header type and logic.

pub mod v4;
pub mod v6;

pub use v4::Ipv4Auth;
pub use v6::Ipv6Auth;

use crate::ip::NextHeader;
use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError};
use etherparse::IpAuthHeader;
use std::num::NonZero;

/// An IP authentication header.
///
/// This may appear in IPv4 and IPv6 headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAuth(Box<IpAuthHeader>);

impl From<Box<IpAuthHeader>> for IpAuth {
    fn from(inner: Box<IpAuthHeader>) -> Self {
        Self(inner)
    }
}

impl IpAuth {
    /// Get the next-header protocol number.
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        NextHeader::from(self.0.next_header)
    }

    /// Set the next-header protocol number.
    pub fn set_next_header(&mut self, nh: NextHeader) {
        self.0.next_header = nh.into();
    }
}

impl Parse for IpAuth {
    type Error = etherparse::err::ip_auth::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = IpAuthHeader::from_slice(buf)
            .map(|(h, rest)| (Box::new(h), rest))
            .map_err(ParseError::Invalid)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok((Self(inner), consumed))
    }
}

impl DeParse for IpAuth {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // IpAuthHeader length is bounded
        NonZero::new(self.0.header_len() as u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        let bytes = self.0.to_bytes();
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(self.size())
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::IpAuth;
    use bolero::{Driver, TypeGenerator};
    use etherparse::{IpAuthHeader, IpNumber};

    /// Valid ICV lengths (multiples of 4).
    ///
    /// Includes the boundaries: 0 (minimum), small values for fast fuzzing,
    /// and `MAX_ICV_LEN` (1016) to cover the upper limit.
    const VALID_ICV_LENS: [usize; 5] = [0, 4, 8, 12, IpAuthHeader::MAX_ICV_LEN];

    impl TypeGenerator for IpAuth {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let next_header: u8 = driver.produce()?;
            let spi: u32 = driver.produce()?;
            let sequence_number: u32 = driver.produce()?;
            let idx = driver.gen_usize(
                std::ops::Bound::Included(&0),
                std::ops::Bound::Excluded(&VALID_ICV_LENS.len()),
            )?;
            let icv_len = VALID_ICV_LENS[idx];
            let mut icv = vec![0u8; icv_len];
            for byte in &mut icv {
                *byte = driver.produce()?;
            }
            #[allow(clippy::unwrap_used)] // lengths are valid by construction
            let header =
                IpAuthHeader::new(IpNumber(next_header), spi, sequence_number, &icv).unwrap();
            Some(IpAuth::from(Box::new(header)))
        }
    }
}
