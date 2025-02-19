// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! UDP header type and logic.

pub mod checksum;
pub mod port;

use crate::packet::Header;
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError, ParsePayload, Reader};
use crate::udp::port::UdpPort;
use crate::vxlan::Vxlan;
use etherparse::UdpHeader;
use std::num::NonZero;
use tracing::debug;

/// A UDP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp(UdpHeader);

/// A UDP encapsulation.
///
/// At this point we only support VXLAN, but Geneve and others can be added as needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpEncap {
    /// A VXLAN header in a UDP packet
    Vxlan(Vxlan),
}

impl Udp {
    /// The minimum length of a valid UDP header (technically also the maximum length).
    /// The name choice here is for consistency with other header types.
    #[allow(clippy::unwrap_used)] // safe due to const-eval
    pub const MIN_LENGTH: NonZero<usize> = NonZero::new(8).unwrap();

    /// Get the header's source port
    #[must_use]
    pub const fn source(&self) -> UdpPort {
        debug_assert!(self.0.source_port != 0);
        #[allow(unsafe_code)] // non-zero checked in [`Parse`] and `new`.
        unsafe {
            UdpPort::new_unchecked(self.0.source_port)
        }
    }

    /// Get the header's dest port
    #[must_use]
    pub const fn destination(&self) -> UdpPort {
        debug_assert!(self.0.destination_port != 0);
        #[allow(unsafe_code)] // non-zero checked in [`Parse`] and `new`.
        unsafe {
            UdpPort::new_unchecked(self.0.destination_port)
        }
    }

    /// The length of the packet (including the 8-byte udp header).
    ///
    /// No attempt is made to ensure this value is correct (you can't always trust the packet).
    #[must_use]
    pub fn length(&self) -> NonZero<u16> {
        // safety: safety ensured by constructors
        #[allow(unsafe_code)]
        unsafe {
            NonZero::new_unchecked(self.0.length)
        }
    }

    /// Get the header's checksum.  No attempt is made to ensure that the checksum is correct.
    #[must_use]
    pub fn checksum(&self) -> u16 {
        self.0.checksum
    }

    /// Set the source port.
    pub fn set_source(&mut self, port: UdpPort) -> &mut Self {
        self.0.source_port = port.into();
        self
    }

    /// Set the destination port.
    pub fn set_destination(&mut self, port: UdpPort) -> &mut Self {
        self.0.destination_port = port.into();
        self
    }

    /// Set the udp checksum.  No attempt is made to ensure the checksum is correct.
    pub fn set_checksum(&mut self, checksum: u16) -> &mut Self {
        self.0.checksum = checksum;
        self
    }

    /// Set the length of the udp packet (includes the udp header length of eight bytes).
    ///
    /// # Safety
    ///
    /// If you set the length to zero (or anything less than 8) then this is sure to be unsound.
    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_truncation)] // trivially valid since MIN_LENGTH is small
    pub unsafe fn set_length(&mut self, length: NonZero<u16>) -> &mut Self {
        debug_assert!(
            length.get() >= Udp::MIN_LENGTH.get() as u16,
            "udp length must be at least 8 bytes, got: {length:#x}",
        );
        self.0.length = length.get();
        self
    }
}

/// Errors which may occur when parsing a UDP header
#[derive(Debug, thiserror::Error)]
pub enum UdpParseError {
    /// Zero is not a legal udp port
    #[error("zero source port")]
    ZeroSourcePort,
    /// Zero is not a legal udp port
    #[error("zero destination port")]
    ZeroDestinationPort,
}

impl Parse for Udp {
    type Error = UdpParseError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = UdpHeader::from_slice(buf).map_err(|e| {
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
        if inner.source_port == 0 {
            return Err(ParseError::Invalid(UdpParseError::ZeroSourcePort));
        }
        if inner.destination_port == 0 {
            return Err(ParseError::Invalid(UdpParseError::ZeroDestinationPort));
        }
        Ok((Self(inner), consumed))
    }
}

impl DeParse for Udp {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.0.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size(),
                actual: len,
            }));
        }
        buf[..self.size().get()].copy_from_slice(&self.0.to_bytes());
        Ok(self.size())
    }
}

impl ParsePayload for Udp {
    type Next = UdpEncap;

    fn parse_payload(&self, cursor: &mut Reader) -> Option<UdpEncap> {
        match self.destination() {
            Vxlan::PORT => {
                let (vxlan, _) = match cursor.parse::<Vxlan>() {
                    Ok((vxlan, consumed)) => (vxlan, consumed),
                    Err(e) => {
                        debug!("vxlan parse error: {e:?}");
                        return None;
                    }
                };
                Some(UdpEncap::Vxlan(vxlan))
            }
            _ => None,
        }
    }
}

impl From<UdpEncap> for Header {
    fn from(value: UdpEncap) -> Self {
        Header::Encap(value)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::udp::Udp;
    use bolero::{Driver, TypeGenerator};
    use etherparse::UdpHeader;
    use std::num::NonZero;

    impl TypeGenerator for Udp {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            #[allow(clippy::cast_possible_truncation)] // trivially safe
            const MIN_LENGTH: u16 = Udp::MIN_LENGTH.get() as u16;
            let mut header = Udp(UdpHeader::default());
            header.set_source(u.gen()?);
            header.set_destination(u.gen()?);
            header.set_checksum(u.gen()?);
            // Safety:
            // This is sound in-so-far as the whole point of this method is to generate potentially
            // hostile values which are used to test the soundness of the code.
            // Strict soundness here would itself be unsound :)
            #[allow(unsafe_code)]
            #[allow(clippy::cast_possible_truncation)]
            // trivially sound since MIN_LENGTH is small
            let length = u.gen::<u16>()?;
            match length {
                #[allow(unsafe_code)] // trivially safe const-eval
                0..MIN_LENGTH => unsafe {
                    #[allow(clippy::unwrap_used)] // trivially safe const eval
                    header.set_length(const { NonZero::new(MIN_LENGTH).unwrap() });
                },
                MIN_LENGTH..=u16::MAX => {
                    #[allow(unsafe_code)] // trivially safe based on current branch condition
                    unsafe {
                        header.set_length(NonZero::new(length).unwrap_or_else(|| unreachable!()));
                    }
                }
            }
            Some(header)
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)] // valid in test code
#[cfg(test)]
mod test {
    use crate::parse::{DeParse, Parse, ParseError};
    use crate::udp::{Udp, UdpParseError};

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_back() {
        bolero::check!().with_type().for_each(|input: &Udp| {
            let mut buffer = [0u8; 8];
            let consumed = match input.deparse(&mut buffer) {
                Ok(consumed) => consumed,
                Err(err) => {
                    unreachable!("failed to write udp: {err:?}");
                }
            };
            assert_eq!(consumed.get(), buffer.len());
            let (parse_back, consumed2) = Udp::parse(&buffer[..consumed.get()]).unwrap();
            assert_eq!(input, &parse_back);
            assert_eq!(input.source(), parse_back.source());
            assert_eq!(input.destination(), parse_back.destination());
            assert_eq!(input.length(), parse_back.length());
            assert_eq!(input.checksum(), parse_back.checksum());
            assert_eq!(consumed, consumed2);
        });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_arbitrary_bytes() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; Udp::MIN_LENGTH.get()]| {
                let (parsed, bytes_read) = match Udp::parse(slice) {
                    Ok(x) => x,
                    Err(ParseError::Length(e)) => unreachable!("{e:?}", e = e),
                    Err(ParseError::Invalid(UdpParseError::ZeroSourcePort)) => {
                        assert_eq!(slice[0..=1], [0, 0]);
                        return;
                    }
                    Err(ParseError::Invalid(UdpParseError::ZeroDestinationPort)) => {
                        assert_eq!(slice[2..=3], [0, 0]);
                        return;
                    }
                };
                let mut slice2 = [0u8; 8];
                let bytes_written = parsed.deparse(&mut slice2).unwrap_or_else(|e| {
                    unreachable!("{e:?}");
                });
                assert_eq!(bytes_read.get(), slice.len());
                assert_eq!(bytes_written.get(), slice.len());
                assert_eq!(slice, &slice2);
            });
    }
}
