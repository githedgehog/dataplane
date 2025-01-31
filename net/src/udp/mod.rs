// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! UDP header type and logic.

pub mod port;

use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError};
use crate::udp::port::UdpPort;
use etherparse::UdpHeader;
use std::num::NonZero;

/// A UDP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    inner: UdpHeader,
}

impl Udp {
    /// The minimum length of a valid UDP header (technically also the maximum length).
    /// The name choice here is for consistency with other header types.
    #[allow(unsafe_code)] // trivially safe const-eval
    pub const MIN_LENGTH: NonZero<usize> = unsafe { NonZero::new_unchecked(8) };

    /// Get the header's source port
    #[must_use]
    pub const fn source(&self) -> UdpPort {
        debug_assert!(self.inner.source_port != 0);
        #[allow(unsafe_code)] // non-zero checked in [`Parse`] and `new`.
        unsafe {
            UdpPort::new_unchecked(self.inner.source_port)
        }
    }

    /// Get the header's dest port
    #[must_use]
    pub const fn destination(&self) -> UdpPort {
        debug_assert!(self.inner.destination_port != 0);
        #[allow(unsafe_code)] // non-zero checked in [`Parse`] and `new`.
        unsafe {
            UdpPort::new_unchecked(self.inner.destination_port)
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
            NonZero::new_unchecked(self.inner.length)
        }
    }

    /// Get the header's checksum.  No attempt is made to ensure that the checksum is correct.
    #[must_use]
    pub fn checksum(&self) -> u16 {
        self.inner.checksum
    }

    /// Set the source port.
    pub fn set_source(&mut self, port: UdpPort) -> &mut Self {
        self.inner.source_port = port.into();
        self
    }

    /// Set the destination port.
    pub fn set_destination(&mut self, port: UdpPort) -> &mut Self {
        self.inner.destination_port = port.into();
        self
    }

    /// Set the udp checksum.  No attempt is made to ensure the checksum is correct.
    pub fn set_checksum(&mut self, checksum: u16) -> &mut Self {
        self.inner.checksum = checksum;
        self
    }

    /// Set the length of the udp packet (includes the udp header length of eight bytes).
    ///
    /// # Safety
    ///
    /// If you set the length to zero (or anything less than 8) then this is sure to be unsound.
    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_truncation)] // trivially valid since MIN_LENGTH is small
    pub unsafe fn set_length(&mut self, length: u16) -> &mut Self {
        debug_assert!(
            length >= Udp::MIN_LENGTH.get() as u16,
            "udp length must be at least 8 bytes, got: {length:#x}",
        );
        self.inner.length = length;
        self
    }
}

impl Parse for Udp {
    type Error = LengthError;

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
        Ok((Self { inner }, consumed))
    }
}

impl DeParse for Udp {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.inner.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size(),
                actual: len,
            }));
        };
        buf[..self.size().get()].copy_from_slice(&self.inner.to_bytes());
        Ok(self.size())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::udp::Udp;
    use arbitrary::{Arbitrary, Unstructured};
    use etherparse::UdpHeader;

    impl<'a> Arbitrary<'a> for Udp {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut header = Udp {
                inner: UdpHeader::default(),
            };
            header.set_source(u.arbitrary()?);
            header.set_destination(u.arbitrary()?);
            header.set_checksum(u.arbitrary()?);
            // Safety:
            // This is sound in-so-far as the whole point of this method is to generate potentially
            // hostile values which are used to test the soundness of the code.
            // Strict soundness here would itself be unsound :)
            #[allow(unsafe_code)]
            #[allow(clippy::cast_possible_truncation)]
            // trivially sound since MIN_LENGTH is small
            unsafe {
                header.set_length(u.int_in_range((Self::MIN_LENGTH.get() as u16)..=u16::MAX)?);
            }
            Ok(header)
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)] // valid in test code
#[cfg(test)]
mod test {
    use crate::parse::{DeParse, Parse};
    use crate::udp::Udp;

    #[test]
    fn parse_back() {
        bolero::check!().with_arbitrary().for_each(|input: &Udp| {
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
            assert_eq!(consumed, consumed2);
        });
    }

    #[test]
    fn parse_noise() {
        bolero::check!()
            .with_arbitrary()
            .for_each(|slice: &[u8; 8]| {
                let (parsed, bytes_read) =
                    Udp::parse(slice).unwrap_or_else(|e| unreachable!("{e:?}"));
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
