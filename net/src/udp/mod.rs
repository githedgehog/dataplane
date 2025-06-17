// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! UDP header type and logic.

mod checksum;
pub mod port;

pub use checksum::*;

use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParsePayload, Reader,
};
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
    pub const MIN_LENGTH: NonZero<u16> = NonZero::new(8).unwrap();

    /// Build an empty UDP header, without checksum and with the length equal to the header only length
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn empty() -> Self {
        Udp(UdpHeader {
            source_port: 0,
            destination_port: 0,
            length: (UdpHeader::LEN as u16),
            checksum: 0,
        })
    }

    #[allow(missing_docs)] // TODO
    #[must_use]
    pub fn new(source: UdpPort, destination: UdpPort) -> Udp {
        let header = UdpHeader {
            source_port: source.into(),
            destination_port: destination.into(),
            ..Default::default()
        };
        Udp(header)
    }

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

    /// Set the length of the udp packet (includes the udp header length of eight bytes).
    ///
    /// # Safety
    ///
    /// If you set the length to zero (or anything less than [`Udp::MIN_LENGTH`]) then this is sure
    /// to be unsound.
    #[allow(unsafe_code)]
    pub unsafe fn set_length(&mut self, length: NonZero<u16>) -> &mut Self {
        debug_assert!(
            length >= Udp::MIN_LENGTH,
            "udp length must be at least 8 bytes, got: {length:#x}",
        );
        self.0.length = length.get();
        self
    }

    fn compute_checksum_ipv4(&self, net: &Ipv4, payload: impl AsRef<[u8]>) -> UdpChecksum {
        #[allow(clippy::expect_used)] // payload greater than 2^16 bytes should be excluded by DPDK
        self.0
            .calc_checksum_ipv4(&net.0, payload.as_ref())
            .expect("unreasonable payload")
            .into()
    }

    fn compute_checksum_ipv6(&self, net: &Ipv6, payload: impl AsRef<[u8]>) -> UdpChecksum {
        #[allow(clippy::expect_used)] // payload greater than 2^16 bytes should be excluded by DPDK
        self.0
            .calc_checksum_ipv6(&net.0, payload.as_ref())
            .expect("unreasonable payload")
            .into()
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

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
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
        #[allow(clippy::cast_possible_truncation)] // size of buffer bounded above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).unwrap_or_else(|| unreachable!());
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

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // bounded size for header
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
        buf[..self.size().into_non_zero_usize().get()].copy_from_slice(&self.0.to_bytes());
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

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::checksum::Checksum;
    use crate::udp::Udp;
    use bolero::{Driver, TypeGenerator};
    use etherparse::UdpHeader;
    use std::num::NonZero;

    impl TypeGenerator for Udp {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            const MIN_LENGTH: u16 = Udp::MIN_LENGTH.get();
            let mut header = Udp(UdpHeader::default());
            header.set_source(u.produce()?);
            header.set_destination(u.produce()?);
            header.set_checksum(u.produce()?);
            let length = u.produce::<u16>()?;
            match length {
                #[allow(unsafe_code)] // trivially safe const-eval
                0..MIN_LENGTH => unsafe {
                    header.set_length(Udp::MIN_LENGTH);
                },
                MIN_LENGTH.. => {
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

#[cfg(test)]
mod test {
    use crate::checksum::Checksum;
    use crate::parse::IntoNonZeroUSize;
    use crate::parse::Parse;
    use crate::parse::{DeParse, ParseError};
    use crate::udp::{Udp, UdpParseError};

    const MIN_LENGTH_USIZE: usize = 8;

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_back() {
        bolero::check!().with_type().for_each(|input: &Udp| {
            let mut buffer = [0u8; MIN_LENGTH_USIZE];
            let consumed = match input.deparse(&mut buffer) {
                Ok(consumed) => consumed,
                Err(err) => {
                    unreachable!("failed to write udp: {err:?}");
                }
            };
            assert_eq!(consumed.into_non_zero_usize().get(), buffer.len());
            let (parse_back, consumed2) =
                Udp::parse(&buffer[..consumed.into_non_zero_usize().get()]).unwrap();
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
            .for_each(|slice: &[u8; MIN_LENGTH_USIZE]| {
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
                    Err(ParseError::BufferTooLong(_)) => unreachable!(),
                };
                let mut slice2 = [0u8; 8];
                let bytes_written = parsed.deparse(&mut slice2).unwrap_or_else(|e| {
                    unreachable!("{e:?}");
                });
                assert_eq!(bytes_read.into_non_zero_usize().get(), slice.len());
                assert_eq!(bytes_written.into_non_zero_usize().get(), slice.len());
                assert_eq!(slice, &slice2);
            });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn too_short_buffer_parse_fails_gracefully() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; MIN_LENGTH_USIZE - 1]| {
                for i in 0..slice.len() {
                    match Udp::parse(&slice[..i]) {
                        Err(ParseError::Length(e)) => {
                            assert_eq!(e.expected, Udp::MIN_LENGTH.into_non_zero_usize());
                            assert_eq!(e.actual, i);
                        }
                        _ => unreachable!(),
                    }
                }
            });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn longer_buffer_parses_ok() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; 2 * MIN_LENGTH_USIZE]| {
                for _ in MIN_LENGTH_USIZE..slice.len() {
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
                        Err(ParseError::BufferTooLong(_)) => unreachable!(),
                    };
                    let mut slice2 = [0u8; MIN_LENGTH_USIZE];
                    let bytes_written = parsed.deparse(&mut slice2).unwrap_or_else(|e| {
                        unreachable!("{e:?}");
                    });
                    assert_eq!(bytes_read, Udp::MIN_LENGTH);
                    assert_eq!(bytes_written, Udp::MIN_LENGTH);
                    assert_eq!(&slice[..MIN_LENGTH_USIZE], &slice2);
                }
            });
    }

    // evolve an arbitrary source towards an arbitrary target to make sure mutation methods work
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn arbitrary_mutation() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|(mut source, target): (Udp, Udp)| {
                if source == target {
                    return;
                }
                let mut target_bytes = [0u8; MIN_LENGTH_USIZE];
                target
                    .deparse(&mut target_bytes)
                    .unwrap_or_else(|e| unreachable!("{e:?}", e = e));
                source.set_source(target.source());
                assert_eq!(source.source(), target.source());
                source.set_destination(target.destination());
                assert_eq!(source.destination(), target.destination());
                #[allow(unsafe_code)] // valid in test context
                unsafe {
                    source.set_length(target.length());
                }
                assert_eq!(source.length(), target.length());
                source.set_checksum(target.checksum());
                assert_eq!(source.checksum(), target.checksum());
                assert_eq!(source, target);
                let mut source_bytes = [0u8; MIN_LENGTH_USIZE];
                source
                    .deparse(&mut source_bytes)
                    .unwrap_or_else(|e| unreachable!("{e:?}", e = e));
                assert_eq!(source_bytes, target_bytes);
            });
    }
}
