// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! [VXLAN][RFC7348] types and parsing.
//!
//! [RFC7348]: https://datatracker.ietf.org/doc/html/rfc7348#section-5

mod vni;

use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError, ParsePayload, Reader};
use crate::udp::port::UdpPort;
use core::num::NonZero;
use tracing::trace;
pub use vni::{InvalidVni, Vni};

/// A [VXLAN] header
///
/// [VXLAN]: https://en.wikipedia.org/wiki/Virtual_Extensible_LAN
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(bolero::TypeGenerator))]
#[allow(clippy::unsafe_derive_deserialize)] // all uses of unsafe are compile time and trivial
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Vxlan {
    vni: Vni,
}

impl Vxlan {
    /// UDP port on which we expect to receive VXLAN frames.  The standard requires 4789.
    #[allow(unsafe_code)] // const-eval and trivially safe
    pub const PORT: UdpPort = unsafe { UdpPort::new_unchecked(4789) };

    /// The minimum (and maximum) length of a [`Vxlan`] header.
    ///
    /// Naming for consistency with other headers.
    #[allow(clippy::unwrap_used)] // trivially safe const expression
    pub const MIN_LENGTH: NonZero<usize> = NonZero::new(8).unwrap();

    /// The only legal set of flags for a VXLAN header.
    ///
    /// From the [IETF vxlan spec (aka RFC7348)](https://datatracker.ietf.org/doc/html/rfc7348#section-5)
    ///
    /// > Flags (8-bits): where the I flag MUST be set to 1 for a valid VXLAN Network ID (VNI).
    /// > The other 7-bits (designated "R") are reserved fields and MUST be set to zero on
    /// > transmission and ignored on receipt.
    pub const LEGAL_FLAGS: u8 = 0b0000_1000;

    /// Create a new VXLAN header.
    #[must_use]
    pub fn new(vni: Vni) -> Vxlan {
        Vxlan { vni }
    }

    /// Get the [`Vni`] of this header.
    #[must_use]
    pub const fn vni(&self) -> Vni {
        self.vni
    }

    /// Set the [`Vni`] of this header.
    pub const fn set_vni(&mut self, vni: Vni) -> &mut Vxlan {
        self.vni = vni;
        self
    }
}

/// Errors which may occur when creating or parsing a [`Vxlan`] header.
#[derive(Debug, thiserror::Error)]
pub enum VxlanError {
    /// [`Vni`] is a non-zero, 24-bit number.
    /// Attempts to use values outside that range should trigger this error.
    #[error(transparent)]
    InvalidVni(InvalidVni),
    /// [The VXLAN spec] requires several bytes in the header to be zero for validity.
    /// The parser will return this error if received frames have any of these bits set.
    ///
    /// [The VXLAN spec]: https://datatracker.ietf.org/doc/html/rfc7348#section-5
    #[error("Reserved bits set")]
    ReservedBitsSet,
    /// [The VXLAN spec] requires a specific flag to be set in the first byte of the header.
    /// This error will result if that bit is not set.
    ///
    /// [The VXLAN spec]: https://datatracker.ietf.org/doc/html/rfc7348#section-5
    #[error("Reserved bits set")]
    RequiredBitUnset,
}

impl Parse for Vxlan {
    type Error = VxlanError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        if buf.len() < Vxlan::MIN_LENGTH.get() {
            return Err(ParseError::Length(LengthError {
                expected: Vxlan::MIN_LENGTH,
                actual: buf.len(),
            }));
        }
        let slice = &buf[..Vxlan::MIN_LENGTH.get()];
        if slice[0] & Vxlan::LEGAL_FLAGS != Vxlan::LEGAL_FLAGS {
            return Err(ParseError::Invalid(VxlanError::RequiredBitUnset));
        }
        if slice[0] != Vxlan::LEGAL_FLAGS {
            trace!("Received VXLAN header with illegal flags: {flags:#8b}.  Flags will be ignored per the spec, however this is likely an error on the source side.", flags = slice[0]);
        }
        if slice[1..=3] != [0, 0, 0] {
            trace!("Received VXLAN header with reserved bits set.");
            return Err(ParseError::Invalid(VxlanError::ReservedBitsSet));
        }
        // length checked in conversion to `VxlanHeaderSlice`
        // check should be optimized out
        let bytes: [u8; 4] = slice[3..=6].try_into().unwrap_or_else(|_| unreachable!());
        if bytes == [0, 0, 0, 0] {
            return Err(ParseError::Invalid(VxlanError::InvalidVni(
                InvalidVni::ReservedZero,
            )));
        }
        let raw_vni = u32::from_be_bytes(bytes);
        let vni = Vni::new_checked(raw_vni)
            .map_err(|e| ParseError::Invalid(VxlanError::InvalidVni(e)))?;
        if slice[7] != 0 {
            return Err(ParseError::Invalid(VxlanError::ReservedBitsSet));
        }
        Ok((Vxlan { vni }, Vxlan::MIN_LENGTH))
    }
}

impl DeParse for Vxlan {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        Vxlan::MIN_LENGTH
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        if buf.len() < Vxlan::MIN_LENGTH.get() {
            return Err(DeParseError::Length(LengthError {
                expected: Vxlan::MIN_LENGTH,
                actual: buf.len(),
            }));
        }
        let vni_bytes = self.vni.as_u32().to_be_bytes();
        buf[0] = Vxlan::LEGAL_FLAGS;
        buf[1..=3].copy_from_slice(&[0, 0, 0]); // spec requires these bits to be zero
        buf[3..=6].copy_from_slice(&vni_bytes);
        buf[7] = 0;
        Ok(Vxlan::MIN_LENGTH)
    }
}

impl ParsePayload for Vxlan {
    type Next = ();

    /// We don't currently support parsing below the Vxlan layer
    /// (you would instead call [`Packet::parse`] on the rest of the buffer)
    fn parse_payload(&self, _cursor: &mut Reader) -> Option<Self::Next> {
        None
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)] // valid in test code
#[cfg(test)]
mod test {
    use crate::parse::{DeParse, DeParseError, Parse, ParseError};
    use crate::vxlan::{InvalidVni, Vni, Vxlan, VxlanError};

    #[test]
    fn parse_back() {
        bolero::check!().with_type().for_each(|vxlan: &Vxlan| {
            assert_eq!(vxlan.size(), Vxlan::MIN_LENGTH);
            let mut buf = [0u8; Vxlan::MIN_LENGTH.get()];
            let bytes_written = vxlan.deparse(&mut buf).unwrap_or_else(|_| unreachable!());
            assert_eq!(bytes_written, Vxlan::MIN_LENGTH);
            let (parsed, bytes_parsed) = Vxlan::parse(&buf).unwrap();
            assert_eq!(parsed, *vxlan);
            assert_eq!(bytes_parsed, Vxlan::MIN_LENGTH);
            assert_eq!(parsed.vni(), vxlan.vni());
        });
    }

    #[test]
    fn creation_identity_check() {
        bolero::check!().with_type().for_each(|vxlan: &Vxlan| {
            assert_eq!(vxlan, &Vxlan::new(vxlan.vni()));
            assert_eq!(vxlan.size(), Vxlan::MIN_LENGTH);
        });
    }

    #[test]
    fn parse_noise() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; Vxlan::MIN_LENGTH.get()]| {
                let (parsed, bytes_parsed) = match Vxlan::parse(slice) {
                    Ok((parsed, bytes_parsed)) => (parsed, bytes_parsed),
                    Err(ParseError::Length(_)) => {
                        unreachable!()
                    }
                    Err(ParseError::Invalid(VxlanError::InvalidVni(InvalidVni::ReservedZero))) => {
                        assert_eq!(&slice[3..=6], &[0, 0, 0, 0]);
                        return;
                    }
                    Err(ParseError::Invalid(VxlanError::ReservedBitsSet)) => {
                        assert_ne!(&slice[1..=3], &[0, 0, 0, 0]);
                        return;
                    }
                    Err(ParseError::Invalid(VxlanError::RequiredBitUnset)) => {
                        assert_ne!(slice[0] & Vxlan::LEGAL_FLAGS, Vxlan::LEGAL_FLAGS);
                        return;
                    }
                    Err(ParseError::Invalid(VxlanError::InvalidVni(InvalidVni::TooLarge(val)))) => {
                        // The parser should never interpret more than 24-bits here.
                        unreachable!(
                            "parser logic error: too large vni should be impossible: found {val}"
                        );
                    }
                };
                assert_eq!(bytes_parsed, Vxlan::MIN_LENGTH);
                let mut write_back_buffer = [0u8; Vxlan::MIN_LENGTH.get()];
                let bytes_written = parsed
                    .deparse(&mut write_back_buffer)
                    .unwrap_or_else(|_| unreachable!());
                assert_eq!(bytes_written, Vxlan::MIN_LENGTH);
                assert_eq!(write_back_buffer[0], Vxlan::LEGAL_FLAGS);
                assert_eq!(slice[0] & Vxlan::LEGAL_FLAGS, Vxlan::LEGAL_FLAGS);
                assert_eq!(&write_back_buffer[1..=3], &[0, 0, 0]); // reserved should always be zero
                assert_eq!(
                    &write_back_buffer[4..bytes_written.get()],
                    &slice[4..bytes_written.get()]
                );
            });
    }

    #[test]
    fn write_to_insufficient_buffer_fails_gracefully() {
        bolero::check!().with_type().for_each(|vni: &Vxlan| {
            let mut too_small_buffer = [0u8; Vxlan::MIN_LENGTH.get() - 1];
            match vni.deparse(&mut too_small_buffer) {
                Err(DeParseError::Length(e)) => {
                    assert_eq!(e.expected, Vxlan::MIN_LENGTH);
                    assert_eq!(e.actual, too_small_buffer.len());
                }
                _ => unreachable!(),
            }
        });
    }

    #[test]
    fn parse_of_insufficient_buffer_fails_gracefully() {
        bolero::check!()
            .with_type()
            .for_each(
                |slice: &[u8; Vxlan::MIN_LENGTH.get() - 1]| match Vxlan::parse(slice) {
                    Err(ParseError::Length(e)) => {
                        assert_eq!(e.expected, Vxlan::MIN_LENGTH);
                        assert_eq!(e.actual, slice.len());
                    }
                    _ => unreachable!(),
                },
            );
    }

    #[test]
    fn mutation_of_header_preserves_contract() {
        bolero::check!()
            .with_type()
            .for_each(|(vxlan, new_vni): &(Vxlan, Vni)| {
                if vxlan.vni() == *new_vni {
                    return;
                }
                let mut new_vxlan = *vxlan;
                new_vxlan.set_vni(*new_vni);
                assert_ne!(*vxlan, new_vxlan);
                assert_eq!(new_vxlan.vni(), *new_vni);
            });
    }
}
