use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError};
use crate::vxlan::{InvalidVni, Vni};
use core::num::NonZero;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vxlan {
    pub vni: Vni,
}

impl Vxlan {
    pub const PORT: u16 = 4789;
    
    #[allow(unsafe_code)] // const fn trivially safe
    pub const LEN: NonZero<usize> = unsafe { NonZero::new_unchecked(8) };

    /// The only legal set of flags for a VXLAN header.
    pub const LEGAL_FLAGS: u8 = 0b0000100;

    pub fn new(vni: Vni) -> Vxlan {
        Vxlan { vni }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VxlanError {
    #[error("Invalid flags")]
    InvalidFlags,
    #[error(transparent)]
    InvalidVni(InvalidVni),
    #[error("Reserved bits set")]
    ReservedBitsSet,
}

impl Parse for Vxlan {
    type Error = VxlanError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        //check length
        if buf.len() < Vxlan::LEN.get() {
            return Err(ParseError::LengthError(LengthError {
                expected: Vxlan::LEN,
                actual: buf.len(),
            }));
        }
        let slice = &buf[..Vxlan::LEN.get()];
        if slice[0] != 0b00001000 {
            return Err(ParseError::FailedToParse(VxlanError::InvalidFlags));
        }
        if slice[1..=3] != [0, 0, 0] {
            return Err(ParseError::FailedToParse(VxlanError::ReservedBitsSet));
        }
        // length checked in conversion to `VxlanHeaderSlice`
        // check should be optimized out
        let bytes: [u8; 4] = slice[3..=6].try_into().unwrap_or_else(|_| unreachable!());
        if bytes == [0, 0, 0, 0] {
            return Err(ParseError::FailedToParse(VxlanError::ReservedBitsSet));
        }
        let raw_vni = u32::from_be_bytes(bytes);
        let vni =
            Vni::new(raw_vni).map_err(|e| ParseError::FailedToParse(VxlanError::InvalidVni(e)))?;
        if slice[7] != 0 {
            return Err(ParseError::FailedToParse(VxlanError::ReservedBitsSet));
        }
        Ok((Vxlan { vni }, Vxlan::LEN))
    }
}

impl DeParse for Vxlan {
    type Error = VxlanError;

    fn size(&self) -> NonZero<usize> {
        Vxlan::LEN
    }

    fn write(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        if buf.len() < Vxlan::LEN.get() {
            return Err(DeParseError::LengthError(LengthError {
                expected: Vxlan::LEN,
                actual: buf.len(),
            }));
        }
        let vni_bytes = self.vni.as_u32().to_be_bytes();
        buf[0] = 0b00001000;
        buf[1..=3].copy_from_slice(&[0, 0, 0]);
        buf[3..=6].copy_from_slice(&vni_bytes);
        buf[7] = 0;
        Ok(Vxlan::LEN)
    }
}
