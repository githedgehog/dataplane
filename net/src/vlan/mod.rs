// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VLAN validation and manipulation.

#[allow(unused_imports)] // conditional re-export
#[cfg(any(test, feature = "arbitrary"))]
pub use contract::*;

use crate::eth::ethtype::EthType;
use crate::eth::{EthNext, parse_from_ethertype};
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParsePayload, Reader,
};
use core::num::NonZero;
use etherparse::{SingleVlanHeader, VlanId, VlanPcp};

/// A VLAN Identifier.
///
/// This type is marked `#[repr(transparent)]` to ensure that it has the same memory layout
/// as a [`NonZero<u16>`].
/// This means that [`Option<Vid>`] should always have the same size and alignment as
/// [`Option<NonZero<u16>>`], and thus the same size and alignment as `u16`.
/// The memory / compute overhead of using this type as opposed to a `u16` is then strictly
/// limited to the price of checking that the represented value is in fact a legal [`Vid`]
/// (which we should generally be doing anyway).
#[repr(transparent)]
#[allow(clippy::unsafe_derive_deserialize)] // use of unsafe in trivially sound const expression
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Vid(NonZero<u16>);

/// Errors which can occur when converting a `u16` to a validated [`Vid`]
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[must_use]
pub enum InvalidVid {
    /// 0 is a reserved [`Vid`] which basically means "the native vlan."
    /// 0 is not a legal [`Vid`] for Hedgehog's purposes.
    #[error("Zero is a reserved Vid")]
    Zero,
    /// 4095 is a reserved [`Vid`] per the spec.
    #[error("4095 is a reserved Vid")]
    Reserved,
    /// The value is too large to be a legal [`Vid`] (12-bit max).
    #[error("{0} is too large to be a legal Vid ({MAX} is max legal value)", MAX = Vid::MAX)]
    TooLarge(u16),
}

impl InvalidVid {
    /// The raw `u16` value of the reserved (4095) [`Vid`]
    pub const RESERVED: u16 = 4095;
    /// The raw `u16` value of the first truly nonsensical [`Vid`] (4096)
    pub const TOO_LARGE: u16 = Self::RESERVED + 1;
}

impl Vid {
    /// The minimum legal [`Vid`] value (1).
    #[allow(clippy::unwrap_used)] // safe due to const eval
    pub const MIN: Vid = Vid(NonZero::new(1).unwrap());

    /// The maximum legal [`Vid`] value (2^12 - 2).
    #[allow(clippy::unwrap_used)] // safe due to const eval
    pub const MAX: Vid = Vid(NonZero::new(4094).unwrap());

    /// Create a new [`Vid`] from a `u16`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is 0, 4095 (reserved), or greater than [`Vid::MAX`].
    pub fn new(vid: u16) -> Result<Self, InvalidVid> {
        match NonZero::new(vid) {
            None => Err(InvalidVid::Zero),
            Some(val) if val.get() == InvalidVid::RESERVED => Err(InvalidVid::Reserved),
            Some(val) if val.get() > InvalidVid::RESERVED => Err(InvalidVid::TooLarge(val.get())),
            Some(val) => Ok(Vid(val)),
        }
    }

    /// Create a new [`Vid`] from a `u16`.
    ///
    /// # Safety
    ///
    /// It is undefined behavior to pass in vid = 0 or vid >= 4094.
    #[allow(unsafe_code)] // safety requirements documented
    #[must_use]
    pub unsafe fn new_unchecked(vid: u16) -> Self {
        Vid(unsafe { NonZero::new_unchecked(vid) })
    }

    /// Get the value of the [`Vid`] as a `u16`.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0.get()
    }
}

impl AsRef<NonZero<u16>> for Vid {
    fn as_ref(&self) -> &NonZero<u16> {
        &self.0
    }
}

impl From<Vid> for u16 {
    fn from(vid: Vid) -> u16 {
        vid.as_u16()
    }
}

impl TryFrom<u16> for Vid {
    type Error = InvalidVid;

    fn try_from(vid: u16) -> Result<Vid, Self::Error> {
        Vid::new(vid)
    }
}

impl core::fmt::Display for Vid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_u16())
    }
}

/// A Priority Code Point.
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pcp(u8);

/// Error type for invalid [`Pcp`] values.
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
#[error("Invalid PCP value: {0} (3-bit max)")]
pub struct InvalidPcp(u8);

impl Pcp {
    const MIN_BINARY: u8 = 0;
    const MAX_BINARY: u8 = 0b111;
    /// The minimum legal [`Pcp`] value
    pub const MIN: Pcp = Pcp(Pcp::MIN_BINARY);
    /// The maximum legal [`Pcp`] value
    pub const MAX: Pcp = Pcp(Pcp::MAX_BINARY);

    /// Map an u8 to a [`Pcp`]
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied value is larger than 3-bits.
    pub const fn new(raw: u8) -> Result<Pcp, InvalidPcp> {
        match raw {
            Pcp::MIN_BINARY..=Pcp::MAX_BINARY => Ok(Pcp(raw)),
            _ => Err(InvalidPcp(raw)),
        }
    }

    /// Map the [`Pcp`] value back to a `u8`.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl Default for Pcp {
    fn default() -> Self {
        Pcp::new(0).unwrap_or_else(|_| unreachable!())
    }
}

impl From<Pcp> for VlanPcp {
    fn from(value: Pcp) -> Self {
        #[allow(unsafe_code)] // SAFETY: overlapping check between libraries.
        unsafe {
            Self::new_unchecked(value.as_u8())
        }
    }
}

impl From<VlanPcp> for Pcp {
    fn from(value: VlanPcp) -> Self {
        Pcp(value.value())
    }
}

impl From<Vid> for VlanId {
    fn from(value: Vid) -> Self {
        #[allow(unsafe_code)] // SAFETY: overlapping check between libraries.
        unsafe {
            Self::new_unchecked(value.0.get())
        }
    }
}

/// A VLAN header.
///
/// This may represent 802.1Q or 802.1AD (the outer ethtype is not stored in this struct)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vlan(SingleVlanHeader);

impl Vlan {
    /// The minimum (and maximum) length of a [`Vlan`] header.
    ///
    /// Name choice for consistency.
    #[allow(clippy::unwrap_used)] // safety: trivial and const-eval
    pub const MIN_LENGTH: NonZero<u16> = NonZero::new(4).unwrap();

    // TODO: non-panic proof
    /// Create a new [Vlan] header.
    #[must_use]
    pub fn new(vid: Vid, inner_ethtype: EthType, pcp: Pcp, dei: bool) -> Vlan {
        Vlan(SingleVlanHeader {
            pcp: pcp.into(),
            drop_eligible_indicator: dei,
            #[allow(unsafe_code)] // SAFETY: overlapping validity check between libraries.
            vlan_id: unsafe { VlanId::new_unchecked(vid.as_u16()) },
            ether_type: inner_ethtype.0,
        })
    }

    /// Get the [`Vid`] of this `Vlan` header.
    #[must_use]
    pub fn vid(&self) -> Vid {
        #[allow(unsafe_code)] // safety: new and parse already check Vid validity
        unsafe {
            Vid::new_unchecked(self.0.vlan_id.value())
        }
    }

    /// Get the headers [`Pcp`]
    #[must_use]
    pub fn pcp(&self) -> Pcp {
        self.0.pcp.into()
    }

    /// Get the headers drop eligibility indicator
    #[must_use]
    pub fn dei(&self) -> bool {
        self.0.drop_eligible_indicator
    }

    /// Get the headers ethtype.
    ///
    /// # Note
    ///
    /// This method returns the headers _inner_ ethertype.
    /// It does _not_ return the ethertype of the ethernet (or other vlan) header which contains
    /// this header.
    #[must_use]
    pub fn inner_ethtype(&self) -> EthType {
        EthType(self.0.ether_type)
    }

    /// Set the [`Vid`] of this header.
    pub fn set_vid(&mut self, vid: Vid) -> &mut Self {
        self.0.vlan_id = vid.into();
        self
    }

    /// Set the [`Pcp`] of this header.
    pub fn set_pcp(&mut self, pcp: Pcp) -> &mut Self {
        self.0.pcp = pcp.into();
        self
    }

    /// Set the drop eligibility indicator of this header.
    pub fn set_dei(&mut self, dei: bool) -> &mut Self {
        self.0.drop_eligible_indicator = dei;
        self
    }

    /// Set the headers [`EthType`].
    ///
    /// # Note
    ///
    /// This method sets the headers _inner_ ethertype.
    /// It does _not_ set the ethertype of the ethernet (or other vlan) header which contains
    /// this header.
    pub fn set_inner_ethtype(&mut self, eth_type: EthType) -> &mut Self {
        self.0.ether_type = eth_type.0;
        self
    }
}

impl Parse for Vlan {
    type Error = InvalidVid;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = SingleVlanHeader::from_slice(buf).map_err(|e| {
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
        // validate vlan
        Vid::new(inner.vlan_id.value()).map_err(ParseError::Invalid)?;
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok((Self(inner), consumed))
    }
}

impl DeParse for Vlan {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // bounded header length
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

impl ParsePayload for Vlan {
    type Next = EthNext;

    fn parse_payload(&self, cursor: &mut Reader) -> Option<EthNext> {
        parse_from_ethertype(self.0.ether_type, cursor)
    }
}

/// Contracts for Vlan types
#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::eth::ethtype::{CommonEthType, EthType};
    use crate::vlan::{InvalidPcp, InvalidVid, Pcp, Vid, Vlan};
    use bolero::{Driver, TypeGenerator, ValueGenerator};

    impl TypeGenerator for Vid {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let raw = u.produce::<u16>()? & Vid::MAX.0.get();
            match Vid::new(raw) {
                Ok(vid) => Some(vid),
                Err(InvalidVid::Zero) => Some(Vid::MIN),
                Err(InvalidVid::Reserved) => Some(Vid::MAX),
                Err(InvalidVid::TooLarge(_)) => unreachable!(),
            }
        }
    }

    impl TypeGenerator for Pcp {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            match Pcp::new(driver.produce::<u8>()? & Pcp::MAX.0) {
                Ok(pcp) => Some(pcp),
                Err(InvalidPcp(_)) => unreachable!(),
            }
        }
    }

    /// Generate an arbitrary [`Vlan`] header with the specified [`EthType`] (inner)
    pub struct GenWithEthType(pub EthType);

    impl ValueGenerator for GenWithEthType {
        type Output = Vlan;

        fn generate<D: Driver>(&self, u: &mut D) -> Option<Self::Output> {
            let ethertype = self.0;
            let vid = u.produce()?;
            let pcp = u.produce()?;
            let dei = u.produce()?;
            Some(Vlan::new(vid, ethertype, pcp, dei))
        }
    }

    impl TypeGenerator for Vlan {
        /// Generate a completely arbitrary [`Vlan`] header
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            GenWithEthType(EthType::generate(u)?).generate(u)
        }
    }

    /// Generate a [`Vlan`] header with a [`CommonEthType`]
    #[non_exhaustive]
    #[repr(transparent)]
    pub struct CommonVlan;

    impl ValueGenerator for CommonVlan {
        type Output = Vlan;
        /// Generate a [`Vlan`] header with a [`CommonEthType`]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vlan> {
            GenWithEthType(driver.produce::<CommonEthType>()?.into()).generate(driver)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::vlan::Vid;

    const MIN_LENGTH_USIZE: usize = 4;

    #[test]
    fn vid_min_is_valid() {
        let vid = Vid::MIN;
        assert_eq!(vid.as_u16(), 1);
        assert_eq!(vid, Vid::new(1).unwrap());
    }

    #[test]
    fn vid_max_is_valid() {
        let vid = Vid::MAX;
        assert_eq!(vid.as_u16(), Vid::MAX.0.get());
        assert_eq!(vid, Vid::new(Vid::MAX.0.get()).unwrap());
    }

    #[test]
    #[allow(unsafe_code)]
    fn unsafe_vid_version_works_with_vid_1() {
        let vid = unsafe { Vid::new_unchecked(1) };
        assert_eq!(vid.as_u16(), 1);
        assert_eq!(vid, Vid::new(1).unwrap());
    }

    #[test]
    fn vid_zero_is_invalid() {
        match Vid::new(0) {
            Err(InvalidVid::Zero) => {}
            e => unreachable!(
                "Vid::new(0) should have failed with InvalidVid::Zero, but instead returned {e:?}",
            ),
        }
    }

    #[test]
    fn vid_too_large_is_invalid() {
        match Vid::new(InvalidVid::TOO_LARGE) {
            Err(InvalidVid::TooLarge(x)) => {
                assert_eq!(x, InvalidVid::TOO_LARGE);
            }
            e => unreachable!(
                "Vid::new(InvalidVid::TOO_LARGE) should have failed with InvalidVid::TooLarge, but instead returned {e:?}",
            ),
        }
    }

    #[test]
    fn vid_reserved_is_invalid() {
        match Vid::new(InvalidVid::RESERVED) {
            Err(InvalidVid::Reserved) => {}
            e => unreachable!(
                "Vid::new(InvalidVid::RESERVED) should have failed with InvalidVid::Reserved, but instead returned {e:?}",
            ),
        }
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn pcp_bounds_respected() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|byte: u8| match Pcp::new(byte) {
                Ok(pcp) => {
                    assert_eq!(pcp.as_u8(), byte);
                    assert!(pcp.as_u8() <= Pcp::MAX_BINARY);
                    assert!(pcp <= Pcp::MAX);
                }
                Err(e) => {
                    assert_eq!(e.0, byte);
                    assert!(e.0 > Pcp::MAX_BINARY);
                }
            });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_back() {
        bolero::check!().with_type().for_each(|vlan: &Vlan| {
            let mut buf = [0u8; MIN_LENGTH_USIZE]; // vlan headers are always 4 bytes long
            let written = vlan.deparse(&mut buf).unwrap();
            assert_eq!(written, vlan.size());
            let (parsed, consumed) =
                Vlan::parse(&buf[..written.into_non_zero_usize().get()]).unwrap();
            assert_eq!(parsed, *vlan);
            assert_eq!(consumed, written);
            assert_eq!(consumed, Vlan::MIN_LENGTH);
            assert_eq!(vlan.vid(), parsed.vid());
            assert_eq!(vlan.pcp(), parsed.pcp());
            assert_eq!(vlan.dei(), parsed.dei());
            assert_eq!(vlan.inner_ethtype(), parsed.inner_ethtype());
        });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_noise() {
        bolero::check!().with_type().for_each(|buf: &[u8; MIN_LENGTH_USIZE]| {
            let (vlan, consumed) = match Vlan::parse(buf) {
                Ok((vlan, consumed)) => (vlan, consumed),
                Err(ParseError::Invalid(InvalidVid::Zero | InvalidVid::Reserved)) => { return; }
                Err(ParseError::Invalid(InvalidVid::TooLarge(e))) => {
                    unreachable!("parser error: we should never get a too large error from a real sequence of bytes: {e:?}")
                }
                Err(ParseError::Length(e)) => {
                    unreachable!("parser error: we should never get a length error from a sequence of four bytes: {e:?}")
                },
                Err(ParseError::BufferTooLong(_)) => unreachable!(),
            };
            assert_eq!(consumed, Vlan::MIN_LENGTH);
            let mut buf2 = [0u8; MIN_LENGTH_USIZE];
            let written = vlan.deparse(&mut buf2).unwrap_or_else(|_| unreachable!());
            assert_eq!(written, consumed);
            assert_eq!(buf, &buf2);
        });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_noise_too_short() {
        bolero::check!().with_type().for_each(
            |buf: &[u8; MIN_LENGTH_USIZE - 1]| match Vlan::parse(buf) {
                Err(ParseError::Length(e)) => {
                    assert_eq!(e.actual, buf.len());
                    assert_eq!(e.expected, Vlan::MIN_LENGTH.into_non_zero_usize());
                }
                _ => unreachable!(),
            },
        );
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn arbitrary_mutation() {
        bolero::check!()
            .with_type()
            .for_each(|(from, into): &(Vlan, Vlan)| {
                let mut from = from.clone();
                from.set_vid(into.vid());
                from.set_pcp(into.pcp());
                from.set_dei(into.dei());
                from.set_inner_ethtype(into.inner_ethtype());
                assert_eq!(&from, into);
                let mut from_buffer = [0u8; MIN_LENGTH_USIZE];
                let mut into_buffer = [0u8; MIN_LENGTH_USIZE];
                from.deparse(from_buffer.as_mut()).unwrap();
                into.deparse(into_buffer.as_mut()).unwrap();
                assert_eq!(from_buffer, into_buffer);
            });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn deparse_to_insufficient_buffer_is_graceful() {
        bolero::check!().with_type().for_each(|vlan: &Vlan| {
            let mut buf = [0u8; MIN_LENGTH_USIZE - 1];
            match vlan.deparse(&mut buf) {
                Err(DeParseError::Length(e)) => {
                    assert_eq!(e.actual, buf.len());
                    assert_eq!(e.expected, Vlan::MIN_LENGTH.into_non_zero_usize());
                }
                _ => unreachable!(),
            }
        });
    }
}
