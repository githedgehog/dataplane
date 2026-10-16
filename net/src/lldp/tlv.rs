// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! [LLDP] TLV framing.
//!
//! Every TLV in an LLDPDU shares the same two octet header:
//!
//! ```text
//!  0                   1
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    TLV type     |  TLV length |
//! |    (7 bits)     |   (9 bits)  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The type occupies the high seven bits of the first octet and the length
//! occupies the remaining nine bits, so a TLV value is at most 511 octets.
//!
//! [LLDP]: crate::lldp

use core::fmt::{Debug, Display, Formatter};
use core::num::NonZero;

use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError};

/// The type field of an LLDP TLV.
///
/// This is a seven bit field, so not every `u8` is a legal `TlvType`.  It is
/// deliberately impossible to build one from a `u8` without a range check; use
/// [`TlvType::new_checked`].
#[repr(transparent)]
#[derive(
    Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "u8", into = "u8")]
pub struct TlvType(u8);

impl TlvType {
    /// The largest legal TLV type (2<sup>7</sup> - 1).
    pub const MAX: u8 = 127;

    /// Marks the end of an LLDPDU.  Always carries a zero length value.
    pub const END_OF_LLDPDU: TlvType = TlvType(0);
    /// Identifies the chassis which sent the LLDPDU.  Mandatory.
    pub const CHASSIS_ID: TlvType = TlvType(1);
    /// Identifies the port which sent the LLDPDU.  Mandatory.
    pub const PORT_ID: TlvType = TlvType(2);
    /// How long the information in the LLDPDU remains valid.  Mandatory.
    pub const TIME_TO_LIVE: TlvType = TlvType(3);
    /// A human readable description of the sending port.
    pub const PORT_DESCRIPTION: TlvType = TlvType(4);
    /// The administratively assigned name of the sending system.
    pub const SYSTEM_NAME: TlvType = TlvType(5);
    /// A human readable description of the sending system.
    pub const SYSTEM_DESCRIPTION: TlvType = TlvType(6);
    /// The capabilities the sending system supports and has enabled.
    pub const SYSTEM_CAPABILITIES: TlvType = TlvType(7);
    /// An address at which the sending system may be managed.
    pub const MANAGEMENT_ADDRESS: TlvType = TlvType(8);
    /// A vendor defined TLV, discriminated by a three octet OUI.
    pub const ORGANIZATIONALLY_SPECIFIC: TlvType = TlvType(127);

    /// Map a raw `u8` into a [`TlvType`].
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTlvType`] if `raw` does not fit in seven bits.
    pub const fn new_checked(raw: u8) -> Result<TlvType, InvalidTlvType> {
        if raw > TlvType::MAX {
            return Err(InvalidTlvType(raw));
        }
        Ok(TlvType(raw))
    }

    /// The raw value of this TLV type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// True if this TLV is one of the three mandatory TLVs, which an
    /// `Lldpdu` carries in dedicated fields, or the end
    /// of LLDPDU marker, which it supplies itself.
    ///
    /// Such a TLV may not be added to the optional section of an LLDPDU.
    #[must_use]
    pub const fn is_structural(self) -> bool {
        matches!(
            self,
            TlvType::END_OF_LLDPDU | TlvType::CHASSIS_ID | TlvType::PORT_ID | TlvType::TIME_TO_LIVE
        )
    }

    /// True if [`OptionalTlv`](crate::lldp::OptionalTlv) decodes this TLV into
    /// a structured form rather than keeping its octets verbatim.
    ///
    /// Such a TLV may not be wrapped in
    /// [`UnrecognizedTlv`](crate::lldp::UnrecognizedTlv), which would give the
    /// same octets on the wire two different representations in memory.
    #[must_use]
    pub const fn is_modelled(self) -> bool {
        matches!(
            self,
            TlvType::PORT_DESCRIPTION
                | TlvType::SYSTEM_NAME
                | TlvType::SYSTEM_DESCRIPTION
                | TlvType::SYSTEM_CAPABILITIES
                | TlvType::MANAGEMENT_ADDRESS
                | TlvType::ORGANIZATIONALLY_SPECIFIC
        )
    }
}

impl Display for TlvType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let name = match *self {
            TlvType::END_OF_LLDPDU => "end-of-lldpdu",
            TlvType::CHASSIS_ID => "chassis-id",
            TlvType::PORT_ID => "port-id",
            TlvType::TIME_TO_LIVE => "time-to-live",
            TlvType::PORT_DESCRIPTION => "port-description",
            TlvType::SYSTEM_NAME => "system-name",
            TlvType::SYSTEM_DESCRIPTION => "system-description",
            TlvType::SYSTEM_CAPABILITIES => "system-capabilities",
            TlvType::MANAGEMENT_ADDRESS => "management-address",
            TlvType::ORGANIZATIONALLY_SPECIFIC => "organizationally-specific",
            _ => "unrecognized",
        };
        write!(f, "{name} ({raw})", raw = self.0)
    }
}

impl TryFrom<u8> for TlvType {
    type Error = InvalidTlvType;

    fn try_from(value: u8) -> Result<TlvType, InvalidTlvType> {
        TlvType::new_checked(value)
    }
}

impl From<TlvType> for u8 {
    fn from(value: TlvType) -> u8 {
        value.as_u8()
    }
}

/// The error returned when a `u8` is too large to be a [`TlvType`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{0} is too large to be an LLDP TLV type (max {max})", max = TlvType::MAX)]
pub struct InvalidTlvType(pub u8);

/// The two octet header which prefixes every LLDP TLV.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(remote = "Self")]
pub struct TlvHeader {
    typ: TlvType,
    length: u16,
}

impl TlvHeader {
    /// The length of the header itself.
    #[allow(clippy::unwrap_used)] // trivially safe const expression
    pub const LENGTH: NonZero<u16> = NonZero::new(2).unwrap();

    /// The largest value length a TLV header can describe (2<sup>9</sup> - 1).
    pub const MAX_VALUE_LENGTH: u16 = 511;

    /// Build a TLV header.
    ///
    /// # Errors
    ///
    /// Returns [`TlvValueTooLong`] if `length` exceeds
    /// [`TlvHeader::MAX_VALUE_LENGTH`], as such a length cannot be represented
    /// in the nine bits available on the wire.
    pub const fn new(typ: TlvType, length: u16) -> Result<TlvHeader, TlvValueTooLong> {
        if length > TlvHeader::MAX_VALUE_LENGTH {
            return Err(TlvValueTooLong(length as usize));
        }
        Ok(TlvHeader { typ, length })
    }

    /// The type of the TLV this header describes.
    #[must_use]
    pub const fn typ(self) -> TlvType {
        self.typ
    }

    /// The length of the value which follows this header.
    #[must_use]
    pub const fn length(self) -> u16 {
        self.length
    }

    /// The length of the header plus the value it describes.
    ///
    /// `length` is bounded by [`TlvHeader::MAX_VALUE_LENGTH`], so the
    /// saturation this is written in terms of is unreachable.
    #[must_use]
    pub const fn total_length(self) -> NonZero<u16> {
        TlvHeader::LENGTH.saturating_add(self.length)
    }
}

/// Deserialization goes through the derived shape and then [`TlvHeader::new`],
/// so a length which cannot be expressed in nine bits is rejected.
impl<'de> serde::Deserialize<'de> for TlvHeader {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<TlvHeader, D::Error> {
        let unchecked = TlvHeader::deserialize(deserializer)?;
        TlvHeader::new(unchecked.typ, unchecked.length).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for TlvHeader {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        TlvHeader::serialize(self, serializer)
    }
}

impl Parse for TlvHeader {
    /// A TLV header cannot be invalid: the type is masked down to seven bits
    /// and the length to nine, so every two octet sequence is a legal header.
    type Error = core::convert::Infallible;

    fn parse(buf: &[u8]) -> Result<(TlvHeader, NonZero<u16>), ParseError<Self::Error>> {
        let [high, low] = match buf {
            [high, low, ..] => [*high, *low],
            _ => {
                return Err(ParseError::Length(LengthError {
                    expected: TlvHeader::LENGTH.into_non_zero_usize(),
                    actual: buf.len(),
                }));
            }
        };
        let typ = TlvType(high >> 1);
        let length = (u16::from(high & 1) << 8) | u16::from(low);
        Ok((TlvHeader { typ, length }, TlvHeader::LENGTH))
    }
}

impl DeParse for TlvHeader {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        TlvHeader::LENGTH
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let Some(slot) = buf.get_mut(..TlvHeader::LENGTH.into_non_zero_usize().get()) else {
            return Err(DeParseError::Length(LengthError {
                expected: TlvHeader::LENGTH.into_non_zero_usize(),
                actual: buf.len(),
            }));
        };
        // `length` is bounded by `MAX_VALUE_LENGTH`, so bit 8 is the only bit
        // of it which lands in the first octet.
        #[allow(clippy::cast_possible_truncation)] // masked to a single bit
        let high = (self.typ.0 << 1) | ((self.length >> 8) as u8 & 1);
        #[allow(clippy::cast_possible_truncation)] // deliberately keeping the low octet
        let low = self.length as u8;
        slot.copy_from_slice(&[high, low]);
        Ok(TlvHeader::LENGTH)
    }
}

/// The error returned when a TLV value is too long to be described by a nine
/// bit length field.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error(
    "TLV value of {0} octets is too long (max {max})",
    max = TlvHeader::MAX_VALUE_LENGTH
)]
pub struct TlvValueTooLong(pub usize);

/// The error returned when a TLV is not of the type the parser required.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("expected a {expected} TLV, found a {found} TLV")]
pub struct UnexpectedTlvType {
    /// The TLV type the parser required at this position.
    pub expected: TlvType,
    /// The TLV type actually found on the wire.
    pub found: TlvType,
}

/// Parse a TLV header, confirm it is of the expected type, and return the value
/// it describes along with the total number of octets the TLV occupies.
///
/// This is the shared front half of every concrete TLV parser in this module.
pub(crate) fn split_tlv<E>(
    buf: &[u8],
    expected: TlvType,
) -> Result<(&[u8], NonZero<u16>), ParseError<E>>
where
    E: core::error::Error + From<UnexpectedTlvType>,
{
    let (header, _) = TlvHeader::parse(buf).map_err(never)?;
    if header.typ() != expected {
        return Err(ParseError::Invalid(E::from(UnexpectedTlvType {
            expected,
            found: header.typ(),
        })));
    }
    let total = header.total_length();
    let Some(value) =
        buf.get(TlvHeader::LENGTH.into_non_zero_usize().get()..total.into_non_zero_usize().get())
    else {
        return Err(ParseError::Length(LengthError {
            expected: total.into_non_zero_usize(),
            actual: buf.len(),
        }));
    };
    Ok((value, total))
}

/// Re-target a [`ParseError`] from an inner parser onto the parser which
/// contains it, leaving the length and buffer errors alone.
pub(crate) fn lift<E, T, F>(wrap: F) -> impl FnOnce(ParseError<E>) -> ParseError<T>
where
    E: core::error::Error,
    T: core::error::Error,
    F: FnOnce(E) -> T,
{
    move |error| match error {
        ParseError::BufferTooLong(len) => ParseError::BufferTooLong(len),
        ParseError::Length(length) => ParseError::Length(length),
        ParseError::Invalid(inner) => ParseError::Invalid(wrap(inner)),
    }
}

/// Re-target a [`ParseError`] which is statically known not to carry an
/// `Invalid` payload.
pub(crate) fn never<E: core::error::Error>(
    error: ParseError<core::convert::Infallible>,
) -> ParseError<E> {
    match error {
        ParseError::BufferTooLong(len) => ParseError::BufferTooLong(len),
        ParseError::Length(length) => ParseError::Length(length),
        ParseError::Invalid(impossible) => match impossible {},
    }
}

/// Write a TLV header and the value which follows it.
///
/// This is the shared front half of every concrete TLV serializer in this
/// module.  `value_length` must match the number of octets `write_value` goes
/// on to write.
pub(crate) fn write_tlv<E, F>(
    buf: &mut [u8],
    typ: TlvType,
    value_length: u16,
    write_value: F,
) -> Result<NonZero<u16>, DeParseError<E>>
where
    F: FnOnce(&mut [u8]),
{
    // Every caller derives `value_length` from a length bounded field, so the
    // header cannot reject it.
    let header = TlvHeader::new(typ, value_length)
        .unwrap_or_else(|e| unreachable!("TLV value length is bounded by construction: {e:?}"));
    let total = header.total_length();
    if buf.len() < total.into_non_zero_usize().get() {
        return Err(DeParseError::Length(LengthError {
            expected: total.into_non_zero_usize(),
            actual: buf.len(),
        }));
    }
    let (header_slot, rest) = buf.split_at_mut(TlvHeader::LENGTH.into_non_zero_usize().get());
    header
        .deparse(header_slot)
        .unwrap_or_else(|e| unreachable!("header slot is exactly the header length: {e:?}"));
    write_value(&mut rest[..value_length as usize]);
    Ok(total)
}

/// A TLV which this library does not (yet) model in a structured way.
///
/// An LLDPDU carries its optional TLVs as `RawTlv`s so that unrecognized and
/// vendor specific TLVs survive a parse and deparse cycle byte for byte.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RawTlv {
    typ: TlvType,
    value: TlvValue,
}

impl RawTlv {
    /// Build a TLV from its type and value.
    #[must_use]
    pub const fn new(typ: TlvType, value: TlvValue) -> RawTlv {
        RawTlv { typ, value }
    }

    /// The type of this TLV.
    #[must_use]
    pub const fn typ(&self) -> TlvType {
        self.typ
    }

    /// The value of this TLV.
    #[must_use]
    pub const fn value(&self) -> &TlvValue {
        &self.value
    }
}

impl Parse for RawTlv {
    type Error = core::convert::Infallible;

    fn parse(buf: &[u8]) -> Result<(RawTlv, NonZero<u16>), ParseError<Self::Error>> {
        let (header, _) = TlvHeader::parse(buf)?;
        let total = header.total_length();
        let Some(value) = buf
            .get(TlvHeader::LENGTH.into_non_zero_usize().get()..total.into_non_zero_usize().get())
        else {
            return Err(ParseError::Length(LengthError {
                expected: total.into_non_zero_usize(),
                actual: buf.len(),
            }));
        };
        // The header length field is nine bits, so the value can never exceed
        // the bound `TlvValue` enforces.
        let value = TlvValue::new(value)
            .unwrap_or_else(|e| unreachable!("TLV length field is nine bits: {e:?}"));
        Ok((
            RawTlv {
                typ: header.typ(),
                value,
            },
            total,
        ))
    }
}

impl DeParse for RawTlv {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        // `TlvValue` is bounded by `MAX_VALUE_LENGTH`, so this cannot overflow.
        #[allow(clippy::cast_possible_truncation)] // bounded by 511
        let value_length = self.value.len() as u16;
        TlvHeader::LENGTH.saturating_add(value_length)
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        #[allow(clippy::cast_possible_truncation)] // bounded by 511
        let value_length = self.value.len() as u16;
        write_tlv(buf, self.typ, value_length, |slot| {
            slot.copy_from_slice(self.value.as_bytes());
        })
    }
}

/// The value half of a TLV: at most 511 octets, possibly empty.
///
/// Unlike [`Octets`](crate::lldp::Octets), a `TlvValue` may be empty, because
/// the end of LLDPDU TLV and some vendor TLVs legitimately carry no value.
#[derive(Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct TlvValue(Vec<u8>);

impl TlvValue {
    /// The largest number of octets a TLV value can hold.
    pub const MAX_LEN: usize = TlvHeader::MAX_VALUE_LENGTH as usize;

    /// Build a TLV value from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`TlvValueTooLong`] if `bytes` is longer than
    /// [`TlvValue::MAX_LEN`].
    pub fn new(bytes: &[u8]) -> Result<TlvValue, TlvValueTooLong> {
        if bytes.len() > TlvValue::MAX_LEN {
            return Err(TlvValueTooLong(bytes.len()));
        }
        Ok(TlvValue(bytes.to_vec()))
    }

    /// The octets of this value.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The number of octets in this value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if this value carries no octets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Debug for TlvValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        self.0.iter().try_for_each(|octet| write!(f, "{octet:02x}"))
    }
}

impl AsRef<[u8]> for TlvValue {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Deserialization goes through [`TlvValue::new`], so an over long value is
/// rejected rather than trusted.
impl TryFrom<Vec<u8>> for TlvValue {
    type Error = TlvValueTooLong;

    fn try_from(value: Vec<u8>) -> Result<TlvValue, TlvValueTooLong> {
        TlvValue::new(&value)
    }
}

impl From<TlvValue> for Vec<u8> {
    fn from(value: TlvValue) -> Vec<u8> {
        value.0
    }
}

impl TryFrom<&[u8]> for TlvValue {
    type Error = TlvValueTooLong;

    fn try_from(value: &[u8]) -> Result<TlvValue, TlvValueTooLong> {
        TlvValue::new(value)
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{RawTlv, TlvType, TlvValue};
    use bolero::{Driver, TypeGenerator};
    use core::ops::Bound;

    impl TypeGenerator for TlvType {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            Some(TlvType(u.produce::<u8>()? & TlvType::MAX))
        }
    }

    impl TypeGenerator for TlvValue {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let len = u.gen_usize(Bound::Included(&0), Bound::Included(&TlvValue::MAX_LEN))?;
            let mut inner = Vec::with_capacity(len);
            for _ in 0..len {
                inner.push(u.produce::<u8>()?);
            }
            Some(TlvValue(inner))
        }
    }

    impl TypeGenerator for RawTlv {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            Some(RawTlv {
                typ: u.produce()?,
                value: u.produce()?,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        RawTlv, TlvHeader, TlvType, TlvValue, TlvValueTooLong, UnexpectedTlvType, split_tlv,
    };
    use crate::parse::{DeParse, IntoNonZeroUSize, Parse, ParseError};

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        UnexpectedType(#[from] UnexpectedTlvType),
    }

    #[test]
    fn type_beyond_seven_bits_is_rejected() {
        assert_eq!(TlvType::new_checked(128).unwrap_err().0, 128);
        assert_eq!(TlvType::new_checked(127).unwrap().as_u8(), 127);
    }

    #[test]
    fn value_beyond_nine_bits_is_rejected() {
        assert_eq!(
            TlvHeader::new(TlvType::PORT_DESCRIPTION, 512).unwrap_err(),
            TlvValueTooLong(512)
        );
        assert!(TlvHeader::new(TlvType::PORT_DESCRIPTION, 511).is_ok());
    }

    #[test]
    fn header_round_trips() {
        bolero::check!()
            .with_type()
            .for_each(|(typ, raw_length): &(TlvType, u16)| {
                let length = raw_length % (TlvHeader::MAX_VALUE_LENGTH + 1);
                let header = TlvHeader::new(*typ, length).unwrap();
                let mut buf = [0u8; 2];
                assert_eq!(header.deparse(&mut buf).unwrap(), TlvHeader::LENGTH);
                let (parsed, consumed) = TlvHeader::parse(&buf).unwrap();
                assert_eq!(consumed, TlvHeader::LENGTH);
                assert_eq!(parsed, header);
            });
    }

    #[test]
    fn every_two_octets_is_a_legal_header() {
        bolero::check!().with_type().for_each(|raw: &[u8; 2]| {
            let (header, _) = TlvHeader::parse(raw).unwrap();
            assert!(header.typ().as_u8() <= TlvType::MAX);
            assert!(header.length() <= TlvHeader::MAX_VALUE_LENGTH);
            let mut buf = [0u8; 2];
            header.deparse(&mut buf).unwrap();
            assert_eq!(&buf, raw, "header parse is not byte exact");
        });
    }

    #[test]
    fn raw_tlv_round_trips() {
        bolero::check!().with_type().for_each(|tlv: &RawTlv| {
            let mut buf = vec![0u8; tlv.size().get() as usize];
            let written = tlv.deparse(&mut buf).unwrap();
            assert_eq!(written, tlv.size());
            let (parsed, consumed) = RawTlv::parse(&buf).unwrap();
            assert_eq!(consumed, written);
            assert_eq!(&parsed, tlv);
        });
    }

    #[test]
    fn split_tlv_rejects_the_wrong_type() {
        let tlv = RawTlv::new(TlvType::SYSTEM_NAME, TlvValue::new(b"hedgehog").unwrap());
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();

        let (value, total) = split_tlv::<TestError>(&buf, TlvType::SYSTEM_NAME).unwrap();
        assert_eq!(value, b"hedgehog");
        assert_eq!(total, tlv.size());

        match split_tlv::<TestError>(&buf, TlvType::PORT_ID) {
            Err(ParseError::Invalid(TestError::UnexpectedType(e))) => {
                assert_eq!(e.expected, TlvType::PORT_ID);
                assert_eq!(e.found, TlvType::SYSTEM_NAME);
            }
            other => unreachable!("expected a type mismatch, got {other:?}"),
        }
    }

    #[test]
    fn split_tlv_rejects_a_truncated_value() {
        let tlv = RawTlv::new(TlvType::SYSTEM_NAME, TlvValue::new(b"hedgehog").unwrap());
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        buf.pop();

        match split_tlv::<TestError>(&buf, TlvType::SYSTEM_NAME) {
            Err(ParseError::Length(e)) => {
                assert_eq!(e.expected, tlv.size().into_non_zero_usize());
                assert_eq!(e.actual, buf.len());
            }
            other => unreachable!("expected a length error, got {other:?}"),
        }
    }

    #[test]
    fn deparse_into_insufficient_buffer_fails_gracefully() {
        bolero::check!().with_type().for_each(|tlv: &RawTlv| {
            let mut buf = vec![0u8; tlv.size().get() as usize - 1];
            assert!(tlv.deparse(&mut buf).is_err());
        });
    }

    #[test]
    fn structural_types_are_exactly_the_reserved_four() {
        for raw in 0..=TlvType::MAX {
            let typ = TlvType::new_checked(raw).unwrap();
            assert_eq!(typ.is_structural(), raw <= 3, "{typ}");
        }
    }
}
