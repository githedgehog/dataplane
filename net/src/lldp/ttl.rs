// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The time to live TLV and the end of LLDPDU TLV.
//!
//! These are the two fixed length TLVs: a time to live is always a two octet
//! count of seconds, and an end of LLDPDU marker always carries no value at
//! all.

use core::num::NonZero;

use crate::lldp::tlv::{TlvHeader, TlvType, UnexpectedTlvType, split_tlv, write_tlv};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};

/// How long the information in an LLDPDU remains valid, in seconds.
///
/// A time to live of zero is not a degenerate case: it is the signal a station
/// sends when it is about to stop advertising on a port, and it instructs the
/// receiver to discard what it previously learned.  See
/// [`TimeToLive::SHUTDOWN`].
#[repr(transparent)]
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(from = "u16", into = "u16")]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct TimeToLive(u16);

impl TimeToLive {
    /// The TLV type of a time to live.
    pub const TLV_TYPE: TlvType = TlvType::TIME_TO_LIVE;

    /// The length of a time to live TLV value.
    pub const VALUE_LENGTH: u16 = 2;

    /// The time to live which asks a receiver to discard what it has learned
    /// from this chassis and port.
    pub const SHUTDOWN: TimeToLive = TimeToLive(0);

    /// Build a time to live from a count of seconds.
    #[must_use]
    pub const fn new(seconds: u16) -> TimeToLive {
        TimeToLive(seconds)
    }

    /// The number of seconds this time to live represents.
    #[must_use]
    pub const fn as_secs(self) -> u16 {
        self.0
    }

    /// True if this time to live asks the receiver to discard what it learned.
    #[must_use]
    pub const fn is_shutdown(self) -> bool {
        self.0 == 0
    }
}

impl From<u16> for TimeToLive {
    fn from(value: u16) -> TimeToLive {
        TimeToLive(value)
    }
}

impl From<TimeToLive> for u16 {
    fn from(value: TimeToLive) -> u16 {
        value.as_secs()
    }
}

/// Errors which can occur while parsing a [`TimeToLive`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum TimeToLiveError {
    /// The TLV at this position was not a time to live TLV.
    #[error(transparent)]
    UnexpectedTlvType(#[from] UnexpectedTlvType),
    /// A time to live TLV carried something other than two octets.
    #[error(
        "a time to live TLV must carry exactly {expected} octets, found {0}",
        expected = TimeToLive::VALUE_LENGTH
    )]
    InvalidValueLength(u16),
}

impl Parse for TimeToLive {
    type Error = TimeToLiveError;

    fn parse(buf: &[u8]) -> Result<(TimeToLive, NonZero<u16>), ParseError<TimeToLiveError>> {
        let (value, total) = split_tlv::<TimeToLiveError>(buf, TimeToLive::TLV_TYPE)?;
        let raw: [u8; 2] = value.try_into().map_err(|_| {
            // A TLV length field is nine bits, so this always fits in a `u16`.
            #[allow(clippy::cast_possible_truncation)] // bounded by 511
            ParseError::Invalid(TimeToLiveError::InvalidValueLength(value.len() as u16))
        })?;
        Ok((TimeToLive(u16::from_be_bytes(raw)), total))
    }
}

impl DeParse for TimeToLive {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        TlvHeader::LENGTH.saturating_add(TimeToLive::VALUE_LENGTH)
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        write_tlv(
            buf,
            TimeToLive::TLV_TYPE,
            TimeToLive::VALUE_LENGTH,
            |slot| slot.copy_from_slice(&self.0.to_be_bytes()),
        )
    }
}

/// The marker which ends an LLDPDU.
///
/// [`Lldpdu`](crate::lldp::Lldpdu) writes this itself and consumes it on parse,
/// so it is not something a caller normally handles.  It is public because it
/// is occasionally useful to recognize the two zero octets in isolation.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct EndOfLldpdu;

impl EndOfLldpdu {
    /// The TLV type of an end of LLDPDU marker.
    pub const TLV_TYPE: TlvType = TlvType::END_OF_LLDPDU;
}

/// Errors which can occur while parsing an [`EndOfLldpdu`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum EndOfLldpduError {
    /// The TLV at this position was not an end of LLDPDU TLV.
    #[error(transparent)]
    UnexpectedTlvType(#[from] UnexpectedTlvType),
    /// An end of LLDPDU TLV carried a value, which the standard forbids.
    #[error("an end of LLDPDU TLV must carry no value, found {0} octets")]
    UnexpectedValue(u16),
}

impl Parse for EndOfLldpdu {
    type Error = EndOfLldpduError;

    fn parse(buf: &[u8]) -> Result<(EndOfLldpdu, NonZero<u16>), ParseError<EndOfLldpduError>> {
        let (value, total) = split_tlv::<EndOfLldpduError>(buf, EndOfLldpdu::TLV_TYPE)?;
        if !value.is_empty() {
            // A TLV length field is nine bits, so this always fits in a `u16`.
            #[allow(clippy::cast_possible_truncation)] // bounded by 511
            return Err(ParseError::Invalid(EndOfLldpduError::UnexpectedValue(
                value.len() as u16,
            )));
        }
        Ok((EndOfLldpdu, total))
    }
}

impl DeParse for EndOfLldpdu {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        TlvHeader::LENGTH
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        write_tlv(buf, EndOfLldpdu::TLV_TYPE, 0, |_| ())
    }
}

#[cfg(test)]
mod test {
    use super::{EndOfLldpdu, EndOfLldpduError, TimeToLive, TimeToLiveError};
    use crate::lldp::tlv::{RawTlv, TlvHeader, TlvType, TlvValue};
    use crate::parse::{DeParse, Parse, ParseError};

    #[test]
    fn time_to_live_round_trips() {
        bolero::check!().with_type().for_each(|ttl: &TimeToLive| {
            let mut buf = [0u8; 4];
            let written = ttl.deparse(&mut buf).unwrap();
            assert_eq!(written, ttl.size());
            let (parsed, consumed) = TimeToLive::parse(&buf).unwrap();
            assert_eq!(&parsed, ttl);
            assert_eq!(consumed, written);
        });
    }

    #[test]
    fn time_to_live_is_big_endian() {
        let mut buf = [0u8; 4];
        TimeToLive::new(120).deparse(&mut buf).unwrap();
        assert_eq!(buf, [0x06, 0x02, 0x00, 0x78]);
    }

    #[test]
    fn shutdown_is_zero() {
        assert!(TimeToLive::SHUTDOWN.is_shutdown());
        assert_eq!(TimeToLive::SHUTDOWN.as_secs(), 0);
        assert!(!TimeToLive::new(1).is_shutdown());
    }

    #[test]
    fn a_time_to_live_of_the_wrong_length_is_rejected() {
        for length in [0usize, 1, 3, 4] {
            let value = vec![0u8; length];
            let tlv = RawTlv::new(TlvType::TIME_TO_LIVE, TlvValue::new(&value).unwrap());
            let mut buf = vec![0u8; tlv.size().get() as usize];
            tlv.deparse(&mut buf).unwrap();
            match TimeToLive::parse(&buf) {
                Err(ParseError::Invalid(TimeToLiveError::InvalidValueLength(found))) => {
                    assert_eq!(usize::from(found), length);
                }
                other => unreachable!("expected a length error for {length}, got {other:?}"),
            }
        }
    }

    #[test]
    fn end_of_lldpdu_is_two_zero_octets() {
        let mut buf = [0xffu8; 2];
        let written = EndOfLldpdu.deparse(&mut buf).unwrap();
        assert_eq!(written, TlvHeader::LENGTH);
        assert_eq!(buf, [0x00, 0x00]);
        let (parsed, consumed) = EndOfLldpdu::parse(&buf).unwrap();
        assert_eq!(parsed, EndOfLldpdu);
        assert_eq!(consumed, TlvHeader::LENGTH);
    }

    #[test]
    fn an_end_of_lldpdu_with_a_value_is_rejected() {
        let tlv = RawTlv::new(TlvType::END_OF_LLDPDU, TlvValue::new(&[0x01]).unwrap());
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        match EndOfLldpdu::parse(&buf) {
            Err(ParseError::Invalid(EndOfLldpduError::UnexpectedValue(found))) => {
                assert_eq!(found, 1);
            }
            other => unreachable!("expected an unexpected value error, got {other:?}"),
        }
    }

    #[test]
    fn the_wrong_tlv_type_is_rejected() {
        let mut buf = [0u8; 4];
        TimeToLive::new(30).deparse(&mut buf).unwrap();
        match EndOfLldpdu::parse(&buf) {
            Err(ParseError::Invalid(EndOfLldpduError::UnexpectedTlvType(e))) => {
                assert_eq!(e.expected, TlvType::END_OF_LLDPDU);
                assert_eq!(e.found, TlvType::TIME_TO_LIVE);
            }
            other => unreachable!("expected a TLV type error, got {other:?}"),
        }
    }
}
