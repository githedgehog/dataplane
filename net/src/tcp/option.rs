// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Individual TCP option types.

use arrayvec::ArrayVec;
use std::num::NonZero;

/// A single TCP header option.
///
/// See [RFC 9293 section 3.1](https://datatracker.ietf.org/doc/html/rfc9293#section-3.1).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    strum_macros::EnumCount,
    strum_macros::Display,
    strum_macros::IntoStaticStr,
    strum_macros::AsRefStr,
    strum_macros::EnumMessage,
)]
#[repr(u8)]
pub enum TcpOption {
    /// No-Operation padding (kind 1, RFC 9293).
    Noop = 1,

    /// Maximum Segment Size (kind 2, RFC 9293).
    Mss(TcpMss) = 2,

    /// Window Scale factor (kind 3, RFC 7323).
    ///
    /// Valid scale factors are 0..=14 per RFC 7323, but this is not currently
    /// enforced at parse time.
    WindowScale(u8) = 3,

    /// SACK Permitted (kind 4, RFC 2018).
    ///
    /// Indicates the sender supports selective acknowledgement.
    /// Only valid in SYN segments.
    SackPermitted = 4,

    /// Selective Acknowledgement blocks (kind 5, RFC 2018).
    Sack(TcpSack) = 5,

    /// Timestamps (kind 8, RFC 7323).
    ///
    /// First value is the sender timestamp (`TSval`), second is the echo reply
    /// timestamp (`TSecr`).
    Timestamp(u32, u32) = 8,
}

impl TcpOption {
    /// Convert from an etherparse option element.
    pub(in crate::tcp) fn from_etherparse(
        element: &etherparse::TcpOptionElement,
    ) -> Result<Self, TcpOptionParseError> {
        use etherparse::TcpOptionElement;
        match *element {
            TcpOptionElement::Noop => Ok(TcpOption::Noop),
            TcpOptionElement::MaximumSegmentSize(v) => {
                let mss = TcpMss::new(v).map_err(|_| TcpOptionParseError::ZeroMss)?;
                Ok(TcpOption::Mss(mss))
            }
            TcpOptionElement::WindowScale(scale) => Ok(TcpOption::WindowScale(scale)),
            TcpOptionElement::SelectiveAcknowledgementPermitted => Ok(TcpOption::SackPermitted),
            TcpOptionElement::SelectiveAcknowledgement(first, ref rest) => {
                let mut buf = [TcpSackBlock::default(); 4];
                buf[0] = TcpSackBlock::new(first.0, first.1);
                let mut count = 1;
                for (left, right) in rest.iter().flatten() {
                    buf[count] = TcpSackBlock::new(*left, *right);
                    count += 1;
                }
                // count is 1..=4 (1 mandatory + up to 3 optional), so this cannot fail.
                let sack = TcpSack::new(&buf[..count]).unwrap_or_else(|_| unreachable!());
                Ok(TcpOption::Sack(sack))
            }
            TcpOptionElement::Timestamp(val, echo) => Ok(TcpOption::Timestamp(val, echo)),
        }
    }

    /// Convert to an etherparse option element.
    pub(in crate::tcp) fn to_etherparse(&self) -> etherparse::TcpOptionElement {
        use etherparse::TcpOptionElement;
        match self {
            TcpOption::Noop => TcpOptionElement::Noop,
            TcpOption::Mss(mss) => TcpOptionElement::MaximumSegmentSize(mss.get()),
            TcpOption::WindowScale(scale) => TcpOptionElement::WindowScale(*scale),
            TcpOption::SackPermitted => TcpOptionElement::SelectiveAcknowledgementPermitted,
            TcpOption::Sack(sack) => {
                let b = sack.blocks();
                let first = (b[0].left_edge(), b[0].right_edge());
                let mut rest = [None; 3];
                for (i, block) in b.iter().skip(1).enumerate() {
                    rest[i] = Some((block.left_edge(), block.right_edge()));
                }
                TcpOptionElement::SelectiveAcknowledgement(first, rest)
            }
            TcpOption::Timestamp(val, echo) => TcpOptionElement::Timestamp(*val, *echo),
        }
    }

    /// Wire size of this option in bytes.
    pub(in crate::tcp) fn wire_size(&self) -> usize {
        match self {
            TcpOption::Noop => 1,
            TcpOption::Mss(_) => 4,
            TcpOption::WindowScale(_) => 3,
            TcpOption::SackPermitted => 2,
            TcpOption::Sack(sack) => 2 + sack.blocks().len() * 8,
            TcpOption::Timestamp(_, _) => 10,
        }
    }
}

// ---------------------------------------------------------------------------
// TcpMss
// ---------------------------------------------------------------------------

/// Maximum Segment Size value (RFC 9293 section 3.7.1).
///
/// An MSS of zero is semantically nonsensical and rejected at parse time.
#[repr(transparent)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct TcpMss(NonZero<u16>);

/// Errors from creating a [`TcpMss`].
#[derive(Debug, thiserror::Error)]
pub enum TcpMssError {
    /// MSS must be non-zero.
    #[error("MSS must be non-zero")]
    Zero,
}

impl TcpMss {
    /// Create a new [`TcpMss`] from a raw u16.
    ///
    /// # Errors
    ///
    /// Returns [`TcpMssError::Zero`] if the value is zero.
    pub const fn new(value: u16) -> Result<Self, TcpMssError> {
        match NonZero::new(value) {
            Some(v) => Ok(TcpMss(v)),
            None => Err(TcpMssError::Zero),
        }
    }

    /// Get the MSS value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl From<TcpMss> for u16 {
    fn from(mss: TcpMss) -> Self {
        mss.get()
    }
}

impl TryFrom<u16> for TcpMss {
    type Error = TcpMssError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

// ---------------------------------------------------------------------------
// TcpSackBlock / TcpSack
// ---------------------------------------------------------------------------

/// A SACK block representing a contiguous range of received sequence numbers.
///
/// See [RFC 2018](https://datatracker.ietf.org/doc/html/rfc2018).
///
/// Note: TCP sequence numbers use modular arithmetic (mod 2^32), so
/// `left_edge > right_edge` is technically legal when the range spans the
/// wrap-around point. We do not reject such blocks, but log them as
/// suspicious since they are extremely rare in practice.
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Default, Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct TcpSackBlock {
    left_edge: u32,
    right_edge: u32,
}

impl TcpSackBlock {
    /// Create a new SACK block.
    #[must_use]
    pub fn new(left_edge: u32, right_edge: u32) -> Self {
        if left_edge > right_edge {
            tracing::debug!(
                left_edge,
                right_edge,
                "SACK block wraps sequence number space (left > right); \
                 legal per modular arithmetic but suspicious"
            );
        }
        Self {
            left_edge,
            right_edge,
        }
    }

    /// The first sequence number of the block.
    #[must_use]
    pub const fn left_edge(self) -> u32 {
        self.left_edge
    }

    /// The sequence number immediately following the last in the block.
    #[must_use]
    pub const fn right_edge(self) -> u32 {
        self.right_edge
    }
}

/// Selective Acknowledgement data containing 1 to 4 SACK blocks (RFC 2018).
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct TcpSack {
    blocks: ArrayVec<TcpSackBlock, 4>,
}

/// Errors from creating a [`TcpSack`].
#[derive(Debug, thiserror::Error)]
pub enum TcpSackError {
    /// SACK must contain 1 to 4 blocks.
    #[error("invalid SACK block count: {0} (expected 1..=4)")]
    InvalidBlockCount(usize),
}

impl TcpSack {
    /// Maximum number of SACK blocks.
    pub const MAX_BLOCKS: usize = 4;

    /// Create a new [`TcpSack`] from a slice of blocks.
    ///
    /// # Errors
    ///
    /// Returns [`TcpSackError::InvalidBlockCount`] if `blocks` is empty or
    /// contains more than 4 blocks.
    pub fn new(blocks: &[TcpSackBlock]) -> Result<Self, TcpSackError> {
        if blocks.is_empty() || blocks.len() > Self::MAX_BLOCKS {
            return Err(TcpSackError::InvalidBlockCount(blocks.len()));
        }
        let mut av = ArrayVec::new();
        av.try_extend_from_slice(blocks)
            .unwrap_or_else(|_| unreachable!());
        Ok(TcpSack { blocks: av })
    }

    /// The number of SACK blocks (always 1..=4).
    #[must_use]
    pub fn len(&self) -> NonZero<u8> {
        #[allow(clippy::cast_possible_truncation)] // bounded to 4
        NonZero::new(self.blocks.len() as u8).unwrap_or_else(|| unreachable!())
    }

    /// The SACK blocks.
    #[must_use]
    pub fn blocks(&self) -> &[TcpSackBlock] {
        &self.blocks
    }
}

// ---------------------------------------------------------------------------
// TcpOptionParseError
// ---------------------------------------------------------------------------

/// Errors from parsing a TCP option.
#[derive(Debug, thiserror::Error)]
pub enum TcpOptionParseError {
    /// MSS value was zero.
    #[error("zero MSS value")]
    ZeroMss,
    /// Unknown TCP option kind byte.
    #[error("unknown TCP option kind: {0}")]
    UnknownKind(u8),
    /// Option data was truncated.
    #[error(
        "unexpected end of TCP option (kind {option_id}): \
         need {expected_len} bytes, have {actual_len}"
    )]
    UnexpectedEnd {
        /// The option kind byte.
        option_id: u8,
        /// Minimum bytes required.
        expected_len: u8,
        /// Bytes actually available.
        actual_len: usize,
    },
    /// Option length field had an unexpected value.
    #[error("unexpected size {size} for TCP option kind {option_id}")]
    UnexpectedSize {
        /// The option kind byte.
        option_id: u8,
        /// The unexpected length value.
        size: u8,
    },
}

impl TcpOptionParseError {
    pub(in crate::tcp) fn from_etherparse_read(e: &etherparse::TcpOptionReadError) -> Self {
        use etherparse::TcpOptionReadError;
        match *e {
            TcpOptionReadError::UnknownId(id) => TcpOptionParseError::UnknownKind(id),
            TcpOptionReadError::UnexpectedEndOfSlice {
                option_id,
                expected_len,
                actual_len,
            } => TcpOptionParseError::UnexpectedEnd {
                option_id,
                expected_len,
                actual_len,
            },
            TcpOptionReadError::UnexpectedSize { option_id, size } => {
                TcpOptionParseError::UnexpectedSize { option_id, size }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TypeGenerator impls
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{TcpOption, TcpSack};
    use bolero::{Driver, TypeGenerator};
    use strum::EnumCount;

    impl TypeGenerator for TcpSack {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let count = (u.produce::<u8>()? % 4 + 1) as usize; // 1..=4
            let mut blocks = arrayvec::ArrayVec::new();
            for _ in 0..count {
                blocks.push(u.produce()?);
            }
            Some(TcpSack { blocks })
        }
    }

    impl TypeGenerator for TcpOption {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            static_assertions::const_assert!(TcpOption::COUNT <= u8::MAX as usize);
            #[allow(clippy::cast_possible_truncation)] // const asserted to be safe (also repr(u8))
            let variant_index = u.produce::<u8>()? % TcpOption::COUNT as u8;
            match variant_index {
                0 => Some(TcpOption::Noop),
                1 => Some(TcpOption::Mss(u.produce()?)),
                2 => Some(TcpOption::WindowScale(u.produce()?)),
                3 => Some(TcpOption::SackPermitted),
                4 => Some(TcpOption::Sack(u.produce()?)),
                5 => Some(TcpOption::Timestamp(u.produce()?, u.produce()?)),
                _ => unreachable!(),
            }
        }
    }
}

