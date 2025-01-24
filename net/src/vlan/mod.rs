// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VLAN validation and manipulation.

use crate::eth::{parse_from_ethertype, EthNext};
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError, Reader, Step};
use core::num::NonZero;
use etherparse::{EtherType, SingleVlanHeader, VlanId, VlanPcp};

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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
// SAFETY: only use of unsafe is unrelated to deserialize logic
#[allow(clippy::unsafe_derive_deserialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
pub struct Vid(NonZero<u16>);

/// A Priority Code Point.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Pcp(pub u8);

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
    #[allow(unsafe_code)] // safe due to const eval
    pub const MIN: Vid = Vid(unsafe { NonZero::new_unchecked(1) });

    /// The maximum legal [`Vid`] value (2^12 - 2).
    #[allow(unsafe_code)] // safe due to const eval
    pub const MAX: Vid = Vid(unsafe { NonZero::new_unchecked(4094) });

    /// Create a new [`Vid`] from a `u16`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is 0, 4095 (reserved), or greater than [`Vid::MAX`].
    #[tracing::instrument(level = "trace")]
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
    pub fn as_u16(self) -> u16 {
        self.0.get()
    }

    /// Check the contract of the `Vid::new` function.
    ///
    /// # Panics
    ///
    /// 1. Never panics if `Vid::new` is written correctly.
    /// 2. Always panics if `Vid::new` violates expected invariants.
    #[cfg(any(test, feature = "contract"))]
    pub fn check_new_contract(raw: u16) {
        match Vid::new(raw) {
            Ok(vid) => {
                assert_eq!(vid.as_u16(), raw);
                assert!(vid >= Vid::MIN);
                assert!(vid <= Vid::MAX);
                assert!(vid.as_u16() >= Vid::MIN.as_u16());
                assert!(vid.as_u16() <= Vid::MAX.as_u16());
            }
            Err(InvalidVid::Zero) => assert_eq!(raw, 0),
            Err(InvalidVid::Reserved) => assert_eq!(raw, InvalidVid::RESERVED),
            Err(InvalidVid::TooLarge(x)) => {
                assert_eq!(x, raw);
                assert!(raw >= InvalidVid::TOO_LARGE);
            }
        }
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

/// A VLAN header.
///
/// This may represent 802.1Q or 802.1AD
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vlan {
    inner: SingleVlanHeader,
}

impl Vlan {
    /// Create a new [Vlan] header.
    #[must_use]
    pub fn new(vid: Vid, ether_type: EtherType) -> Vlan {
        Vlan {
            inner: SingleVlanHeader {
                pcp: VlanPcp::ZERO,
                drop_eligible_indicator: false,
                #[allow(unsafe_code)] // SAFETY: overlapping check between libraries.
                vlan_id: unsafe { VlanId::new_unchecked(vid.as_u16()) },
                ether_type,
            },
        }
    }

    /// Get the [`Vid`] found in the parsed header.
    ///
    /// # Errors
    ///
    /// The parsed header may not include a valid [`Vid`], and in that case an `InvalidVid` error
    /// will be returned.
    pub fn vid(&self) -> Result<Vid, InvalidVid> {
        Vid::new(self.inner.vlan_id.value())
    }

    /// Get the vlan id without ensuring it is a valid [`Vid`].
    ///
    /// # Safety
    ///
    /// This function does not ensure that the [`Vid`] is greater than zero or less than 4095.
    /// Avoid using this method on untrusted data.
    #[must_use]
    #[allow(unsafe_code)] // explicitly unsafe
    pub unsafe fn vid_unchecked(&self) -> Vid {
        Vid::new_unchecked(self.inner.vlan_id.value())
    }
}

impl Parse for Vlan {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = SingleVlanHeader::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::LengthError(LengthError {
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

impl DeParse for Vlan {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.inner.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn write(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::LengthError(LengthError {
                expected: self.size(),
                actual: len,
            }));
        };
        buf[..self.size().get()].copy_from_slice(&self.inner.to_bytes());
        Ok(self.size())
    }
}

impl Step for Vlan {
    type Next = EthNext;

    fn step(&self, cursor: &mut Reader) -> Option<EthNext> {
        parse_from_ethertype(self.inner.ether_type, cursor)
    }
}

/// Contracts for Vlan types
#[cfg(any(test, feature = "contract"))]
pub mod contract {
    use crate::contract::{CheckTypeContract, TypeGenerator};
    use crate::vlan::{InvalidVid, Vid};
    use proptest::prelude::*;

    impl TypeGenerator for Vid {
        fn generate_valid() -> impl Strategy<Value = Self> {
            any::<u16>().prop_map(|x| {
                let x = x & InvalidVid::RESERVED;
                if x == 0 {
                    Vid::new(1).unwrap_or_else(|_| unreachable!())
                } else if x == InvalidVid::RESERVED {
                    Vid::new(InvalidVid::RESERVED - 1).unwrap_or_else(|_| unreachable!())
                }  else {
                    Vid::new(x).unwrap_or_else(|_| unreachable!())
                }
            })
        }
    }

    #[cfg(any(test, feature = "contract"))]
    impl CheckTypeContract for Vid {
        #[allow(clippy::unwrap_used)] // method must panic if the contract is violated
        fn check_type_contract(&self) {
            let other = Vid::new(self.as_u16()).unwrap();
            assert_eq!(self.as_u16(), other.as_u16());
            assert_eq!(self, &other);
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod test {
    use super::*;
    use crate::contract::{CheckTypeContract, TypeGenerator};
    use crate::vlan::Vid;
    use proptest::prelude::*;

    #[test]
    fn vid_min_is_valid() {
        let vid = Vid::MIN;
        assert_eq!(vid.as_u16(), 1);
        assert_eq!(vid, Vid::new(1).unwrap());
        vid.check_type_contract();
    }

    #[test]
    fn vid_max_is_valid() {
        let vid = Vid::MAX;
        assert_eq!(vid.as_u16(), Vid::MAX.0.get());
        assert_eq!(vid, Vid::new(Vid::MAX.0.get()).unwrap());
        vid.check_type_contract();
    }

    #[test]
    #[allow(unsafe_code)]
    fn unsafe_vid_versions_work() {
        let vid = unsafe { Vid::new_unchecked(1) };
        assert_eq!(vid.as_u16(), 1);
        assert_eq!(vid, Vid::new(1).unwrap());
    }

    #[test]
    #[allow(unsafe_code)]
    #[should_panic]
    fn illegal_vid_4094_contract_panics() {
        let vid = unsafe { Vid::new_unchecked(InvalidVid::RESERVED) };
        vid.check_type_contract();
    }

    #[test]
    #[allow(unsafe_code)]
    #[should_panic]
    fn illegal_vid_too_large_contract_panics() {
        let vid = unsafe { Vid::new_unchecked(InvalidVid::TOO_LARGE) };
        vid.check_type_contract();
    }

    #[test]
    #[allow(unsafe_code)]
    #[should_panic]
    fn illegal_vid_u16_max_contract_panics() {
        let vid = unsafe { Vid::new_unchecked(u16::MAX) };
        vid.check_type_contract();
    }

    #[test]
    fn vid_zero_is_invalid() {
        match Vid::new(0) {
            Err(InvalidVid::Zero) => {}
            e => panic!(
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
            e => panic!(
                "Vid::new(InvalidVid::TOO_LARGE) should have failed with InvalidVid::TooLarge, but instead returned {e:?}",
            ),
        }
    }

    #[test]
    fn vid_reserved_is_invalid() {
        match Vid::new(InvalidVid::RESERVED) {
            Err(InvalidVid::Reserved) => {}
            e => panic!(
                "Vid::new(InvalidVid::RESERVED) should have failed with InvalidVid::Reserved, but instead returned {e:?}",
            ),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]
        #[test]
        fn check_vid_new_contract(raw in any::<u16>()) {
            Vid::check_new_contract(raw);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]
        #[test]
        fn check_vid_new_contract_zero(raw in Vid::generate_valid()) {
            raw.check_type_contract();
        }
    }
}
