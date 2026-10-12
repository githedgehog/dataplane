// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Length bounded octet strings.

use core::fmt::{Debug, Display, Formatter};
use core::str::Utf8Error;

/// An octet string of between `MIN` and `MAX` octets inclusive.
///
/// Nearly every variable length field in an [LLDPDU] is an octet string with a
/// protocol-imposed length range, and the ranges differ from field to field: a
/// chassis identifier is 1 to 255 octets, a system name is 0 to 255, a VLAN
/// name is 1 to 32.  `Octets` puts those bounds in the type, so a parsed field
/// cannot fall outside them and a crafted field cannot silently overflow the
/// TLV it is written into.
///
/// # Representation
///
/// The octets live on the heap.  LLDP is a control plane protocol which sees a
/// handful of frames per port per minute, so an allocation costs nothing worth
/// counting, while storing the worst case inline would make every enum that
/// holds one hundreds of octets wide.  [`Lldpdu`] holds a list of TLVs, so that
/// width would be multiplied by the number of TLVs in a frame.
///
/// # Encoding
///
/// [IEEE Std 802.1AB] describes several of these fields as strings, but it does
/// not require that the octets on the wire are valid UTF-8, and real
/// implementations do send fields which are not.  `Octets` therefore stores raw
/// octets and offers [`Octets::as_str`] for callers that want to interpret them
/// as text.  This keeps parsing byte-exact: an `Octets` always deparses to the
/// octets it was parsed from.
///
/// [LLDPDU]: crate::lldp::Lldpdu
/// [`Lldpdu`]: crate::lldp::Lldpdu
/// [IEEE Std 802.1AB]: https://standards.ieee.org/ieee/802.1AB/6047/
#[derive(
    Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct Octets<const MIN: usize, const MAX: usize>(Vec<u8>);

impl<const MIN: usize, const MAX: usize> Octets<MIN, MAX> {
    /// The fewest octets this type can hold.
    pub const MIN_LEN: usize = MIN;

    /// The most octets this type can hold.
    pub const MAX_LEN: usize = MAX;

    /// Build an `Octets` from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`OctetsError::TooShort`] if `bytes` is shorter than `MIN`, and
    /// [`OctetsError::TooLong`] if it is longer than `MAX`.
    pub fn new(bytes: &[u8]) -> Result<Octets<MIN, MAX>, OctetsError> {
        if bytes.len() < MIN {
            return Err(OctetsError::TooShort {
                len: bytes.len(),
                min: MIN,
            });
        }
        if bytes.len() > MAX {
            return Err(OctetsError::TooLong {
                len: bytes.len(),
                max: MAX,
            });
        }
        Ok(Octets(bytes.to_vec()))
    }

    /// The octets of this string.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The number of octets in this string.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if this string carries no octets.
    ///
    /// This can only be true when `MIN` is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Interpret the octets as a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns a [`Utf8Error`] if the octets are not valid UTF-8.  This is not
    /// a protocol violation; see the type level documentation.
    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        core::str::from_utf8(&self.0)
    }
}

impl<const MIN: usize, const MAX: usize> AsRef<[u8]> for Octets<MIN, MAX> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Deserialization goes through [`Octets::new`], so a representation which
/// falls outside `MIN..=MAX` is rejected rather than trusted.
impl<const MIN: usize, const MAX: usize> TryFrom<Vec<u8>> for Octets<MIN, MAX> {
    type Error = OctetsError;

    fn try_from(value: Vec<u8>) -> Result<Octets<MIN, MAX>, OctetsError> {
        Octets::new(&value)
    }
}

impl<const MIN: usize, const MAX: usize> From<Octets<MIN, MAX>> for Vec<u8> {
    fn from(value: Octets<MIN, MAX>) -> Vec<u8> {
        value.0
    }
}

impl<const MIN: usize, const MAX: usize> TryFrom<&[u8]> for Octets<MIN, MAX> {
    type Error = OctetsError;

    fn try_from(value: &[u8]) -> Result<Octets<MIN, MAX>, OctetsError> {
        Octets::new(value)
    }
}

/// Render as a quoted string when the octets are valid UTF-8, and as a hex
/// literal otherwise.  These fields are usually text, and a list of decimal
/// byte values is close to unreadable when they are.
impl<const MIN: usize, const MAX: usize> Debug for Octets<MIN, MAX> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        if let Ok(text) = self.as_str() {
            return write!(f, "{text:?}");
        }
        write!(f, "0x")?;
        self.0.iter().try_for_each(|octet| write!(f, "{octet:02x}"))
    }
}

/// Errors which can occur while building an [`Octets`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum OctetsError {
    /// The field is shorter than the protocol permits.
    #[error("octet string of {len} octets is too short (min {min})")]
    TooShort {
        /// The length of the offending octet string.
        len: usize,
        /// The shortest length which would have been accepted.
        min: usize,
    },
    /// The field is longer than the protocol permits.
    #[error("octet string of {len} octets is too long (max {max})")]
    TooLong {
        /// The length of the offending octet string.
        len: usize,
        /// The longest length which would have been accepted.
        max: usize,
    },
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::Octets;
    use bolero::{Driver, TypeGenerator};
    use core::ops::Bound;

    impl<const MIN: usize, const MAX: usize> TypeGenerator for Octets<MIN, MAX> {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let len = u.gen_usize(Bound::Included(&MIN), Bound::Included(&MAX))?;
            let mut inner = Vec::with_capacity(len);
            for _ in 0..len {
                inner.push(u.produce::<u8>()?);
            }
            Some(Octets(inner))
        }
    }
}

/// As text if the octets are printable UTF-8, as colon-separated hex otherwise.
///
/// LLDP carries both: names that are meant to be read and identifiers that are not, often under the
/// same TLV type, so the octets decide.
impl<const MIN: usize, const MAX: usize> Display for Octets<MIN, MAX> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        if let Ok(text) = self.as_str()
            && !text.chars().any(char::is_control)
        {
            return f.write_str(text);
        }
        for (i, octet) in self.as_bytes().iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{octet:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{Octets, OctetsError};

    #[test]
    fn octets_show_as_text_when_they_are_text_and_as_hex_otherwise() {
        let show = |bytes: &[u8]| Octets::<0, 8>::new(bytes).unwrap().to_string();
        assert_eq!(show(b"swp1"), "swp1");
        assert_eq!(show(&[0x00, 0x1b, 0xff]), "00:1b:ff");
        assert_eq!(
            show(b"a\nb"),
            "61:0a:62",
            "control characters are not shown as text"
        );
        assert_eq!(show(&[0xc3]), "c3", "invalid UTF-8 is not shown as text");
    }

    #[test]
    fn under_length_is_rejected() {
        assert_eq!(
            Octets::<1, 255>::new(&[]).unwrap_err(),
            OctetsError::TooShort { len: 0, min: 1 }
        );
        assert_eq!(
            Octets::<4, 8>::new(&[0, 1, 2]).unwrap_err(),
            OctetsError::TooShort { len: 3, min: 4 }
        );
    }

    #[test]
    fn over_length_is_rejected() {
        let too_long = [0u8; 5];
        assert_eq!(
            Octets::<0, 4>::new(&too_long).unwrap_err(),
            OctetsError::TooLong { len: 5, max: 4 }
        );
    }

    #[test]
    fn the_bounds_themselves_are_accepted() {
        assert_eq!(Octets::<2, 4>::new(&[0, 1]).unwrap().len(), 2);
        assert_eq!(Octets::<2, 4>::new(&[0, 1, 2, 3]).unwrap().len(), 4);
    }

    #[test]
    fn a_zero_minimum_admits_the_empty_string() {
        let empty = Octets::<0, 255>::new(&[]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn round_trips_through_slice() {
        bolero::check!()
            .with_type()
            .for_each(|octets: &Octets<0, 255>| {
                let reparsed = Octets::<0, 255>::new(octets.as_bytes()).unwrap();
                assert_eq!(&reparsed, octets);
            });
    }

    #[test]
    fn generated_values_comply_with_contract() {
        bolero::check!()
            .with_type()
            .for_each(|octets: &Octets<1, 255>| {
                assert!(!octets.is_empty());
                assert!(octets.len() <= 255);
                assert_eq!(octets.len(), octets.as_bytes().len());
            });
    }

    #[test]
    fn arbitrary_slices_are_accepted_exactly_when_legal() {
        bolero::check!()
            .with_type()
            .for_each(|raw: &Vec<u8>| match Octets::<2, 4>::new(raw) {
                Ok(octets) => {
                    assert_eq!(octets.as_bytes(), &raw[..]);
                    assert!((2..=4).contains(&octets.len()));
                }
                Err(OctetsError::TooShort { len, min }) => {
                    assert_eq!(len, raw.len());
                    assert_eq!(min, 2);
                    assert!(raw.len() < 2);
                }
                Err(OctetsError::TooLong { len, max }) => {
                    assert_eq!(len, raw.len());
                    assert_eq!(max, 4);
                    assert!(raw.len() > 4);
                }
            });
    }
}
