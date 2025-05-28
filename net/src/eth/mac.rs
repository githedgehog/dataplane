// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Mac address type and logic.

use arrayvec::ArrayVec;
use std::fmt::Display;

/// A [MAC Address] type.
///
/// `Mac` is a transparent wrapper around `[u8; 6]` which provides a
/// small collection of methods and type safety.
///
/// [MAC Address]: https://en.wikipedia.org/wiki/MAC_address
#[repr(transparent)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(bolero::TypeGenerator))]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Mac(pub [u8; 6]);

impl From<[u8; 6]> for Mac {
    fn from(value: [u8; 6]) -> Self {
        Mac(value)
    }
}

impl From<Mac> for [u8; 6] {
    fn from(value: Mac) -> Self {
        value.0
    }
}

impl AsRef<[u8; 6]> for Mac {
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl AsMut<[u8; 6]> for Mac {
    fn as_mut(&mut self) -> &mut [u8; 6] {
        &mut self.0
    }
}

/// Errors which can occur while converting a string to a [`Mac`]
#[derive(Debug, thiserror::Error)]
pub enum MacFromStringError {
    /// Invalid string representation of mac address
    #[error("invalid string representation of mac address: {0}")]
    Invalid(String),
}

impl TryFrom<&str> for Mac {
    type Error = MacFromStringError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        const MAX_OCTETS: usize = 6;
        let mut octets_strs = value.split(':');
        let octets_parsed =
            octets_strs.try_fold(ArrayVec::<_, MAX_OCTETS>::new(), |mut acc, octet_str| {
                if octet_str.len() != 2 {
                    return Err(MacFromStringError::Invalid(value.to_string()));
                }
                if octet_str.chars().any(|c| !c.is_ascii_hexdigit()) {
                    return Err(MacFromStringError::Invalid(value.to_string()));
                }
                let parsed = u8::from_str_radix(octet_str, 16)
                    .map_err(|_| MacFromStringError::Invalid(value.to_string()))?;
                acc.try_push(parsed)
                    .map_err(|_| MacFromStringError::Invalid(value.to_string()))?;
                Ok(acc)
            })?;

        let octets = match octets_parsed.as_slice() {
            [o0, o1, o2, o3, o4, o5] => [*o0, *o1, *o2, *o3, *o4, *o5],
            _ => return Err(MacFromStringError::Invalid(value.to_string())),
        };

        Ok(Mac(octets))
    }
}

impl Mac {
    /// The broadcast `Mac`
    pub const BROADCAST: Mac = Mac([u8::MAX; 6]);
    /// The zero `Mac`.
    ///
    /// `ZERO` is illegal as a source or destination `Mac` in most contexts.
    pub const ZERO: Mac = Mac([0; 6]);

    /// Returns true iff the binary representation of the [`Mac`] is exclusively ones.
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self == &Mac::BROADCAST
    }

    /// Returns true iff the least significant bit of the first octet of the `[Mac]` is one.
    #[must_use]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 == 0x01
    }

    /// Returns true iff the least significant bit of the first octet of the `[Mac]` is zero.
    #[must_use]
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Returns true iff the binary representation of the [`Mac`] is exclusively zeros.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self == &Mac::ZERO
    }

    /// Returns true iff the second least significant bit of the first octet is one.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Returns true iff the second least significant bit of the first octet is zero.
    #[must_use]
    pub fn is_universal(&self) -> bool {
        !self.is_local()
    }

    /// Returns true if the [`Mac`] is reserved for link local usage.
    ///
    /// Link local usage includes [spanning tree protocol] and [LACP].
    ///
    /// [spanning tree protocol]: https://en.wikipedia.org/wiki/Spanning_Tree_Protocol
    /// [LACP]: https://en.wikipedia.org/wiki/Link_aggregation#Link_Aggregation_Control_Protocol
    #[must_use]
    pub fn is_link_local(&self) -> bool {
        let bytes = self.as_ref();
        (bytes[0..5] == [0x01, 0x80, 0xc2, 0x00, 0x00]) && (bytes[5] & 0x0f == bytes[5])
    }

    /// Returns `Ok(())` iff the [`Mac`] is a legal source `Mac`.
    ///
    /// # Errors
    ///
    /// Multicast and zero are not legal [`SourceMac`].
    pub fn valid_src(&self) -> Result<(), SourceMacAddressError> {
        if self.is_zero() {
            Err(SourceMacAddressError::ZeroSource(*self))
        } else if self.is_multicast() {
            Err(SourceMacAddressError::MulticastSource(*self))
        } else {
            Ok(())
        }
    }

    /// Returns `Ok(())` iff the [`Mac`] is a legal destination [`Mac`].
    ///
    /// # Errors
    ///
    /// Zero is not a legal destination [`Mac`].
    pub fn valid_dst(&self) -> Result<(), DestinationMacAddressError> {
        if self.is_zero() {
            Err(DestinationMacAddressError::ZeroDestination(*self))
        } else {
            Ok(())
        }
    }

    /// Return true iff the [`Mac`] is not zero.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_zero()
    }
}

impl Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl Display for SourceMac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner().fmt(f)
    }
}

impl Display for DestinationMac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner().fmt(f)
    }
}

/// A [`Mac`] which is legal as a source in an ethernet header.
#[allow(clippy::unsafe_derive_deserialize)] // unsafe methods not called in Deserialize
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(try_from = "Mac", into = "Mac")]
#[repr(transparent)]
pub struct SourceMac(Mac);

impl SourceMac {
    /// Map a [`Mac`] to a [`SourceMac`]
    ///
    /// # Errors
    ///
    /// Will return a [`SourceMacAddressError`] if the supplied [`Mac`] is not a legal source [`Mac`].
    pub fn new(mac: Mac) -> Result<SourceMac, SourceMacAddressError> {
        mac.valid_src().map(|()| SourceMac(mac))
    }

    /// Map a [`Mac`] to a [`SourceMac`] without checking validity.
    ///
    /// # Safety
    ///
    /// Supplied [`Mac`] must be a valid source [`Mac`].
    #[allow(unsafe_code)]
    pub(crate) unsafe fn new_unchecked(mac: Mac) -> SourceMac {
        SourceMac(mac)
    }

    /// Map the [`SourceMac`] back to an unqualified [`Mac`]
    #[must_use]
    pub const fn inner(self) -> Mac {
        self.0
    }
}

/// A [`Mac`] which is legal as a destination in an ethernet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct DestinationMac(Mac);

impl DestinationMac {
    /// Map a [`Mac`] to a [`DestinationMac`]
    ///
    /// # Errors
    ///
    /// Will return a [`DestinationMacAddressError`] if the supplied [`Mac`] is not legal as a
    /// destination.
    pub fn new(mac: Mac) -> Result<DestinationMac, DestinationMacAddressError> {
        mac.valid_dst().map(|()| DestinationMac(mac))
    }

    /// Map a [`Mac`] to a [`DestinationMac`] without checking validity.
    ///
    /// # Safety
    ///
    /// Supplied [`Mac`] must be a valid destination [`Mac`].
    #[allow(unsafe_code)]
    pub(crate) unsafe fn new_unchecked(mac: Mac) -> DestinationMac {
        DestinationMac(mac)
    }

    /// Map the [`DestinationMac`] back to an unqualified [`Mac`]
    #[must_use]
    pub const fn inner(self) -> Mac {
        self.0
    }
}

/// Errors which can occur while setting the source [`Mac`] of a [`Packet`]
///
/// [`Packet`]: crate::headers::Headers
#[derive(Debug, thiserror::Error)]
pub enum SourceMacAddressError {
    /// Multicast [`Mac`]s are not legal as a source [`Mac`]
    #[error("invalid source MAC address: multicast MACs are illegal as source macs")]
    MulticastSource(Mac),
    /// Zero is not a legal source
    #[error("invalid source MAC address: zero MAC is illegal as source MAC")]
    ZeroSource(Mac),
}

/// Errors which may occur when parsing a [`SourceMac`] from a `Vec<u8>`
#[derive(Debug, thiserror::Error)]
pub enum SourceMacParseError {
    /// Class of errors which are not valid as [`SourceMac`]
    #[error(transparent)]
    SourceMacError(#[from] SourceMacAddressError),
    /// Not a [`Mac`] at all
    #[error("length error: invalid MAC {0:?}")]
    NotAMac(Vec<u8>),
}

/// Errors which can occur while setting the destination [`Mac`] of a [`Packet`]
///
/// [`Packet`]: crate::headers::Headers
#[derive(Debug, thiserror::Error)]
pub enum DestinationMacAddressError {
    /// Zero is not a legal source
    #[error("invalid destination mac address: zero mac is illegal as destination mac")]
    ZeroDestination(Mac),
}

impl AsRef<Mac> for SourceMac {
    fn as_ref(&self) -> &Mac {
        &self.0
    }
}

impl AsRef<Mac> for DestinationMac {
    fn as_ref(&self) -> &Mac {
        &self.0
    }
}

impl From<SourceMac> for Mac {
    fn from(value: SourceMac) -> Self {
        value.0
    }
}

impl From<SourceMac> for DestinationMac {
    fn from(value: SourceMac) -> Self {
        DestinationMac(value.0)
    }
}

impl TryFrom<Mac> for SourceMac {
    type Error = SourceMacAddressError;

    fn try_from(value: Mac) -> Result<Self, Self::Error> {
        SourceMac::new(value)
    }
}

impl TryFrom<&Vec<u8>> for SourceMac {
    type Error = SourceMacParseError;

    fn try_from(addr: &Vec<u8>) -> Result<Self, Self::Error> {
        match TryInto::<[u8; 6]>::try_into(addr.as_ref()) {
            Ok(array) => match SourceMac::new(Mac::from(array)) {
                Ok(mac) => Ok(mac),
                Err(SourceMacAddressError::ZeroSource(zero)) => Err(
                    SourceMacParseError::SourceMacError(SourceMacAddressError::ZeroSource(zero)),
                ),
                Err(SourceMacAddressError::MulticastSource(mac)) => {
                    Err(SourceMacParseError::SourceMacError(
                        SourceMacAddressError::MulticastSource(mac),
                    ))
                }
            },
            Err(_) => Err(SourceMacParseError::NotAMac(addr.clone())),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::eth::mac::{DestinationMac, Mac, SourceMac};
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use std::ops::Bound;
    impl TypeGenerator for SourceMac {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let mut mac: Mac = u.produce()?;
            mac.0[0] &= 0b1111_1110;
            if mac.is_zero() {
                mac.0[5] = 1;
            }
            Some(SourceMac::new(mac).unwrap_or_else(|e| unreachable!("{e:?}", e = e)))
        }
    }

    impl TypeGenerator for DestinationMac {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let mut mac: Mac = u.produce()?;
            if mac.is_zero() {
                mac.0[5] = 1;
            }
            Some(DestinationMac::new(mac).unwrap_or_else(|e| unreachable!("{e:?}", e = e)))
        }
    }

    /// Generate valid MAC address strings in format XX:XX:XX:XX:XX:XX
    pub struct MacTestStringGenerator;
    impl ValueGenerator for MacTestStringGenerator {
        type Output = String;

        fn generate<D: Driver>(&self, u: &mut D) -> Option<Self::Output> {
            let hexchars = "0123456789abcdefABCDEF";
            let s: Option<String> = (0..6)
                .map(|_| {
                    let segment: Option<String> = (0..2)
                        .map(|_| {
                            hexchars.chars().nth(
                                u.gen_usize(Bound::Included(&0), Bound::Excluded(&hexchars.len()))?,
                            )
                        })
                        .collect();
                    segment
                })
                .collect::<Option<Vec<String>>>()
                .map(|v| v.join(":"));
            s
        }
    }
}

#[cfg(test)]
mod test {
    use super::Mac;
    use crate::eth::mac::contract::MacTestStringGenerator;
    use bolero::{Driver, ValueGenerator};
    use std::ops::Bound;

    struct InvalidMacStringGenerator;
    impl ValueGenerator for InvalidMacStringGenerator {
        type Output = String;

        fn generate<D: Driver>(&self, u: &mut D) -> Option<Self::Output> {
            let mut valid_mac = MacTestStringGenerator.generate(u)?;
            let fuzz_u8: u8 = u.produce()?;
            let fuzz_char = char::from(fuzz_u8);
            if fuzz_char.is_ascii_hexdigit() || fuzz_char == ':' {
                // If fuzz_char is a valid hex digit, overwrite a random character
                let pos = u.gen_usize(Bound::Included(&0), Bound::Excluded(&valid_mac.len()))?;
                valid_mac.insert(pos, fuzz_char);
            } else {
                // If fuzz_char is not a valid hex digit, insert it at a random position
                let pos = u.gen_usize(Bound::Included(&0), Bound::Excluded(&valid_mac.len()))?;
                valid_mac.replace_range(pos..=pos, &fuzz_char.to_string());
            }
            Some(valid_mac)
        }
    }

    #[test]
    fn test_mac_from_valid_string() {
        bolero::check!()
            .with_generator(MacTestStringGenerator)
            .for_each(|input: &String| {
                let result = Mac::try_from(input.as_str());
                assert_eq!(
                    input.to_lowercase(),
                    result.unwrap().to_string().to_lowercase()
                );
            });
    }

    #[test]
    fn test_mac_from_invalid_string() {
        bolero::check!()
            .with_generator(InvalidMacStringGenerator)
            .for_each(|input: &String| {
                let result = Mac::try_from(input.as_str());
                assert!(result.is_err());
            });
    }

    #[test]
    fn mac_from_string_too_many_octets() {
        let result = Mac::try_from("00:00:00:00:00:00:00");
        assert!(result.is_err());

        let result = Mac::try_from("00:00:00:00:00:00:00:00");
        assert!(result.is_err());
    }

    #[test]
    fn mac_from_string_too_few_octets() {
        let result = Mac::try_from("00:00:00:00:00");
        assert!(result.is_err());
    }

    #[test]
    fn mac_from_string_invalid_octet() {
        let result = Mac::try_from("00:00:00:00:00:000");
        assert!(result.is_err());

        let result = Mac::try_from("00:00:00:00:+00:00");
        assert!(result.is_err());
    }
}
