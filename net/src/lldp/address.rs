// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The network address encoding shared by several LLDP TLVs.
//!
//! A network address is a one octet [IANA address family number] followed by an
//! address whose length and interpretation depend on that family.  It appears
//! as a chassis ID subtype, as a port ID subtype, and (with an extra layer of
//! framing) in the management address TLV.
//!
//! [IANA address family number]: https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::lldp::octets::{Octets, OctetsError};

/// The address portion of a network address.
///
/// A chassis or port identifier is at most 255 octets, one of which is spent on
/// the family, so an unrecognized address is at most 254 octets.
pub type AddressOctets = Octets<1, 254>;

/// A network address as encoded inside an LLDP TLV.
///
/// The two address families the dataplane cares about are modelled directly.
/// Every other family is preserved verbatim in [`NetworkAddress::Other`] rather
/// than rejected, because the IANA registry is large, the field is
/// pass-through, and discarding an LLDPDU over an address family we happen not
/// to recognize would be unhelpful.
///
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum NetworkAddress {
    /// An IPv4 address (family 1).
    Ipv4(Ipv4Addr),
    /// An IPv6 address (family 2).
    Ipv6(Ipv6Addr),
    /// An address in some other family.
    Other(OtherNetworkAddress),
}

impl NetworkAddress {
    /// The IANA address family number for IPv4.
    pub const FAMILY_IPV4: u8 = 1;
    /// The IANA address family number for IPv6.
    pub const FAMILY_IPV6: u8 = 2;

    /// The IANA address family number of this address.
    #[must_use]
    pub const fn family(&self) -> u8 {
        match self {
            NetworkAddress::Ipv4(_) => NetworkAddress::FAMILY_IPV4,
            NetworkAddress::Ipv6(_) => NetworkAddress::FAMILY_IPV6,
            NetworkAddress::Other(other) => other.family,
        }
    }

    /// The number of octets this address occupies on the wire, including the
    /// family octet.
    #[must_use]
    pub fn octet_len(&self) -> usize {
        let address_len = match self {
            NetworkAddress::Ipv4(_) => 4,
            NetworkAddress::Ipv6(_) => 16,
            NetworkAddress::Other(other) => other.address.len(),
        };
        1 + address_len
    }

    /// Decode a network address from the family octet onwards.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkAddressError::Empty`] if there is not even a family
    /// octet, [`NetworkAddressError::WrongAddressLength`] if a recognized
    /// family is paired with an address of the wrong length, and
    /// [`NetworkAddressError::Address`] if an unrecognized family is paired
    /// with an address which cannot be stored.
    pub fn from_octets(octets: &[u8]) -> Result<NetworkAddress, NetworkAddressError> {
        let Some((&family, address)) = octets.split_first() else {
            return Err(NetworkAddressError::Empty);
        };
        match family {
            NetworkAddress::FAMILY_IPV4 => {
                let raw: [u8; 4] =
                    address
                        .try_into()
                        .map_err(|_| NetworkAddressError::WrongAddressLength {
                            family,
                            expected: 4,
                            found: address.len(),
                        })?;
                Ok(NetworkAddress::Ipv4(Ipv4Addr::from(raw)))
            }
            NetworkAddress::FAMILY_IPV6 => {
                let raw: [u8; 16] =
                    address
                        .try_into()
                        .map_err(|_| NetworkAddressError::WrongAddressLength {
                            family,
                            expected: 16,
                            found: address.len(),
                        })?;
                Ok(NetworkAddress::Ipv6(Ipv6Addr::from(raw)))
            }
            other => {
                let address = AddressOctets::new(address).map_err(NetworkAddressError::Address)?;
                Ok(NetworkAddress::Other(OtherNetworkAddress {
                    family: other,
                    address,
                }))
            }
        }
    }

    /// Write this address, family octet first, into the front of `buf`.
    ///
    /// The caller is responsible for having already confirmed that `buf` is at
    /// least [`NetworkAddress::octet_len`] octets long.
    pub(crate) fn write_octets(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= self.octet_len());
        buf[0] = self.family();
        match self {
            NetworkAddress::Ipv4(ip) => buf[1..5].copy_from_slice(&ip.octets()),
            NetworkAddress::Ipv6(ip) => buf[1..17].copy_from_slice(&ip.octets()),
            NetworkAddress::Other(other) => {
                let address = other.address.as_bytes();
                buf[1..=address.len()].copy_from_slice(address);
            }
        }
    }
}

impl From<Ipv4Addr> for NetworkAddress {
    fn from(value: Ipv4Addr) -> NetworkAddress {
        NetworkAddress::Ipv4(value)
    }
}

impl From<Ipv6Addr> for NetworkAddress {
    fn from(value: Ipv6Addr) -> NetworkAddress {
        NetworkAddress::Ipv6(value)
    }
}

/// A network address in a family this library does not model directly.
///
/// The family is guaranteed not to be one of the families which
/// [`NetworkAddress`] does model.  Without that guarantee the same octets on
/// the wire would have two representations, only one of which a parser could
/// produce, and a deparse then parse cycle would not be an identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(remote = "Self")]
pub struct OtherNetworkAddress {
    family: u8,
    address: AddressOctets,
}

impl OtherNetworkAddress {
    /// Build an address in an unmodelled family.
    ///
    /// # Errors
    ///
    /// Returns [`AmbiguousFamily`] if `family` is one of the families
    /// [`NetworkAddress`] models directly; use the corresponding
    /// [`NetworkAddress`] variant instead.
    pub fn new(family: u8, address: AddressOctets) -> Result<OtherNetworkAddress, AmbiguousFamily> {
        if family == NetworkAddress::FAMILY_IPV4 || family == NetworkAddress::FAMILY_IPV6 {
            return Err(AmbiguousFamily(family));
        }
        Ok(OtherNetworkAddress { family, address })
    }

    /// The IANA address family number of this address.
    #[must_use]
    pub const fn family(&self) -> u8 {
        self.family
    }

    /// The address itself, not including the family octet.
    #[must_use]
    pub const fn address(&self) -> &AddressOctets {
        &self.address
    }
}

/// Deserialization goes through the derived shape and then re-checks the
/// invariant, so a hand written or tampered representation cannot smuggle in a
/// family which has a dedicated [`NetworkAddress`] variant.
impl<'de> serde::Deserialize<'de> for OtherNetworkAddress {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OtherNetworkAddress, D::Error> {
        let unchecked = OtherNetworkAddress::deserialize(deserializer)?;
        OtherNetworkAddress::new(unchecked.family, unchecked.address)
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for OtherNetworkAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        OtherNetworkAddress::serialize(self, serializer)
    }
}

/// The error returned when [`OtherNetworkAddress`] is handed a family which
/// [`NetworkAddress`] models directly.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("address family {0} has a dedicated NetworkAddress variant")]
pub struct AmbiguousFamily(pub u8);

/// Errors which can occur while decoding a [`NetworkAddress`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NetworkAddressError {
    /// The field did not contain even an address family octet.
    #[error("network address is missing its address family octet")]
    Empty,
    /// A recognized address family was paired with an address of the wrong
    /// length.
    #[error("address family {family} requires a {expected} octet address, found {found} octets")]
    WrongAddressLength {
        /// The address family in question.
        family: u8,
        /// The length that family requires.
        expected: usize,
        /// The length actually found.
        found: usize,
    },
    /// The address in an unrecognized family could not be stored.
    #[error(transparent)]
    Address(OctetsError),
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{NetworkAddress, OtherNetworkAddress};
    use bolero::{Driver, TypeGenerator};
    use core::net::{Ipv4Addr, Ipv6Addr};

    impl TypeGenerator for OtherNetworkAddress {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let family = match u.produce::<u8>()? {
                // Steer clear of the families which have their own variant
                // rather than rejecting, so the driver does not waste budget.
                NetworkAddress::FAMILY_IPV4 | NetworkAddress::FAMILY_IPV6 => 3,
                other => other,
            };
            OtherNetworkAddress::new(family, u.produce()?).ok()
        }
    }

    impl TypeGenerator for NetworkAddress {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            match u.produce::<u8>()? % 3 {
                0 => Some(NetworkAddress::Ipv4(Ipv4Addr::from(
                    u.produce::<[u8; 4]>()?,
                ))),
                1 => Some(NetworkAddress::Ipv6(Ipv6Addr::from(
                    u.produce::<[u8; 16]>()?,
                ))),
                _ => Some(NetworkAddress::Other(u.produce()?)),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        AddressOctets, AmbiguousFamily, NetworkAddress, NetworkAddressError, OtherNetworkAddress,
    };

    #[test]
    fn empty_input_is_rejected() {
        assert_eq!(
            NetworkAddress::from_octets(&[]).unwrap_err(),
            NetworkAddressError::Empty
        );
    }

    #[test]
    fn short_ipv4_is_rejected() {
        assert_eq!(
            NetworkAddress::from_octets(&[1, 10, 0, 0]).unwrap_err(),
            NetworkAddressError::WrongAddressLength {
                family: 1,
                expected: 4,
                found: 3,
            }
        );
    }

    #[test]
    fn long_ipv6_is_rejected() {
        let raw = [2u8; 18];
        assert_eq!(
            NetworkAddress::from_octets(&raw).unwrap_err(),
            NetworkAddressError::WrongAddressLength {
                family: 2,
                expected: 16,
                found: 17,
            }
        );
    }

    #[test]
    fn modelled_families_are_rejected_by_other() {
        let address = AddressOctets::new(&[1, 2, 3, 4]).unwrap();
        assert_eq!(
            OtherNetworkAddress::new(1, address.clone()).unwrap_err(),
            AmbiguousFamily(1)
        );
        assert_eq!(
            OtherNetworkAddress::new(2, address).unwrap_err(),
            AmbiguousFamily(2)
        );
    }

    #[test]
    fn round_trips() {
        bolero::check!()
            .with_type()
            .for_each(|address: &NetworkAddress| {
                let mut buf = vec![0u8; address.octet_len()];
                address.write_octets(&mut buf);
                let parsed = NetworkAddress::from_octets(&buf).unwrap();
                assert_eq!(&parsed, address);
                assert_eq!(parsed.octet_len(), buf.len());
            });
    }

    #[test]
    fn parse_of_arbitrary_octets_is_byte_exact() {
        bolero::check!().with_type().for_each(|raw: &Vec<u8>| {
            let Ok(address) = NetworkAddress::from_octets(raw) else {
                return;
            };
            assert_eq!(address.octet_len(), raw.len());
            let mut buf = vec![0u8; address.octet_len()];
            address.write_octets(&mut buf);
            assert_eq!(&buf, raw);
        });
    }
}
