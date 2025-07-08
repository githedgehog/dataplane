// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(any(test, feature = "bolero"))]
#[allow(unused_imports)] // re-export
pub use contract::*;
use ipnet::{AddrParseError, Ipv4Net};
use prefix_trie::Prefix;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::net::Ipv4Addr;
use std::str::FromStr;
use tracing::{debug, warn};

/// An `Ipv4Addr` with a mask describing a network in CIDR notation.
///
/// Note that unlike [`Ipv4Net`] from the `ipnet` crate, this type ensures that only network bits
/// are set in the address.
#[derive(
    Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Ipv4Prefix(Ipv4Net);

/// A checked type describing the values 0 to 32, which constitute all legal prefix lengths for
/// Ipv4 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(try_from = "u8", into = "u8")]
pub struct Ipv4PrefixLen(u8);

/// An error indicating that an invalid prefix length was provided.
#[derive(Debug, thiserror::Error)]
#[repr(transparent)]
pub enum InvalidIpv4PrefixLength {
    /// The provided prefix is too long to form a legal [`Ipv4PrefixLen`]
    #[error("invalid prefix length {0} is invalid, max is {MAX}", MAX = Ipv4PrefixLen::MAX_LEN)]
    TooLong(u8),
}

/// An error indicating that an invalid network was provided.
#[derive(Debug, thiserror::Error)]
pub enum InvalidIpv4Network {
    /// The provided network description contains set non-network bits
    #[error("Address {0}/{1} contains non network bits")]
    AddressContainsNonNetworkBits(Ipv4Addr, Ipv4PrefixLen),
    /// The provided prefix length is invalid
    #[error(transparent)]
    InvalidPrefix(InvalidIpv4PrefixLength),
}

/// An error indicating that an invalid network was provided.
#[derive(Debug, thiserror::Error)]
pub enum Ipv4PrefixParseError {
    /// failure to interpret string as an ip and a prefix length
    #[error(transparent)]
    AddrParseError(AddrParseError),
    /// invalid ip or prefix length
    #[error(transparent)]
    InvalidIpv4Network(InvalidIpv4Network),
}

impl Ipv4PrefixLen {
    /// The largest possible prefix length for IPv4 (i.e. /32)
    pub const MAX_LEN: u8 = 32;
    /// The largest possible prefix length for IPv4 (i.e. /32)
    pub const MAX: Self = Self(Self::MAX_LEN);
    /// The minimum possible prefix length for IPv4 (i.e. /0)
    pub const MIN: Self = Self(0);

    /// Constructor which asserts if the provided length is invalid.
    /// Useful in const contexts where you are sure you won't panic.
    ///
    /// # Panics
    ///
    /// Panics if the provided length is greater than [`Ipv4PrefixLen::MAX_LEN`].
    #[must_use]
    pub const fn new_assert(len: u8) -> Self {
        assert!(len <= Self::MAX_LEN, "invalid prefix length");
        Self(len)
    }

    /// Constructor which checks that the provided length is valid.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIpv4PrefixLength::TooLong`] if the provided length is greater than
    /// [`Ipv4PrefixLen::MAX_LEN`].
    pub const fn try_new(len: u8) -> Result<Ipv4PrefixLen, InvalidIpv4PrefixLength> {
        if len > Self::MAX_LEN {
            return Err(InvalidIpv4PrefixLength::TooLong(len));
        }
        Ok(Ipv4PrefixLen(len))
    }

    /// Interpret the [`Ipv4PrefixLen`] as a `u8`
    #[must_use]
    pub const fn as_u8(&self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for Ipv4PrefixLen {
    type Error = InvalidIpv4PrefixLength;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ipv4PrefixLen::try_new(value)
    }
}

impl From<Ipv4PrefixLen> for u8 {
    fn from(value: Ipv4PrefixLen) -> Self {
        value.0
    }
}

impl From<Ipv4Addr> for Ipv4Prefix {
    fn from(value: Ipv4Addr) -> Self {
        Ipv4Prefix::new_assert(value.octets(), Ipv4PrefixLen::MAX.as_u8())
    }
}

impl Display for Ipv4PrefixLen {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for Ipv4Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<Ipv4PrefixLen> for u8 {
    fn eq(&self, other: &Ipv4PrefixLen) -> bool {
        *self == other.0
    }
}

impl PartialEq<u8> for Ipv4PrefixLen {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl Ipv4Prefix {
    /// The root [`Ipv4Prefix`], aka 0.0.0.0/0
    pub const ROOT: Ipv4Prefix = Ipv4Prefix::new_assert([0, 0, 0, 0], 0);

    /// Validating a constructor which panics if the arguments are invalid.
    /// Useful in const contexts and testing.
    ///
    /// Avoid this method outside const contexts or testing settings.
    ///
    /// # Panics
    ///
    /// * Panics if the provided prefix is greater than 32
    /// * Panics if the provided address contains non-network bits.
    #[must_use]
    pub const fn new_assert(addr: [u8; 4], prefix: u8) -> Self {
        let addr = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
        let prefix = Ipv4PrefixLen::new_assert(prefix);
        let mask = (!0u32)
            .overflowing_shl((Ipv4PrefixLen::MAX_LEN - prefix.0) as u32)
            .0;
        assert!(
            addr.to_bits() & mask == addr.to_bits(),
            "Ipv4Network address contains non network bits"
        );
        Ipv4Prefix(Ipv4Net::new_assert(addr, prefix.0))
    }

    /// Constructor which validates the arguments provided.
    ///
    /// # Errors
    ///
    /// * Returns [`InvalidIpv4Network::InvalidPrefix`] if the provided prefix length is greater
    ///   than [`Ipv4PrefixLen::MAX_LEN`].
    /// * Returns [`InvalidIpv4Network::AddressContainsNonNetworkBits`] if the provided address
    ///   contains non-network bits.
    #[tracing::instrument(level = "trace")]
    pub fn new_strict(
        addr: impl Into<Ipv4Addr> + Debug,
        prefix: impl TryInto<Ipv4PrefixLen, Error = InvalidIpv4PrefixLength> + Debug,
    ) -> Result<Ipv4Prefix, InvalidIpv4Network> {
        let addr = addr.into();
        let prefix = prefix
            .try_into()
            .map_err(InvalidIpv4Network::InvalidPrefix)?;
        if addr.to_bits()
            & (!0u32)
                .overflowing_shl(u32::from(Ipv4PrefixLen::MAX_LEN - prefix.0))
                .0
            != addr.to_bits()
        {
            return Err(InvalidIpv4Network::AddressContainsNonNetworkBits(
                addr, prefix,
            ));
        }
        Ok(Ipv4Prefix(Ipv4Net::new_assert(addr, prefix.0)))
    }

    /// Create an [`Ipv4Prefix`] even if the argument contains non-network bits.
    ///
    /// This method is useful in the cases that
    ///
    /// 1. You can't trust your routing input and still don't wish to reject the routes (ideally,
    ///    this does not happen).
    /// 2. You need to convert an interface address assignment into a route
    ///
    /// This method will log a warning if the provided address contains non-network bits.
    ///
    /// # Errors
    ///
    /// * Returns an error if the provided prefix length is greater than [`Ipv4PrefixLen::MAX_LEN`].
    #[tracing::instrument(level = "debug")]
    pub fn new_tolerant<E>(
        addr: impl Into<Ipv4Addr> + Debug,
        prefix: impl TryInto<Ipv4PrefixLen, Error = E> + Debug,
    ) -> Result<Ipv4Prefix, E> {
        let mut addr = addr.into();
        let prefix = prefix.try_into()?;
        #[allow(clippy::cast_possible_truncation)] // upper bounded to 32
        let zeros = addr.to_bits().trailing_zeros() as u8;
        if zeros < (32 - prefix.0) {
            debug!(
                addr = %addr,
                prefix = %prefix,
                "logic error: attempting to construct prefix with fewer zeros than prefix length: zeroing low bits"
            );
            let mask = (!0u32)
                .overflowing_shl(u32::from(Ipv4PrefixLen::MAX_LEN - prefix.0))
                .0;
            addr = Ipv4Addr::from_bits(addr.to_bits() & mask);
            #[allow(clippy::cast_possible_truncation)] // upper bounded to 32
            let zeros = addr.to_bits().trailing_zeros() as u8;
            debug_assert!(zeros >= (32 - prefix.0));
        }
        Ok(Ipv4Prefix(
            Ipv4Net::new(addr, prefix.0).unwrap_or_else(|_| unreachable!()),
        ))
    }

    /// Returns the address of the network.
    #[must_use]
    pub const fn address(&self) -> Ipv4Addr {
        self.0.addr()
    }

    /// Returns the prefix length of the network.
    #[must_use]
    pub const fn prefix_len(&self) -> Ipv4PrefixLen {
        Ipv4PrefixLen(self.0.prefix_len()) // checked already
    }

    /// Safe cast of [`Ipv4Prefix`] to `ipnet::Ipv4Net`
    #[must_use]
    pub const fn as_net(&self) -> Ipv4Net {
        self.0
    }

    /// Convert an [`Ipv4Net`] to an [`Ipv4Prefix`].
    ///
    /// # Safety
    ///
    /// It is undefined behavior to pass an [`Ipv4Net`] which contains set non-network bits.
    #[must_use]
    pub const fn from_net_unchecked(x: Ipv4Net) -> Self {
        Self(x)
    }
}

impl FromStr for Ipv4Prefix {
    type Err = Ipv4PrefixParseError;

    /// Attempt to parse an [`Ipv4Prefix`] from a `str`.
    ///
    /// # Errors
    ///
    /// * Returns [`Ipv4PrefixParseError::AddrParseError`] if the provided string cannot be parsed
    ///   as an [`Ipv4Addr`].
    /// * Returns [`Ipv4PrefixParseError::InvalidIpv4Network`] if the provided string can be parsed
    ///   as an ip address and a prefix, but does not form a valid [`Ipv4Prefix`] (e.g., when
    ///   non-network bits are set).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let net = Ipv4Net::from_str(s).map_err(Ipv4PrefixParseError::AddrParseError)?;
        Ipv4Prefix::new_strict(net.addr(), net.prefix_len())
            .map_err(Ipv4PrefixParseError::InvalidIpv4Network)
    }
}

/// Trait to describe containment relationships between different data types.
pub trait Contains<T> {
    /// Returns true if self "contains" other
    fn contains(&self, other: T) -> bool;
}

impl Contains<Ipv4Prefix> for Ipv4Prefix {
    fn contains(&self, other: Ipv4Prefix) -> bool {
        self.0.contains(&other.0)
    }
}

impl Contains<Ipv4Addr> for Ipv4Prefix {
    fn contains(&self, other: Ipv4Addr) -> bool {
        self.0.contains(&other)
    }
}

impl From<Ipv4Prefix> for Ipv4Net {
    fn from(value: Ipv4Prefix) -> Self {
        value.0
    }
}

impl From<Ipv4Net> for Ipv4Prefix {
    fn from(value: Ipv4Net) -> Self {
        let net_addr = Ipv4Addr::from_bits(
            value.addr().to_bits()
                & (!0u32)
                    .overflowing_shl(
                        u32::from(Ipv4PrefixLen::MAX_LEN) - u32::from(value.prefix_len()),
                    )
                    .0,
        );
        Ipv4Prefix::new_tolerant(net_addr, value.prefix_len())
            .unwrap_or_else(|e| unreachable!("{}", e))
    }
}

impl Prefix for Ipv4Prefix {
    type R = u32;

    fn repr(&self) -> Self::R {
        self.address().to_bits()
    }

    fn prefix_len(&self) -> u8 {
        self.prefix_len().0
    }

    fn from_repr_len(repr: Self::R, len: u8) -> Self {
        if len > Ipv4PrefixLen::MAX_LEN {
            debug!(
                "nonsense prefix length {len}, mapping to {MAX}",
                MAX = Ipv4PrefixLen::MAX_LEN
            );
            return Ipv4Prefix::from(Ipv4Addr::from_bits(repr));
        }
        Ipv4Prefix::new_tolerant(repr, len).unwrap_or_else(|e| unreachable!("{}", e))
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::ipv4::{Ipv4Prefix, Ipv4PrefixLen};
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use std::net::Ipv4Addr;
    use std::ops::Bound;

    impl TypeGenerator for Ipv4PrefixLen {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Ipv4PrefixLen::new_assert(driver.gen_u8(
                Bound::Included(&0),
                Bound::Included(&Ipv4PrefixLen::MAX_LEN),
            )?))
        }
    }

    impl TypeGenerator for Ipv4Prefix {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let ip: Ipv4Addr = driver.produce()?;
            let min_prefix_len = u32::from(Ipv4PrefixLen::MAX_LEN) - ip.to_bits().trailing_zeros();
            #[allow(clippy::cast_possible_truncation)] // upper bounded to 32
            let prefix_len = driver.gen_u8(
                Bound::Included(&(min_prefix_len as u8)),
                Bound::Included(&Ipv4PrefixLen::MAX_LEN),
            )?;
            Some(Ipv4Prefix::new_assert(ip.octets(), prefix_len))
        }
    }

    /// generate the largest possible network from an [`Ipv4Addr`]
    #[must_use]
    pub const fn largest_possible_network(ip: Ipv4Addr) -> Ipv4Prefix {
        #[allow(clippy::cast_possible_truncation)] // upper bounded to 32
        let prefix_len = Ipv4PrefixLen::MAX_LEN - (ip.to_bits().trailing_zeros() as u8);
        Ipv4Prefix::new_assert(ip.octets(), prefix_len)
    }

    // /// Value generator which selects an arbitrary Ipv4 Address and then computes the largest legal
    // /// [`Ipv4Prefix`] from that address.
    // pub struct LargestPossibleNetworkGenerator;
    //
    // impl LargestPossibleNetworkGenerator {
    //     /// Create a new [`LargestPossibleNetworkGenerator`]
    //     #[must_use]
    //     pub fn new<D: Driver>(driver: &mut D) -> Option<Self> {
    //         Some(Self(largest_possible_network(driver.produce()?)))
    //     }
    // }
    //
    // impl ValueGenerator for LargestPossibleNetworkGenerator {
    //     type Output = Ipv4Prefix;
    //
    //     fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
    //         Some(largest_possible_network(driver.produce()?))
    //     }
    // }

    /// Value generator which produces contained networks of the provided [`Ipv4Prefix`].
    ///
    /// All values returned by this generator are guaranteed to be `contained` by the provided
    /// network.
    pub struct ContainedNetworkGenerator(Ipv4Prefix);

    impl ContainedNetworkGenerator {
        /// Create a new [`ContainedNetworkGenerator`]
        #[must_use]
        pub const fn new(network: Ipv4Prefix) -> Self {
            Self(network)
        }
    }

    impl ValueGenerator for ContainedNetworkGenerator {
        type Output = Ipv4Prefix;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let prefix_len = self.0.prefix_len();
            if prefix_len.0 == Ipv4PrefixLen::MAX_LEN {
                return None;
            }
            let extension = driver.gen_u8(
                Bound::Excluded(&prefix_len.0),
                Bound::Included(&Ipv4PrefixLen::MAX_LEN),
            )?;
            let new_bits_to_set = driver.gen_u32(
                Bound::Included(&0),
                Bound::Excluded(&(1 << (32 - extension))),
            )? & ((!0u32).overflowing_shl(u32::from(32 - extension)).0);
            let new_bits = self.0.address().to_bits() | new_bits_to_set;
            let net_addr = Ipv4Addr::from(new_bits);
            Some(Ipv4Prefix::new_assert(net_addr.octets(), extension))
        }
    }

    /// [`ValueGenerator`] which produces two [`Ipv4Prefix`] values.  The first ensured to contain
    /// the second.
    pub struct NetworkAndSubNetworkGenerator;

    impl ValueGenerator for NetworkAndSubNetworkGenerator {
        type Output = (Ipv4Prefix, Ipv4Prefix);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let network = driver.produce()?;
            let sub_network = ContainedNetworkGenerator(network).generate(driver)?;
            Some((network, sub_network))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ipv4::{
        ContainedNetworkGenerator, Contains, InvalidIpv4Network, InvalidIpv4PrefixLength,
        Ipv4Prefix, Ipv4PrefixLen, NetworkAndSubNetworkGenerator, largest_possible_network,
    };
    use std::net::Ipv4Addr;
    use std::panic::catch_unwind;
    use std::time::Duration;

    #[test]
    #[should_panic]
    fn non_network_bits_panic_in_asserting_constructor() {
        let _ = Ipv4Prefix::new_assert([192, 168, 0, 1], 24);
    }

    #[test]
    fn prefix_logic_soundness() {
        bolero::check!().with_type().cloned().for_each(|val: u8| {
            match Ipv4PrefixLen::try_new(val) {
                Ok(prefix) => {
                    assert_eq!(prefix.0, val);
                    assert!(prefix <= Ipv4PrefixLen::MAX);
                    assert!(prefix >= Ipv4PrefixLen::MIN);
                    let _ = Ipv4PrefixLen::new_assert(val); // should never panic
                    Ipv4PrefixLen::try_from(val).unwrap();
                    assert_eq!(val, u8::from(prefix));
                    assert_eq!(format!("{prefix}"), val.to_string());
                }
                Err(InvalidIpv4PrefixLength::TooLong(err_val)) => {
                    assert_eq!(err_val, val);
                    assert!(err_val > Ipv4PrefixLen::MAX.0);
                    // must always panic
                    if catch_unwind(|| {
                        let _ = Ipv4PrefixLen::new_assert(err_val);
                    })
                    .is_ok()
                    {
                        unreachable!()
                    }
                    // must always panic
                    if catch_unwind(|| {
                        Ipv4PrefixLen::try_from(err_val).unwrap();
                    })
                    .is_ok()
                    {
                        unreachable!()
                    }
                }
            }
        });
    }

    #[test]
    fn prefix_generator_soundness() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|length: Ipv4PrefixLen| {
                assert!(length >= Ipv4PrefixLen::MIN);
                assert!(length <= Ipv4PrefixLen::MAX);
            });
    }

    #[test]
    fn non_network_bits_in_checked_constructor_returns_error() {
        let ip = Ipv4Addr::new(192, 168, 0, 1);
        let prefix = 24;
        match Ipv4Prefix::new_strict(ip, prefix) {
            Ok(_) | Err(InvalidIpv4Network::InvalidPrefix(_)) => {
                unreachable!()
            }
            Err(InvalidIpv4Network::AddressContainsNonNetworkBits(err_ip, err_prefix)) => {
                assert_eq!(err_ip, ip);
                assert_eq!(err_prefix, prefix);
            }
        }
    }

    #[test]
    fn basic_fuzz() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|network: Ipv4Prefix| {
                assert!(network.prefix_len() >= Ipv4PrefixLen::MIN);
                assert!(network.prefix_len() <= Ipv4PrefixLen::MAX);
                assert!(network.contains(network));
                assert!(network.contains(network.address()));
            });
    }

    /// Check abstract properties of network overlap
    #[test]
    fn overlap_detection() {
        bolero::check!().with_type().cloned().for_each(
            |(network1, network2): (Ipv4Prefix, Ipv4Prefix)| {
                assert!(largest_possible_network(network1.address()).contains(network1.address()));
                assert!(largest_possible_network(network2.address()).contains(network2.address()));
                if network1.contains(network2) {
                    assert_eq!(
                        network1.address().to_bits() & network2.address().to_bits(),
                        network1.address().to_bits()
                    );
                    assert!(network1.prefix_len() <= network2.prefix_len());
                    assert!(largest_possible_network(network1.address()).contains(network2));
                } else if network2.contains(network1) {
                    assert_eq!(
                        network1.address().to_bits() & network2.address().to_bits(),
                        network2.address().to_bits()
                    );
                    assert!(network2.prefix_len() <= network1.prefix_len());
                    assert!(largest_possible_network(network2.address()).contains(network1));
                } else {
                    assert_ne!(network1.address().to_bits(), network2.address().to_bits());
                }
                if network1.prefix_len() == network2.prefix_len() {
                    if network1.contains(network2) {
                        assert_eq!(network1, network2);
                        assert_eq!(network1.address(), network2.address());
                        assert!(network2.contains(network1));
                        assert!(largest_possible_network(network1.address()).contains(network2));
                    } else {
                        assert_ne!(network1, network2);
                        assert_ne!(network1.address(), network2.address());
                        assert!(!network2.contains(network1));
                    }
                }
            },
        );
    }

    #[test]
    fn address_containment() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|(net, addr): (Ipv4Prefix, Ipv4Addr)| {
                assert!(largest_possible_network(net.address()).contains(net));
                if net.contains(addr) {
                    assert_eq!(
                        net.address().to_bits() & addr.to_bits(),
                        net.address().to_bits()
                    );
                    assert!(largest_possible_network(net.address()).contains(addr));
                } else {
                    assert_ne!(net.address(), addr);
                    let min_addr = net.address().to_bits();
                    #[allow(clippy::cast_possible_truncation)] // bounded math
                    let max_addr = (u64::from(net.address().to_bits())
                        + (1u64 << (32 - net.prefix_len().0))
                        - 1) as u32;
                    assert!(addr.to_bits() < min_addr || addr.to_bits() > max_addr);
                }
            });
    }

    const TEST_PREFIXES: [Ipv4Prefix; 10] = [
        Ipv4Prefix::new_assert([0, 0, 0, 0], 0),
        Ipv4Prefix::new_assert([0, 0, 0, 0], 8),
        Ipv4Prefix::new_assert([0, 0, 0, 0], 32),
        Ipv4Prefix::new_assert([0, 0, 0, 0], 1),
        Ipv4Prefix::new_assert([0, 0, 0, 0], 31),
        Ipv4Prefix::new_assert([255, 255, 255, 255], 32),
        Ipv4Prefix::new_assert([0b1110_0000, 0, 0, 0], 4), // multicast
        Ipv4Prefix::new_assert([192, 168, 0, 0], 16),
        Ipv4Prefix::new_assert([192, 168, 10, 0], 24),
        Ipv4Prefix::new_assert([192, 168, 10, 2], 31),
    ];

    #[test]
    fn containment_logic_soundness() {
        for network in TEST_PREFIXES {
            bolero::check!()
                .with_generator(ContainedNetworkGenerator::new(network))
                .cloned()
                .for_each(|prefix: Ipv4Prefix| {
                    assert!(network.contains(prefix));
                    assert!(largest_possible_network(prefix.address()).contains(prefix));
                });
        }
    }

    #[test]
    fn contained_logic_fuzzing() {
        bolero::check!()
            .with_generator(NetworkAndSubNetworkGenerator)
            .cloned()
            .for_each(|(network, subnetwork)| {
                assert!(network.contains(subnetwork));
                assert!(largest_possible_network(network.address()).contains(subnetwork));
                if subnetwork.contains(network) {
                    assert_eq!(network, subnetwork);
                } else {
                    assert_ne!(network, subnetwork);
                }
            });
    }
}
