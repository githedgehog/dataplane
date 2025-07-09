// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::ipv4::Contains;
#[cfg(any(test, feature = "bolero"))]
#[allow(unused_imports)] // re-export
pub use contract::*;
use ipnet::{AddrParseError, Ipv6Net};
use prefix_trie::Prefix;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::net::Ipv6Addr;
use std::str::FromStr;
use tracing::{debug, warn};

/// An `Ipv6Addr` with a mask describing a network in CIDR notation.
///
/// Note that unlike [`Ipv6Net`] from the `ipnet` crate, this type ensures that only network bits
/// are set in the address.
#[derive(
    Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Ipv6Prefix(Ipv6Net);

/// A checked type describing the values 0 to 128, which constitute all legal prefix lengths for
/// Ipv6 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(try_from = "u8", into = "u8")]
pub struct Ipv6PrefixLen(u8);

/// An error indicating that an invalid prefix length was provided.
#[derive(Debug, thiserror::Error)]
#[repr(transparent)]
pub enum InvalidIpv6PrefixLength {
    /// The provided prefix is too long to form a legal [`Ipv6PrefixLen`]
    #[error("invalid prefix length {0} is invalid, max is {MAX}", MAX = Ipv6PrefixLen::MAX_LEN)]
    TooLong(u8),
}

/// An error indicating that an invalid network was provided.
#[derive(Debug, thiserror::Error)]
pub enum InvalidIpv6Network {
    /// The provided network description contains set non-network bits
    #[error("Address {0}/{1} contains non network bits")]
    AddressContainsNonNetworkBits(Ipv6Addr, Ipv6PrefixLen),
    /// The provided prefix length is invalid
    #[error(transparent)]
    InvalidPrefix(InvalidIpv6PrefixLength),
}

/// An error indicating that an invalid network was provided.
#[derive(Debug, thiserror::Error)]
pub enum Ipv6PrefixParseError {
    /// failure to interpret string as an ip and a prefix length
    #[error(transparent)]
    AddrParseError(AddrParseError),
    /// invalid ip or prefix length
    #[error(transparent)]
    InvalidIpv6Network(InvalidIpv6Network),
}

impl Ipv6PrefixLen {
    /// The longest possible prefix length for IPv6 (i.e. /128)
    pub const MAX_LEN: u8 = 128;
    /// The longest possible prefix length for IPv6 (i.e. /128)
    pub const MAX: Self = Self(Self::MAX_LEN);
    /// The minimum possible prefix length for IPv6 (i.e. /0)
    pub const MIN: Self = Self(0);

    /// Constructor which asserts if the provided length is invalid.
    /// Useful in const contexts where you are sure you won't panic.
    ///
    /// # Panics
    ///
    /// Panics if the provided length is greater than [`Ipv6PrefixLen::MAX_LEN`].
    #[must_use]
    pub const fn new_assert(len: u8) -> Self {
        assert!(len <= Self::MAX_LEN, "invalid prefix length");
        Self(len)
    }

    /// Constructor which checks that the provided length is valid.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIpv6PrefixLength::TooLong`] if the provided length is greater than
    /// [`Ipv6PrefixLen::MAX_LEN`].
    pub const fn try_new(len: u8) -> Result<Ipv6PrefixLen, InvalidIpv6PrefixLength> {
        if len > Self::MAX_LEN {
            return Err(InvalidIpv6PrefixLength::TooLong(len));
        }
        Ok(Ipv6PrefixLen(len))
    }

    /// Interpret the [`Ipv6PrefixLen`] as a `u8`
    #[must_use]
    pub const fn as_u8(&self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for Ipv6PrefixLen {
    type Error = InvalidIpv6PrefixLength;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ipv6PrefixLen::try_new(value)
    }
}

impl From<Ipv6PrefixLen> for u8 {
    fn from(value: Ipv6PrefixLen) -> Self {
        value.0
    }
}

impl From<Ipv6Addr> for Ipv6Prefix {
    fn from(value: Ipv6Addr) -> Self {
        Ipv6Prefix::new_assert(value.segments(), Ipv6PrefixLen::MAX.as_u8())
    }
}

impl Display for Ipv6PrefixLen {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for Ipv6Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<Ipv6PrefixLen> for u8 {
    fn eq(&self, other: &Ipv6PrefixLen) -> bool {
        *self == other.0
    }
}

impl PartialEq<u8> for Ipv6PrefixLen {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl Ipv6Prefix {
    /// The root [`Ipv6Prefix`], aka 0.0.0.0/0
    pub const ROOT: Ipv6Prefix = Ipv6Prefix::new_assert([0, 0, 0, 0, 0, 0, 0, 0], 0);

    /// Validating a constructor which panics if the arguments are invalid.
    /// Useful in const contexts and testing.
    ///
    /// Avoid this method outside const contexts or testing settings.
    ///
    /// # Panics
    ///
    /// * Panics if the provided prefix is greater than 128
    /// * Panics if the provided address contains non-network bits.
    #[must_use]
    pub const fn new_assert(addr: [u16; 8], prefix: u8) -> Self {
        let addr = Ipv6Addr::new(
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
        );
        let prefix = Ipv6PrefixLen::new_assert(prefix);
        let mask = (!0u128)
            .overflowing_shl((Ipv6PrefixLen::MAX_LEN - prefix.0) as u32)
            .0;
        assert!(
            addr.to_bits() & mask == addr.to_bits(),
            "Ipv6Network address contains non network bits"
        );
        Ipv6Prefix(Ipv6Net::new_assert(addr, prefix.0))
    }

    /// Constructor which validates the arguments provided.
    ///
    /// # Errors
    ///
    /// * Returns [`InvalidIpv6Network::InvalidPrefix`] if the provided prefix length is greater
    ///   than [`Ipv6PrefixLen::MAX_LEN`].
    /// * Returns [`InvalidIpv6Network::AddressContainsNonNetworkBits`] if the provided address
    ///   contains non-network bits.
    #[tracing::instrument(level = "trace")]
    pub fn new_strict(
        addr: impl Into<Ipv6Addr> + Debug,
        prefix: impl TryInto<Ipv6PrefixLen, Error = InvalidIpv6PrefixLength> + Debug,
    ) -> Result<Ipv6Prefix, InvalidIpv6Network> {
        let addr = addr.into();
        let prefix = prefix
            .try_into()
            .map_err(InvalidIpv6Network::InvalidPrefix)?;
        if addr.to_bits()
            & (!0u128)
                .overflowing_shl(u32::from(Ipv6PrefixLen::MAX_LEN - prefix.0))
                .0
            != addr.to_bits()
        {
            return Err(InvalidIpv6Network::AddressContainsNonNetworkBits(
                addr, prefix,
            ));
        }
        Ok(Ipv6Prefix(Ipv6Net::new_assert(addr, prefix.0)))
    }

    /// Create an [`Ipv6Prefix`] even if the argument contains non-network bits.
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
    /// * Returns an error if the provided prefix length is greater than [`Ipv6PrefixLen::MAX_LEN`].
    #[tracing::instrument(level = "debug")]
    pub fn new_tolerant<E>(
        addr: impl Into<Ipv6Addr> + Debug,
        prefix: impl TryInto<Ipv6PrefixLen, Error = E> + Debug,
    ) -> Result<Ipv6Prefix, E> {
        let mut addr = addr.into();
        let prefix = prefix.try_into()?;
        #[allow(clippy::cast_possible_truncation)] // upper bounded to 128
        let zeros = addr.to_bits().trailing_zeros() as u8;
        if zeros < (128 - prefix.0) {
            debug!(
                addr = %addr,
                prefix = %prefix,
                "logic error: attempting to construct prefix with fewer zeros than prefix length: zeroing low bits"
            );
            let mask = (!0u128)
                .overflowing_shl(u32::from(Ipv6PrefixLen::MAX_LEN - prefix.0))
                .0;
            addr = Ipv6Addr::from_bits(addr.to_bits() & mask);
            debug_assert!(zeros >= prefix.0);
        }
        Ok(Ipv6Prefix(
            Ipv6Net::new(addr, prefix.0).unwrap_or_else(|_| unreachable!()),
        ))
    }

    /// Returns the address of the network.
    #[must_use]
    pub const fn address(&self) -> Ipv6Addr {
        self.0.addr()
    }

    /// Returns the prefix length of the network.
    #[must_use]
    pub const fn prefix_len(&self) -> Ipv6PrefixLen {
        Ipv6PrefixLen(self.0.prefix_len()) // checked already
    }

    /// Safe cast of [`Ipv6Prefix`] to `ipnet::Ipv6Net`
    #[must_use]
    pub const fn as_net(&self) -> Ipv6Net {
        self.0
    }

    /// Convert an [`Ipv6Net`] to an [`Ipv6Prefix`].
    ///
    /// # Safety
    ///
    /// It is undefined behavior to pass an [`Ipv6Net`] which contains set non-network bits.
    #[must_use]
    pub const fn from_net_unchecked(x: Ipv6Net) -> Self {
        Self(x)
    }
}

impl FromStr for Ipv6Prefix {
    type Err = Ipv6PrefixParseError;

    /// Attempt to parse an [`Ipv6Prefix`] from a `str`.
    ///
    /// # Errors
    ///
    /// * Returns [`Ipv6PrefixParseError::AddrParseError`] if the provided string cannot be parsed
    ///   as an [`Ipv6Addr`].
    /// * Returns [`Ipv6PrefixParseError::InvalidIpv6Network`] if the provided string can be parsed
    ///   as an ip address and a prefix, but does not form a valid [`Ipv6Prefix`] (e.g., when
    ///   non-network bits are set).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let net = Ipv6Net::from_str(s).map_err(Ipv6PrefixParseError::AddrParseError)?;
        Ipv6Prefix::new_strict(net.addr(), net.prefix_len())
            .map_err(Ipv6PrefixParseError::InvalidIpv6Network)
    }
}

impl Contains<Ipv6Prefix> for Ipv6Prefix {
    fn contains(&self, other: Ipv6Prefix) -> bool {
        self.0.contains(&other.0)
    }
}

impl Contains<Ipv6Addr> for Ipv6Prefix {
    fn contains(&self, other: Ipv6Addr) -> bool {
        self.0.contains(&other)
    }
}

impl From<Ipv6Prefix> for Ipv6Net {
    fn from(value: Ipv6Prefix) -> Self {
        value.0
    }
}

impl From<Ipv6Net> for Ipv6Prefix {
    fn from(value: Ipv6Net) -> Self {
        let net_addr = Ipv6Addr::from_bits(
            value.addr().to_bits()
                & (!0u128)
                    .overflowing_shl(
                        u32::from(Ipv6PrefixLen::MAX_LEN) - u32::from(value.prefix_len()),
                    )
                    .0,
        );
        Ipv6Prefix::new_tolerant(net_addr, value.prefix_len())
            .unwrap_or_else(|e| unreachable!("{}", e))
    }
}

impl Prefix for Ipv6Prefix {
    type R = u128;

    fn repr(&self) -> Self::R {
        self.address().to_bits()
    }

    fn prefix_len(&self) -> u8 {
        self.prefix_len().0
    }

    fn from_repr_len(repr: Self::R, len: u8) -> Self {
        if len > Ipv6PrefixLen::MAX_LEN {
            debug!(
                "nonsense prefix length {len}, mapping to {MAX}",
                MAX = Ipv6PrefixLen::MAX_LEN
            );
            return Ipv6Prefix::from(Ipv6Addr::from_bits(repr));
        }
        Ipv6Prefix::new_tolerant(repr, len).unwrap_or_else(|e| unreachable!("{}", e))
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::ipv6::{Ipv6Prefix, Ipv6PrefixLen};
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use std::net::Ipv6Addr;
    use std::ops::Bound;

    impl TypeGenerator for Ipv6PrefixLen {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Ipv6PrefixLen::new_assert(driver.gen_u8(
                Bound::Included(&0),
                Bound::Included(&Ipv6PrefixLen::MAX_LEN),
            )?))
        }
    }

    impl TypeGenerator for Ipv6Prefix {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let ip: Ipv6Addr = driver.produce()?;
            let min_prefix_len = u32::from(Ipv6PrefixLen::MAX_LEN) - ip.to_bits().trailing_zeros();
            #[allow(clippy::cast_possible_truncation)] // upper bounded to 128
            let prefix_len = driver.gen_u8(
                Bound::Included(&(min_prefix_len as u8)),
                Bound::Included(&Ipv6PrefixLen::MAX_LEN),
            )?;
            Some(Ipv6Prefix::new_assert(ip.segments(), prefix_len))
        }
    }

    /// generate the largest possible network from an [`Ipv6Addr`] (i.e., the network with the
    /// shortest possible prefix such that none of the host bits in the supplied address are set).
    #[must_use]
    pub const fn largest_possible_network(ip: Ipv6Addr) -> Ipv6Prefix {
        #[allow(clippy::cast_possible_truncation)] // upper bounded to 128
        let prefix_len = Ipv6PrefixLen::MAX_LEN - (ip.to_bits().trailing_zeros() as u8);
        Ipv6Prefix::new_assert(ip.segments(), prefix_len)
    }

    /// Value generator which produces contained networks of the provided [`Ipv6Prefix`].
    ///
    /// All values returned by this generator are guaranteed to be `contained` by the provided
    /// network.
    pub struct ContainedNetworkGenerator(Ipv6Prefix);

    impl ContainedNetworkGenerator {
        /// Create a new [`ContainedNetworkGenerator`]
        #[must_use]
        pub const fn new(network: Ipv6Prefix) -> Self {
            Self(network)
        }
    }

    impl ValueGenerator for ContainedNetworkGenerator {
        type Output = Ipv6Prefix;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let prefix_len = self.0.prefix_len();
            if prefix_len.0 == Ipv6PrefixLen::MAX_LEN {
                return None;
            }
            let extension = driver.gen_u8(
                Bound::Excluded(&prefix_len.0),
                Bound::Included(&Ipv6PrefixLen::MAX_LEN),
            )?;
            let new_bits_to_set = driver.gen_u128(
                Bound::Included(&0),
                Bound::Excluded(&(1 << (128 - extension))),
            )? & ((!0u128).overflowing_shl(u32::from(128 - extension)).0);
            let new_bits = self.0.address().to_bits() | new_bits_to_set;
            let net_addr = Ipv6Addr::from(new_bits);
            Some(Ipv6Prefix::new_assert(net_addr.segments(), extension))
        }
    }

    /// [`ValueGenerator`] which produces two [`Ipv6Prefix`] values.  The first ensured to contain
    /// the second.
    pub struct NetworkAndSubNetworkGenerator;

    impl ValueGenerator for NetworkAndSubNetworkGenerator {
        type Output = (Ipv6Prefix, Ipv6Prefix);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let network = driver.produce()?;
            let sub_network = ContainedNetworkGenerator(network).generate(driver)?;
            Some((network, sub_network))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ipv4::Contains;
    use crate::ipv6::{
        ContainedNetworkGenerator, InvalidIpv6Network, InvalidIpv6PrefixLength, Ipv6Prefix,
        Ipv6PrefixLen, NetworkAndSubNetworkGenerator, largest_possible_network,
    };
    use std::net::Ipv6Addr;
    use std::panic::catch_unwind;

    #[test]
    #[should_panic]
    fn non_network_bits_panic_in_asserting_constructor() {
        let _ = Ipv6Prefix::new_assert([0xfe80, 0, 0, 0, 0, 0, 0, 1], 24);
    }

    #[test]
    fn prefix_logic_soundness() {
        bolero::check!().with_type().cloned().for_each(|val: u8| {
            match Ipv6PrefixLen::try_new(val) {
                Ok(prefix) => {
                    assert_eq!(prefix.0, val);
                    assert!(prefix <= Ipv6PrefixLen::MAX);
                    assert!(prefix >= Ipv6PrefixLen::MIN);
                    let _ = Ipv6PrefixLen::new_assert(val); // should never panic
                    Ipv6PrefixLen::try_from(val).unwrap();
                    assert_eq!(val, u8::from(prefix));
                    assert_eq!(format!("{prefix}"), val.to_string());
                }
                Err(InvalidIpv6PrefixLength::TooLong(err_val)) => {
                    assert_eq!(err_val, val);
                    assert!(err_val > Ipv6PrefixLen::MAX.0);
                    // must always panic
                    if catch_unwind(|| {
                        let _ = Ipv6PrefixLen::new_assert(err_val);
                    })
                    .is_ok()
                    {
                        unreachable!()
                    }
                    // must always panic
                    if catch_unwind(|| {
                        Ipv6PrefixLen::try_from(err_val).unwrap();
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
            .for_each(|length: Ipv6PrefixLen| {
                assert!(length >= Ipv6PrefixLen::MIN);
                assert!(length <= Ipv6PrefixLen::MAX);
            });
    }

    #[test]
    fn non_network_bits_in_checked_constructor_returns_error() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 1, 0);
        let prefix = 24;
        match Ipv6Prefix::new_strict(ip, prefix) {
            Ok(_) | Err(InvalidIpv6Network::InvalidPrefix(_)) => {
                unreachable!()
            }
            Err(InvalidIpv6Network::AddressContainsNonNetworkBits(err_ip, err_prefix)) => {
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
            .for_each(|network: Ipv6Prefix| {
                assert!(network.prefix_len() >= Ipv6PrefixLen::MIN);
                assert!(network.prefix_len() <= Ipv6PrefixLen::MAX);
                assert!(network.contains(network));
                assert!(network.contains(network.address()));
            });
    }

    /// Check abstract properties of network overlap
    #[test]
    fn overlap_detection() {
        bolero::check!().with_type().cloned().for_each(
            |(network1, network2): (Ipv6Prefix, Ipv6Prefix)| {
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
            .for_each(|(net, addr): (Ipv6Prefix, Ipv6Addr)| {
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
                    let max_addr = if net.prefix_len().0 == 0 {
                        u128::MAX
                    } else {
                        net.address().to_bits() + (1u128 << (128 - net.prefix_len().0)) - 1
                    };
                    assert!(addr.to_bits() < min_addr || addr.to_bits() > max_addr);
                }
            });
    }

    const TEST_PREFIXES: [Ipv6Prefix; 9] = [
        Ipv6Prefix::new_assert([0, 0, 0, 0, 0, 0, 0, 0], 0),
        Ipv6Prefix::new_assert([0, 0, 0, 0, 0, 0, 0, 0], 8),
        Ipv6Prefix::new_assert([0, 0, 0, 0, 0, 0, 0, 0], 32),
        Ipv6Prefix::new_assert([0, 0, 0, 0, 0, 0, 0, 0], 1),
        Ipv6Prefix::new_assert([0, 0, 0, 0, 0, 0, 0, 0], 31),
        Ipv6Prefix::new_assert(
            [
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ],
            128,
        ),
        Ipv6Prefix::new_assert([0xfe80, 0xa, 0, 0, 0, 0, 0, 0], 112),
        Ipv6Prefix::new_assert([0xfe80, 0xa, 0xb, 0, 0, 0, 0, 0], 104),
        Ipv6Prefix::new_assert([0xfe80, 0xa, 0xb, 0xc, 0, 0, 0, 0], 96),
    ];

    #[test]
    fn containment_logic_soundness() {
        for network in TEST_PREFIXES {
            bolero::check!()
                .with_generator(ContainedNetworkGenerator::new(network))
                .cloned()
                .for_each(|prefix: Ipv6Prefix| {
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
