// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::ipv4::{
    Contains, InvalidIpv4Network, InvalidIpv4PrefixLength, Ipv4Prefix, Ipv4PrefixLen,
    Ipv4PrefixParseError,
};
use crate::ipv6::{
    InvalidIpv6Network, InvalidIpv6PrefixLength, Ipv6Prefix, Ipv6PrefixLen, Ipv6PrefixParseError,
};
use ipnet::{IpNet, Ipv4Net};
use prefix_trie::Prefix;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

/// An `IpAddr` with a mask describing a network in CIDR notation.
///
/// Note that unlike [`IpNet`] from the `ipnet` crate, this type ensures that only network bits
/// are set in the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IpPrefix {
    /// An IPv4 prefix
    V4(Ipv4Prefix),
    /// An IPv6 prefix
    V6(Ipv6Prefix),
}
impl From<IpAddr> for IpPrefix {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(addr) => IpPrefix::V4(Ipv4Prefix::from(addr)),
            IpAddr::V6(addr) => IpPrefix::V6(Ipv6Prefix::from(addr)),
        }
    }
}

/// A checked type describing possible lengths of ip prefixes
pub enum IpPrefixLen {
    /// A valid ipv4 prefix length
    V4(Ipv4PrefixLen),
    /// A valid ipv6 prefix length
    V6(Ipv6PrefixLen),
}

/// Errors which may occur when evaluating the length of ip prefixes.
#[derive(Debug, thiserror::Error)]
pub enum InvalidIpPrefixLength {
    /// Prefix length too long for ipv4
    #[error(transparent)]
    InvalidIpv4PrefixLength(#[from] InvalidIpv4PrefixLength),
    /// Prefix length too long for ipv6
    #[error(transparent)]
    InvalidIpv6PrefixLength(#[from] InvalidIpv6PrefixLength),
}

/// An error indicating that an invalid network was provided.
#[derive(Debug, thiserror::Error)]
pub enum InvalidIpNetwork {
    /// An invalid Ipv4 network
    #[error(transparent)]
    InvalidIpv4Network(#[from] InvalidIpv4Network),
    /// An invalid Ipv6 network
    #[error(transparent)]
    InvalidIpv6Network(#[from] InvalidIpv6Network),
}

/// An error indicating that an invalid network was provided.
#[derive(Debug, thiserror::Error)]
pub enum IpPrefixParseError {
    /// A failed attempt to parse an ipv4 prefix
    #[error(transparent)]
    V4(#[from] Ipv4PrefixParseError),
    /// A failed attempt to parse an ipv6 prefix
    #[error(transparent)]
    V6(#[from] Ipv6PrefixParseError),
    /// Failed to parse input as ipv4 or ipv6 prefix
    #[error("failed to parse input '{0}' as ipv4 or ipv6 prefix")]
    ParseFailure(String),
}

impl Display for IpPrefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            IpPrefix::V4(p) => write!(f, "{p}"),
            IpPrefix::V6(p) => write!(f, "{p}"),
        }
    }
}

impl From<Ipv4PrefixLen> for IpPrefixLen {
    fn from(value: Ipv4PrefixLen) -> Self {
        IpPrefixLen::V4(value)
    }
}

impl From<Ipv6PrefixLen> for IpPrefixLen {
    fn from(value: Ipv6PrefixLen) -> Self {
        IpPrefixLen::V6(value)
    }
}

impl From<Ipv4Prefix> for IpPrefix {
    fn from(value: Ipv4Prefix) -> Self {
        IpPrefix::V4(value)
    }
}

impl From<Ipv6Prefix> for IpPrefix {
    fn from(value: Ipv6Prefix) -> Self {
        IpPrefix::V6(value)
    }
}

impl IpPrefix {
    /// Constructor which validates the arguments provided.
    ///
    /// # Errors
    ///
    /// * Returns [`InvalidIpNetwork`] if the provided prefix length is greater
    ///   than the max length for the Ipv4/Ipv6 address supplied or non-network bits are set
    ///   in the supplied address.
    #[tracing::instrument(level = "trace")]
    pub fn new_strict(
        addr: impl Into<IpAddr> + Debug,
        prefix: impl Into<u8> + Debug,
    ) -> Result<IpPrefix, InvalidIpNetwork> {
        let addr = addr.into();
        match addr {
            IpAddr::V4(addr) => match Ipv4Prefix::new_strict(addr, prefix.into()) {
                Ok(prefix) => Ok(IpPrefix::V4(prefix)),
                Err(err) => Err(err.into()),
            },
            IpAddr::V6(addr) => match Ipv6Prefix::new_strict(addr, prefix.into()) {
                Ok(prefix) => Ok(IpPrefix::V6(prefix)),
                Err(err) => Err(err.into()),
            },
        }
    }

    /// Create an [`IpPrefix`] even if the argument contains non-network bits.
    ///
    /// This method is useful in the cases that
    ///
    /// 1. You can't trust your routing input and still don't wish to reject the routes (ideally,
    ///    this does not happen).
    /// 2. You need to convert an interface address assignment into a route
    ///
    /// This method will log (at debug level) if the provided address contains non-network bits.
    ///
    /// # Errors
    ///
    /// * Returns an error if the provided prefix length is greater than [`Ipv4PrefixLen::MAX_LEN`].
    #[tracing::instrument(level = "trace")]
    pub fn new_tolerant(
        addr: impl Into<IpAddr> + Debug,
        prefix: impl Into<u8> + Debug,
    ) -> Result<IpPrefix, InvalidIpPrefixLength> {
        let addr = addr.into();
        match addr {
            IpAddr::V4(addr) => match Ipv4Prefix::new_tolerant(addr, prefix.into()) {
                Ok(prefix) => Ok(IpPrefix::V4(prefix)),
                Err(err) => Err(err.into()),
            },
            IpAddr::V6(addr) => match Ipv6Prefix::new_tolerant(addr, prefix.into()) {
                Ok(prefix) => Ok(IpPrefix::V6(prefix)),
                Err(err) => Err(err.into()),
            },
        }
    }

    /// Returns the address of the network.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        match self {
            IpPrefix::V4(p) => IpAddr::V4(p.address()),
            IpPrefix::V6(p) => IpAddr::V6(p.address()),
        }
    }

    /// Returns the prefix length of the network.
    #[must_use]
    pub const fn prefix_len(&self) -> IpPrefixLen {
        match self {
            IpPrefix::V4(x) => IpPrefixLen::V4(x.prefix_len()),
            IpPrefix::V6(x) => IpPrefixLen::V6(x.prefix_len()),
        }
    }

    /// Safe cast of [`IpPrefix`] to `ipnet::IpNet`
    #[must_use]
    pub const fn as_net(&self) -> IpNet {
        match self {
            IpPrefix::V4(x) => IpNet::V4(x.as_net()),
            IpPrefix::V6(x) => IpNet::V6(x.as_net()),
        }
    }

    /// Convert an [`Ipv4Net`] to an [`Ipv4Prefix`].
    ///
    /// # Safety
    ///
    /// It is undefined behavior to pass an [`Ipv4Net`] which contains set non-network bits.
    #[must_use]
    pub const fn from_net_unchecked(x: IpNet) -> Self {
        match x {
            IpNet::V4(x) => IpPrefix::V4(Ipv4Prefix::from_net_unchecked(x)),
            IpNet::V6(x) => IpPrefix::V6(Ipv6Prefix::from_net_unchecked(x)),
        }
    }
}

impl FromStr for IpPrefix {
    type Err = IpPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match IpNet::from_str(s) {
            Ok(IpNet::V4(_)) => Ipv4Prefix::from_str(s)
                .map(IpPrefix::V4)
                .map_err(IpPrefixParseError::V4),
            Ok(IpNet::V6(_)) => Ipv6Prefix::from_str(s)
                .map(IpPrefix::V6)
                .map_err(IpPrefixParseError::V6),
            Err(_) => Err(IpPrefixParseError::ParseFailure(s.to_string()))?,
        }
    }
}

impl Contains<IpPrefix> for IpPrefix {
    fn contains(&self, other: IpPrefix) -> bool {
        match (self, other) {
            (IpPrefix::V4(x), IpPrefix::V4(y)) => Contains::contains(x, y),
            (IpPrefix::V6(x), IpPrefix::V6(y)) => Contains::contains(x, y),
            _ => false,
        }
    }
}

impl Contains<IpAddr> for IpPrefix {
    fn contains(&self, other: IpAddr) -> bool {
        match (self, other) {
            (IpPrefix::V4(x), IpAddr::V4(y)) => Contains::contains(x, y),
            (IpPrefix::V6(x), IpAddr::V6(y)) => Contains::contains(x, y),
            _ => false,
        }
    }
}

impl From<IpPrefix> for IpNet {
    fn from(value: IpPrefix) -> Self {
        match value {
            IpPrefix::V4(p) => IpNet::V4(p.into()),
            IpPrefix::V6(p) => IpNet::V6(p.into()),
        }
    }
}

impl From<IpNet> for IpPrefix {
    fn from(value: IpNet) -> Self {
        match value {
            IpNet::V4(p) => IpPrefix::V4(p.into()),
            IpNet::V6(p) => IpPrefix::V6(p.into()),
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::ip::prefix::{IpPrefix, IpPrefixLen};
    use crate::{ipv4, ipv6};
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use std::net::IpAddr;

    impl TypeGenerator for IpPrefixLen {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(if driver.gen_bool(Some(0.5))? {
                IpPrefixLen::V4(driver.produce()?)
            } else {
                IpPrefixLen::V6(driver.produce()?)
            })
        }
    }

    impl TypeGenerator for IpPrefix {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(if driver.gen_bool(Some(0.5))? {
                IpPrefix::V4(driver.produce()?)
            } else {
                IpPrefix::V6(driver.produce()?)
            })
        }
    }

    pub const fn largest_possible_network(ip: IpAddr) -> IpPrefix {
        match ip {
            IpAddr::V4(addr) => IpPrefix::V4(ipv4::largest_possible_network(addr)),
            IpAddr::V6(addr) => IpPrefix::V6(ipv6::largest_possible_network(addr)),
        }
    }

    pub struct ContainedNetworkGenerator(IpPrefix);

    impl ContainedNetworkGenerator {
        /// Create a new [`ContainedNetworkGenerator`]
        #[must_use]
        pub const fn new(network: IpPrefix) -> Self {
            Self(network)
        }
    }

    impl ValueGenerator for ContainedNetworkGenerator {
        type Output = IpPrefix;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            Some(match self.0 {
                IpPrefix::V4(ip) => {
                    IpPrefix::V4(ipv4::ContainedNetworkGenerator::new(ip).generate(driver)?)
                }
                IpPrefix::V6(ip) => {
                    IpPrefix::V6(ipv6::ContainedNetworkGenerator::new(ip).generate(driver)?)
                }
            })
        }
    }

    pub struct NetworkAndSubNetworkGenerator;

    impl ValueGenerator for NetworkAndSubNetworkGenerator {
        type Output = (IpPrefix, IpPrefix);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            Some(if driver.gen_bool(Some(0.5))? {
                let (parent, child) = ipv4::NetworkAndSubNetworkGenerator.generate(driver)?;
                (IpPrefix::V4(parent), IpPrefix::V4(child))
            } else {
                let (parent, child) = ipv6::NetworkAndSubNetworkGenerator.generate(driver)?;
                (IpPrefix::V6(parent), IpPrefix::V6(child))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ip::prefix::{InvalidIpNetwork, IpPrefix, IpPrefixLen};
    use crate::ipv4::{
        ContainedNetworkGenerator, Contains, InvalidIpv4Network, InvalidIpv4PrefixLength,
        Ipv4Prefix, Ipv4PrefixLen, NetworkAndSubNetworkGenerator, largest_possible_network,
    };
    use crate::ipv6::{InvalidIpv6Network, Ipv6PrefixLen};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::panic::catch_unwind;

    #[test]
    fn non_network_bits_in_checked_ipv4_constructor_returns_error() {
        let ip = Ipv4Addr::new(192, 168, 0, 1);
        let prefix = 24;
        match IpPrefix::new_strict(ip, prefix) {
            Ok(_)
            | Err(
                InvalidIpNetwork::InvalidIpv6Network(_)
                | InvalidIpNetwork::InvalidIpv4Network(InvalidIpv4Network::InvalidPrefix(_)),
            ) => {
                unreachable!()
            }
            Err(InvalidIpNetwork::InvalidIpv4Network(
                InvalidIpv4Network::AddressContainsNonNetworkBits(err_ip, err_prefix),
            )) => {
                assert_eq!(err_ip, ip);
                assert_eq!(err_prefix, prefix);
            }
        }
    }

    #[test]
    fn non_network_bits_in_checked_ipv6_constructor_returns_error() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let prefix = 127;
        match IpPrefix::new_strict(ip, prefix) {
            Ok(_)
            | Err(
                InvalidIpNetwork::InvalidIpv4Network(_)
                | InvalidIpNetwork::InvalidIpv6Network(InvalidIpv6Network::InvalidPrefix(_)),
            ) => {
                unreachable!()
            }
            Err(InvalidIpNetwork::InvalidIpv6Network(
                InvalidIpv6Network::AddressContainsNonNetworkBits(err_ip, err_prefix),
            )) => {
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
            .for_each(|network: IpPrefix| {
                match network.prefix_len() {
                    IpPrefixLen::V4(prefix) => {
                        assert!(prefix >= Ipv4PrefixLen::MIN);
                        assert!(prefix <= Ipv4PrefixLen::MAX);
                    }
                    IpPrefixLen::V6(prefix) => {
                        assert!(prefix >= Ipv6PrefixLen::MIN);
                        assert!(prefix <= Ipv6PrefixLen::MAX);
                    }
                }
                assert!(network.contains(network));
                assert!(network.contains(network.address()));
            });
    }

    #[test]
    fn contained_logic_fuzzing() {
        bolero::check!()
            .with_generator(super::contract::NetworkAndSubNetworkGenerator)
            .cloned()
            .for_each(|(network, subnetwork)| {
                assert!(network.contains(subnetwork));
                assert!(
                    super::contract::largest_possible_network(network.address())
                        .contains(subnetwork)
                );
                if subnetwork.contains(network) {
                    assert_eq!(network, subnetwork);
                } else {
                    assert_ne!(network, subnetwork);
                }
            });
    }
}
