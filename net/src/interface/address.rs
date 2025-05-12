// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(private_bounds)]

use derive_builder::Builder;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Sealed trait which describes Ipv4 and Ipv6 address types
trait GenericIpAddr: Into<IpAddr> + Copy {
    const MAX_PREFIX_LENGTH: u8;
}

impl GenericIpAddr for Ipv4Addr {
    const MAX_PREFIX_LENGTH: u8 = 32;
}
impl GenericIpAddr for Ipv6Addr {
    const MAX_PREFIX_LENGTH: u8 = 128;
}

impl<Ip: GenericIpAddr> InterfaceAddress<Ip> {
    pub fn ip(&self) -> Ip {
        self.ip
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

#[derive(Debug, Clone, Builder, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct InterfaceAddress<Ip: GenericIpAddr> {
    ip: Ip,
    prefix: u8,
}

#[derive(thiserror::Error, Debug)]
pub enum InterfaceAddressError<Ip: GenericIpAddr> {
    #[error("Invalid prefix for address {ip}: {invalid_prefix} too large")]
    InvalidPrefix { ip: Ip, invalid_prefix: u8 },
    #[error("Multicast addresses can not be assigned to interfaces: {ip} is multicast")]
    MulticastIp { ip: Ip, prefix: u8 },
}

impl<Ip> TryFrom<(Ip, u8)> for InterfaceAddress<Ip>
where
    Ip: GenericIpAddr,
{
    type Error = InterfaceAddressError<Ip>;

    fn try_from((ip, prefix): (Ip, u8)) -> Result<InterfaceAddress<Ip>, Self::Error> {
        if prefix > Ip::MAX_PREFIX_LENGTH {
            return Err(InterfaceAddressError::InvalidPrefix {
                ip,
                invalid_prefix: prefix,
            });
        }
        if ip.into().is_multicast() {
            return Err(InterfaceAddressError::MulticastIp { ip, prefix });
        }
        Ok(InterfaceAddress { ip, prefix })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use super::GenericIpAddr;
    use super::InterfaceAddress;
    use crate::ipv4::UnicastIpv4Addr;
    use crate::ipv6::UnicastIpv6Addr;
    use bolero::{Driver, TypeGenerator};
    use std::net::{Ipv4Addr, Ipv6Addr};

    impl TypeGenerator for InterfaceAddress<Ipv4Addr> {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let ip: UnicastIpv4Addr = driver.produce()?;
            let prefix = driver.produce::<u8>()? & (Ipv4Addr::MAX_PREFIX_LENGTH - 1);
            Some(Self {
                ip: ip.inner(),
                prefix,
            })
        }
    }

    impl TypeGenerator for InterfaceAddress<Ipv6Addr> {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let ip: UnicastIpv6Addr = driver.produce()?;
            let prefix = driver.produce::<u8>()? & (Ipv6Addr::MAX_PREFIX_LENGTH - 1);
            Some(Self {
                ip: ip.inner(),
                prefix,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GenericIpAddr;
    use super::InterfaceAddress;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_assignment_adheres_to_contract() {
        bolero::check!()
            .with_type()
            .for_each(|ifaddr: &InterfaceAddress<Ipv4Addr>| {
                assert!(!ifaddr.ip().is_multicast());
                assert!(ifaddr.prefix <= Ipv4Addr::MAX_PREFIX_LENGTH);
            });
    }

    #[test]
    fn ipv6_assignment_adheres_to_contract() {
        bolero::check!()
            .with_type()
            .for_each(|ifaddr: &InterfaceAddress<Ipv6Addr>| {
                assert!(!ifaddr.ip().is_multicast());
                assert!(ifaddr.prefix <= Ipv6Addr::MAX_PREFIX_LENGTH);
            });
    }
}
