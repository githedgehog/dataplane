// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::fmt::{Debug, Display};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::prefix::{PrefixError, PrefixSize};
use ipnet::{Ipv4Net, Ipv6Net};
use num_traits::{CheckedShr, PrimInt, Unsigned, Zero};

pub trait Representable {
    type Repr: Unsigned + PrimInt + Zero + CheckedShr;

    fn to_bits(&self) -> Self::Repr;
    fn from_bits(repr: Self::Repr) -> Self;
}

impl Representable for Ipv4Addr {
    type Repr = u32;

    fn to_bits(&self) -> Self::Repr {
        Ipv4Addr::to_bits(*self)
    }

    fn from_bits(repr: Self::Repr) -> Self {
        Ipv4Addr::from_bits(repr)
    }
}

impl Representable for Ipv6Addr {
    type Repr = u128;

    fn to_bits(&self) -> Self::Repr {
        Ipv6Addr::to_bits(*self)
    }

    fn from_bits(repr: Self::Repr) -> Self {
        Ipv6Addr::from_bits(repr)
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait IpPrefix: Debug + Clone + From<Self::Addr> + PartialEq {
    type Repr: Debug + Unsigned + PrimInt + Zero + CheckedShr;
    type Addr: Display + Debug + Clone + Eq + Representable<Repr = Self::Repr>;
    const MAX_LEN: u8;

    const ROOT: Self;

    /// # Errors
    ///
    /// Returns an error if the length is greater than `Self::MAX_LEN`
    ///
    /// # Safety
    ///
    /// It is the caller's responsibility to ensure that the prefix does not contain set host bits.
    fn new(addr: Self::Addr, len: u8) -> Result<Self, PrefixError>;

    fn network(&self) -> Self::Addr;

    fn last_address(&self) -> Self::Addr;

    fn len(&self) -> u8;

    fn size(&self) -> PrefixSize;
}

pub trait IpPrefixCovering<Other> {
    fn covers(&self, other: &Other) -> bool;
}

////////////////////////////////////////////////////////////
// IPv4 Prefix
////////////////////////////////////////////////////////////

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Ipv4Prefix(Ipv4Net);

impl Debug for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl Default for Ipv4Prefix {
    fn default() -> Self {
        Ipv4Prefix::ROOT
    }
}

impl Display for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl IpPrefix for Ipv4Prefix {
    type Repr = u32;

    type Addr = Ipv4Addr;
    const MAX_LEN: u8 = 32;

    const ROOT: Ipv4Prefix = Ipv4Prefix(match Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0) {
        Ok(root) => root,
        Err(_) => {
            panic!("unreachable")
        }
    });

    fn new(addr_in: Ipv4Addr, len: u8) -> Result<Self, PrefixError> {
        if len > Self::MAX_LEN {
            return Err(PrefixError::InvalidLength(len));
        }
        let addr = Ipv4Addr::from_bits(
            addr_in.to_bits() & u32::MAX.unbounded_shl(u32::from(Self::MAX_LEN - len)),
        );
        if addr_in != addr {
            let err = format!(
                "{addr_in}/{len} has host bits set: address in binary is {:b}, {:b} would be correct",
                addr_in.to_bits(),
                addr.to_bits()
            );
            return Err(PrefixError::Invalid(err));
        }
        Ok(Self(
            Ipv4Net::new(addr, len).map_err(|e| PrefixError::Invalid(e.to_string()))?,
        ))
    }

    fn network(&self) -> Self::Addr {
        self.0.network()
    }
    fn last_address(&self) -> Self::Addr {
        self.0.broadcast()
    }
    fn len(&self) -> u8 {
        self.0.prefix_len()
    }
    fn size(&self) -> PrefixSize {
        PrefixSize::U128(2u128.pow(32 - u32::from(self.len())))
    }
}

impl IpPrefixCovering<Ipv4Addr> for Ipv4Prefix {
    fn covers(&self, other: &Ipv4Addr) -> bool {
        self.0.contains(other)
    }
}

impl IpPrefixCovering<Ipv4Prefix> for Ipv4Prefix {
    fn covers(&self, other: &Ipv4Prefix) -> bool {
        self.0.contains(&other.0)
    }
}

impl From<Ipv4Addr> for Ipv4Prefix {
    fn from(addr: Ipv4Addr) -> Self {
        Self::new(addr, Self::MAX_LEN).unwrap()
    }
}

impl From<Ipv4Net> for Ipv4Prefix {
    /// Convert an [`Ipv4Net`] into an [`Ipv4Prefix`].
    ///
    /// This conversion will zero any host bits set in the address as they make no sense in the
    /// context of a prefix.
    fn from(value: Ipv4Net) -> Self {
        let addr = Ipv4Addr::from_bits(
            value.network().to_bits()
                & u32::MAX.unbounded_shl(u32::from(Self::MAX_LEN - value.prefix_len())),
        );
        Ipv4Prefix(Ipv4Net::new_assert(addr, value.prefix_len()))
    }
}

impl FromStr for Ipv4Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s
            .split_once('/')
            .ok_or(PrefixError::Invalid(s.to_string()))?;
        let addr = addr
            .parse::<Ipv4Addr>()
            .map_err(|_| PrefixError::Invalid(s.to_string()))?;
        let len = len
            .parse::<u8>()
            .map_err(|_| PrefixError::Invalid(s.to_string()))?;
        Self::new(addr, len)
    }
}

////////////////////////////////////////////////////////////
// IPv6 Prefix
////////////////////////////////////////////////////////////

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Ipv6Prefix(Ipv6Net);

impl Debug for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl Default for Ipv6Prefix {
    fn default() -> Self {
        Ipv6Prefix::ROOT
    }
}

impl Display for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl IpPrefix for Ipv6Prefix {
    type Repr = u128;
    type Addr = Ipv6Addr;
    const MAX_LEN: u8 = 128;

    const ROOT: Ipv6Prefix = Ipv6Prefix(
        match Ipv6Net::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0) {
            Ok(root) => root,
            Err(_) => {
                panic!("unreachable")
            }
        },
    );

    fn new(addr: Ipv6Addr, len: u8) -> Result<Self, PrefixError> {
        if len > Self::MAX_LEN {
            return Err(PrefixError::InvalidLength(len));
        }
        let addr_fixed = Ipv6Addr::from_bits(
            addr.to_bits() & u128::MAX.unbounded_shl(u32::from(Self::MAX_LEN - len)),
        );
        if addr_fixed != addr {
            let err = format!(
                "{addr}/{len} has host bits set: address in binary is {:128b}, {:128b} would be correct for prefix length {len}",
                addr.to_bits(),
                addr_fixed.to_bits()
            );
            return Err(PrefixError::Invalid(err));
        }
        Ok(Self(
            Ipv6Net::new(addr_fixed, len).map_err(|e| PrefixError::Invalid(e.to_string()))?,
        ))
    }
    fn network(&self) -> Self::Addr {
        self.0.network()
    }
    fn last_address(&self) -> Self::Addr {
        self.0.broadcast()
    }
    fn len(&self) -> u8 {
        self.0.prefix_len()
    }
    fn size(&self) -> PrefixSize {
        if self.len() == 0 {
            PrefixSize::Ipv6MaxAddrs
        } else {
            PrefixSize::U128(2u128.pow(128 - u32::from(self.len())))
        }
    }
}

impl IpPrefixCovering<Ipv6Addr> for Ipv6Prefix {
    fn covers(&self, other: &Ipv6Addr) -> bool {
        self.0.contains(other)
    }
}

impl IpPrefixCovering<Ipv6Prefix> for Ipv6Prefix {
    fn covers(&self, other: &Ipv6Prefix) -> bool {
        self.0.contains(&other.0)
    }
}

impl From<Ipv6Addr> for Ipv6Prefix {
    fn from(addr: Ipv6Addr) -> Self {
        Self::new(addr, Self::MAX_LEN).unwrap()
    }
}

impl From<Ipv6Net> for Ipv6Prefix {
    /// Convert an [`Ipv6Net`] into an [`Ipv6Prefix`].
    ///
    /// This conversion will zero any host bits set in the address as they make no sense in the
    /// context of a prefix.
    fn from(value: Ipv6Net) -> Self {
        let addr = Ipv6Addr::from_bits(
            value.network().to_bits()
                & u128::MAX.unbounded_shl(u32::from(Self::MAX_LEN - value.prefix_len())),
        );
        Ipv6Prefix(Ipv6Net::new_assert(addr, value.prefix_len()))
    }
}

impl FromStr for Ipv6Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s
            .split_once('/')
            .ok_or(PrefixError::Invalid(s.to_string()))?;
        let addr = addr
            .parse::<Ipv6Addr>()
            .map_err(|_| PrefixError::Invalid(s.to_string()))?;
        let len = len
            .parse::<u8>()
            .map_err(|_| PrefixError::Invalid(s.to_string()))?;

        Self::new(addr, len)
    }
}

#[cfg(any(test, feature = "testing"))]
mod contract {
    use crate::prefix::{IpPrefix, Ipv4Prefix, Ipv6Prefix, Prefix};
    use bolero::{Driver, TypeGenerator};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ops::Bound;

    impl TypeGenerator for Ipv4Prefix {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let addr = Ipv4Addr::from_bits(driver.produce()?);
            let len = Ipv4Prefix::MAX_LEN
                - driver.gen_u8(
                    Bound::Included(&0),
                    Bound::Included(
                        &u8::try_from(addr.to_bits().trailing_zeros())
                            .unwrap_or_else(|_| unreachable!()),
                    ),
                )?;
            Some(Ipv4Prefix::new(addr, len).unwrap_or_else(|_| unreachable!()))
        }
    }

    impl TypeGenerator for Ipv6Prefix {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let addr = Ipv6Addr::from_bits(driver.produce()?);
            let len = Ipv6Prefix::MAX_LEN
                - driver.gen_u8(
                    Bound::Included(&0),
                    Bound::Included(
                        &u8::try_from(addr.to_bits().trailing_zeros())
                            .unwrap_or_else(|_| unreachable!()),
                    ),
                )?;
            Some(Ipv6Prefix::new(addr, len).unwrap_or_else(|_| unreachable!()))
        }
    }

    impl TypeGenerator for Prefix {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(if driver.gen_bool(None)? {
                Prefix::IPV4(driver.produce()?)
            } else {
                Prefix::IPV6(driver.produce()?)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Bounded;

    #[test]
    fn test_ipv4_prefix_from_str() {
        let prefix = "192.168.1.0/24".parse::<Ipv4Prefix>().unwrap();
        assert_eq!(prefix.network(), Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_ipv4_covers() {
        // IP Address is covered by prefix
        let prefix = "192.168.1.0/24".parse::<Ipv4Prefix>().unwrap();
        assert!(prefix.covers(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!prefix.covers(&Ipv4Addr::new(192, 168, 2, 1)));

        // Prefix is covered by prefix
        assert!(prefix.covers(&prefix));
        assert!(prefix.covers(&Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 25).unwrap()));
        assert!(!prefix.covers(&Ipv4Prefix::new(Ipv4Addr::new(192, 168, 4, 0), 23).unwrap()));

        // Big prefix covers small prefix
        let big_prefix = "128.0.0.0/1".parse::<Ipv4Prefix>().unwrap();
        assert!(big_prefix.covers(&prefix));
        assert!(!prefix.covers(&big_prefix));

        // Prefixes with same length but different network are not covered
        let p1 = "192.168.1.0/24".parse::<Ipv4Prefix>().unwrap();
        let p2 = "192.168.2.0/24".parse::<Ipv4Prefix>().unwrap();
        assert!(!p1.covers(&p2));
        assert!(!p2.covers(&p1));
    }

    #[test]
    fn test_ipv6_prefix_from_str() {
        let prefix = "2001:db8::/32".parse::<Ipv6Prefix>().unwrap();
        assert_eq!(
            prefix.network(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn test_ipv6_covers() {
        // IP Address is covered by prefix
        let prefix = "2001:db8::/32".parse::<Ipv6Prefix>().unwrap();
        assert!(prefix.covers(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert!(prefix.covers(&Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 0)));
        assert!(!prefix.covers(&Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0)));

        // Prefix is covered by prefix
        assert!(prefix.covers(&prefix));
        assert!(
            prefix.covers(
                &Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 48).unwrap()
            )
        );
        assert!(
            !prefix.covers(
                &Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 31).unwrap()
            )
        );

        // Big prefix covers small prefix
        let big_prefix = "::/2".parse::<Ipv6Prefix>().unwrap();
        assert!(big_prefix.covers(&prefix));
        assert!(!prefix.covers(&big_prefix));

        // Prefixes with same length but different network are not covered
        let p1 = "2001:db8::/32".parse::<Ipv6Prefix>().unwrap();
        let p2 = "2001:db9::/32".parse::<Ipv6Prefix>().unwrap();
        assert!(!p1.covers(&p2));
        assert!(!p2.covers(&p1));
    }

    fn prefix_contract<P: IpPrefix + IpPrefixCovering<P>>(prefix: &P) {
        assert!(P::ROOT.covers(prefix));
        let len = prefix.len();
        if len > 0 {
            assert!(!prefix.covers(&P::ROOT));
        }
        assert_eq!(P::new(prefix.network(), prefix.len()).unwrap(), *prefix);
        assert!(len <= P::MAX_LEN);
        let host_prefix = (len..=P::MAX_LEN)
            .map(|len| P::new(prefix.network(), len).unwrap())
            .fold(prefix.clone(), |parent, child| {
                assert!(parent.covers(&parent));
                assert!(parent.covers(&child));
                assert!(child.covers(&child));
                if parent.len() < child.len() {
                    assert!(!child.covers(&parent));
                } else {
                    assert!(child.covers(&parent));
                }
                child
            });
        assert_eq!(host_prefix.len(), P::MAX_LEN);
        let root_prefix = (0..=len)
            .rev()
            .map(|len| {
                let mask = if len == 0 {
                    <P as IpPrefix>::Repr::min_value()
                } else {
                    <P as IpPrefix>::Repr::max_value().unsigned_shl(u32::from(P::MAX_LEN - len))
                };
                let parent = P::Addr::from_bits(prefix.network().to_bits() & mask);
                P::new(parent, len).unwrap()
            })
            .fold(prefix.clone(), |child, parent| {
                assert!(parent.covers(&parent));
                assert!(parent.covers(&child));
                assert!(child.covers(&child));
                if parent.len() < child.len() {
                    assert!(!child.covers(&parent));
                } else {
                    assert!(child.covers(&parent));
                }
                parent
            });
        assert_eq!(root_prefix, P::ROOT);
    }

    #[test]
    fn ipv4_prefix_contract() {
        bolero::check!()
            .with_type::<Ipv4Prefix>()
            .for_each(prefix_contract);
    }

    #[test]
    fn ipv6_prefix_contract() {
        bolero::check!()
            .with_type::<Ipv4Prefix>()
            .for_each(prefix_contract);
    }
}
