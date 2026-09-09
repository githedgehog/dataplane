// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fixed_size::FixedSize;

use crate::ipv4::UnicastIpv4Addr;
use crate::ipv6::UnicastIpv6Addr;

mod private {
    use crate::ipv4::UnicastIpv4Addr;
    use crate::ipv6::UnicastIpv6Addr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub trait Sealed {}
    impl Sealed for Ipv4Addr {}
    impl Sealed for Ipv6Addr {}
    impl Sealed for UnicastIpv4Addr {}
    impl Sealed for UnicastIpv6Addr {}
}

/// One IP address type, of one version, at one level of narrowing.
///
/// Sealed over exactly four types -- `Ipv4Addr`, `Ipv6Addr` and their unicast narrowings -- so
/// that code can be generic over "an address" without becoming generic over "anything with
/// address-shaped methods". A caller that is generic over `I: IpAddress` cannot mix versions,
/// which is the property most of the uses here rely on.
pub trait IpAddress:
    private::Sealed
    + FixedSize
    + Sized
    + Debug
    + Display
    + Copy
    + Eq
    + Ord
    + Hash
    + Send
    + Sync
    + 'static
{
    /// The unicast narrowing of this type, which is itself for a type already narrowed.
    ///
    /// The `Unicast = Self::Unicast` bound is what makes narrowing idempotent:
    /// `Unicast<Unicast<Ipv4Addr>>` is `UnicastIpv4Addr`, not a second wrapper, and the
    /// `assert_type_eq_all!` below is a compile-time check that it stays that way. `Into<Self>`
    /// is the relaxing direction, so a narrowed address can always be handed back to code that
    /// wants the wide type.
    type Unicast: IpAddress<Unicast = Self::Unicast> + Into<Self>;

    /// Width of the address in bits: 32 for IPv4, 128 for IPv6.
    ///
    /// Derived from `FixedSize::SIZE` rather than written per implementation, so it cannot
    /// disagree with the wire size the same type serialises to. A hand-written constant is one
    /// edit away from a prefix length that means something different from the bytes on the wire.
    #[allow(clippy::cast_possible_truncation)]
    const BITS: u8 = const { (<Self as FixedSize>::SIZE * 8) as u8 };

    /// Widen to the standard-library enum, keeping the version.
    fn to_ip_addr(self) -> IpAddr;

    /// # Errors
    ///
    /// Returns the address unchanged if it is not of this type's IP version.
    fn try_from_addr(addr: IpAddr) -> Result<Self, IpAddr>;

    /// The address as an integer, zero-extended to 128 bits.
    ///
    /// Only meaningful alongside the version it came from: `0.0.0.1` and `::1` both produce `1`.
    /// Every caller today is generic over a single `I: IpAddress` and so cannot mix them, but a
    /// bit pattern that has been separated from its type is no longer an address.
    fn to_addr_bits(self) -> u128;

    /// # Errors
    ///
    /// Returns the bits unchanged if they do not fit this type's address width.
    fn try_from_bits(bits: u128) -> Result<Self, u128>;
}

/// The unicast narrowing of `Ip`. See [`IpAddress::Unicast`].
pub type Unicast<Ip> = <Ip as IpAddress>::Unicast;

impl IpAddress for Ipv4Addr {
    type Unicast = UnicastIpv4Addr;

    fn to_ip_addr(self) -> IpAddr {
        IpAddr::V4(self)
    }

    fn try_from_addr(addr: IpAddr) -> Result<Self, IpAddr> {
        match addr {
            IpAddr::V4(addr) => Ok(addr),
            IpAddr::V6(_) => Err(addr),
        }
    }

    fn to_addr_bits(self) -> u128 {
        u128::from(self.to_bits())
    }

    fn try_from_bits(bits: u128) -> Result<Self, u128> {
        u32::try_from(bits).map(Self::from).map_err(|_| bits)
    }
}

impl IpAddress for Ipv6Addr {
    type Unicast = UnicastIpv6Addr;

    fn to_ip_addr(self) -> IpAddr {
        IpAddr::V6(self)
    }

    fn try_from_addr(addr: IpAddr) -> Result<Self, IpAddr> {
        match addr {
            IpAddr::V6(addr) => Ok(addr),
            IpAddr::V4(_) => Err(addr),
        }
    }

    fn to_addr_bits(self) -> u128 {
        self.to_bits()
    }

    fn try_from_bits(bits: u128) -> Result<Self, u128> {
        Ok(Self::from(bits))
    }
}

impl IpAddress for UnicastIpv4Addr {
    type Unicast = Self;

    fn to_ip_addr(self) -> IpAddr {
        IpAddr::V4(self.inner())
    }

    fn try_from_addr(addr: IpAddr) -> Result<Self, IpAddr> {
        Self::try_from(Ipv4Addr::try_from_addr(addr)?).map_err(IpAddr::V4)
    }

    fn to_addr_bits(self) -> u128 {
        self.inner().to_addr_bits()
    }

    fn try_from_bits(bits: u128) -> Result<Self, u128> {
        Self::try_from(Ipv4Addr::try_from_bits(bits)?).map_err(|_| bits)
    }
}

impl IpAddress for UnicastIpv6Addr {
    type Unicast = Self;

    fn to_ip_addr(self) -> IpAddr {
        IpAddr::V6(self.inner())
    }

    fn try_from_addr(addr: IpAddr) -> Result<Self, IpAddr> {
        Self::try_from(Ipv6Addr::try_from_addr(addr)?).map_err(IpAddr::V6)
    }

    fn to_addr_bits(self) -> u128 {
        self.inner().to_addr_bits()
    }

    fn try_from_bits(bits: u128) -> Result<Self, u128> {
        Self::try_from(Ipv6Addr::try_from_bits(bits)?).map_err(|_| bits)
    }
}

#[cfg(test)]
mod tests {
    use super::{IpAddress, Unicast};
    use crate::ipv4::UnicastIpv4Addr;
    use crate::ipv6::UnicastIpv6Addr;
    use static_assertions::assert_type_eq_all;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Pattern<Ip: IpAddress> {
        src: Unicast<Ip>,
        dst: Ip,
    }

    fn relax<Ip: IpAddress>(pattern: Pattern<Unicast<Ip>>) -> Pattern<Ip> {
        Pattern {
            src: pattern.src,
            dst: pattern.dst.into(),
        }
    }

    assert_type_eq_all!(
        Unicast<Unicast<Ipv4Addr>>,
        Unicast<Ipv4Addr>,
        UnicastIpv4Addr
    );
    assert_type_eq_all!(
        Unicast<Unicast<Ipv6Addr>>,
        Unicast<Ipv6Addr>,
        UnicastIpv6Addr
    );

    #[test]
    fn relaxing_keeps_the_addresses() {
        let src = UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        let dst = UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 2)).unwrap();
        let strong: Pattern<UnicastIpv4Addr> = Pattern { src, dst };
        assert_eq!(
            relax::<Ipv4Addr>(strong),
            Pattern {
                src,
                dst: Ipv4Addr::new(10, 0, 0, 2)
            }
        );

        let src = UnicastIpv6Addr::new(Ipv6Addr::LOCALHOST).unwrap();
        let dst = UnicastIpv6Addr::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)).unwrap();
        let strong: Pattern<UnicastIpv6Addr> = Pattern { src, dst };
        assert_eq!(
            relax::<Ipv6Addr>(strong),
            Pattern {
                src,
                dst: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
            }
        );
    }

    #[test]
    fn narrowing_round_trips_within_a_version() {
        bolero::check!()
            .with_type()
            .for_each(|&addr: &IpAddr| match addr {
                IpAddr::V4(_) => {
                    assert_eq!(
                        Ipv4Addr::try_from_addr(addr).map(IpAddress::to_ip_addr),
                        Ok(addr)
                    );
                    assert_eq!(Ipv6Addr::try_from_addr(addr), Err(addr));
                }
                IpAddr::V6(_) => {
                    assert_eq!(
                        Ipv6Addr::try_from_addr(addr).map(IpAddress::to_ip_addr),
                        Ok(addr)
                    );
                    assert_eq!(Ipv4Addr::try_from_addr(addr), Err(addr));
                }
            });
    }

    #[test]
    fn bits_round_trip() {
        bolero::check!()
            .with_type()
            .for_each(|&addr: &IpAddr| match addr {
                IpAddr::V4(addr) => {
                    assert_eq!(Ipv4Addr::try_from_bits(addr.to_addr_bits()), Ok(addr));
                }
                IpAddr::V6(addr) => {
                    assert_eq!(Ipv6Addr::try_from_bits(addr.to_addr_bits()), Ok(addr));
                }
            });
    }

    #[test]
    fn v4_bits_reject_out_of_range() {
        let too_big = u128::from(u32::MAX) + 1;
        assert_eq!(Ipv4Addr::try_from_bits(too_big), Err(too_big));
        assert_eq!(UnicastIpv4Addr::try_from_bits(too_big), Err(too_big));
    }

    #[test]
    fn unicast_narrowing_rejects_non_unicast() {
        for addr in [
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        ] {
            assert_eq!(Ipv4Addr::try_from_addr(addr).map(IpAddr::V4), Ok(addr));
            assert_eq!(UnicastIpv4Addr::try_from_addr(addr), Err(addr));
        }

        let multicast = IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            Ipv6Addr::try_from_addr(multicast).map(IpAddr::V6),
            Ok(multicast)
        );
        assert_eq!(UnicastIpv6Addr::try_from_addr(multicast), Err(multicast));

        let broadcast_bits = Ipv4Addr::BROADCAST.to_addr_bits();
        assert_eq!(
            UnicastIpv4Addr::try_from_bits(broadcast_bits),
            Err(broadcast_bits)
        );
    }

    #[test]
    fn width_matches_the_version() {
        assert_eq!(<Ipv4Addr as IpAddress>::BITS, 32);
        assert_eq!(<UnicastIpv4Addr as IpAddress>::BITS, 32);
        assert_eq!(<Ipv6Addr as IpAddress>::BITS, 128);
        assert_eq!(<UnicastIpv6Addr as IpAddress>::BITS, 128);
    }
}
