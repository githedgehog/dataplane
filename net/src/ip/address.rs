// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! One trait over the IP address types.
//!
//! A pattern with `src: IpAddr, dst: IpAddr` admits states that cannot occur on the wire: a v4
//! source with a v6 destination, or a multicast source. Nothing stops those from being built, so
//! every consumer has to check, and the check has nowhere good to fail -- the arms that result are
//! spread across the tree as `InternalIssue`, as a dropped packet, or as a re-validation of
//! something validation already proved.
//!
//! Making the address a type parameter closes both holes at once
//! (`development/code/avoid-global-reasoning.md`: "make illegal states unrepresentable"):
//!
//! ```
//! # extern crate dataplane_net as net;
//! # use net::ip::address::{IpAddress, Unicast};
//! struct Pattern<Ip: IpAddress> {
//!     src: Unicast<Ip>,
//!     dst: Ip,
//! }
//! ```
//!
//! One parameter carries two facts. `Ip` fixes the version for both fields, and [`Unicast`] on the
//! source says the thing a source address must satisfy but a destination need not.
//!
//! # Two strengths, one parameter
//!
//! [`IpAddress`] is implemented for the unicast wrappers as well as for the bare addresses, and
//! [`Unicast`] is idempotent, so the parameter also chooses how much is constrained:
//!
//! - `Pattern<Ipv4Addr>` -- source unicast, destination any v4 address.
//! - `Pattern<UnicastIpv4Addr>` -- both ends unicast.
//!
//! These are different types stating different propositions, and the [`Into`] bound on
//! [`IpAddress::Unicast`] gives the weakening between them: anything that holds of both ends holds
//! of the source alone.
//!
//! ```
//! # extern crate dataplane_net as net;
//! # use net::ip::address::{IpAddress, Unicast};
//! # struct Pattern<Ip: IpAddress> { src: Unicast<Ip>, dst: Ip }
//! /// Forget what is known about the destination.
//! fn relax<Ip: IpAddress>(pattern: Pattern<Unicast<Ip>>) -> Pattern<Ip> {
//!     Pattern { src: pattern.src, dst: pattern.dst.into() }
//! }
//! ```
//!
//! That signature is why [`IpAddress::Unicast`] is bound by `IpAddress<Unicast = Self::Unicast>`
//! and not merely by [`Into`]. The bound is what lets generic code name `Unicast<Ip>` as an
//! address type in its own right; without it the two strengths only exist at concrete
//! instantiations, and `relax` cannot be written at all.

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

/// An IP address type: one of the two versions, at one of two strengths.
///
/// Sealed. The four implementors are [`Ipv4Addr`], [`Ipv6Addr`], [`UnicastIpv4Addr`], and
/// [`UnicastIpv6Addr`]; the module docs explain what a type parameter bounded by this trait buys.
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
    /// This address type, constrained to unicast.
    ///
    /// Idempotent: `Unicast<Unicast<Ip>>` and `Unicast<Ip>` are the same type, which is what the
    /// `Unicast = Self::Unicast` half of the bound states. The [`Into`] half is the weakening in
    /// the other direction, from the constrained form back to this one.
    type Unicast: IpAddress<Unicast = Self::Unicast> + Into<Self>;

    /// Width of the address, in bits.
    const BITS: u8 = const { <Self as FixedSize>::SIZE as u8 * 8 };

    /// Widen to the version-erased [`IpAddr`].
    fn to_ip_addr(self) -> IpAddr;

    /// Narrow an [`IpAddr`] to this type.
    ///
    /// # Errors
    ///
    /// Returns the address back if it is the other version, or -- for the unicast forms -- if it
    /// is not unicast.
    fn try_from_addr(addr: IpAddr) -> Result<Self, IpAddr>;

    /// The address as a 128-bit integer, zero-extended for v4.
    ///
    /// Named to avoid colliding with the inherent `to_bits` of [`Ipv4Addr`], which yields a `u32`
    /// and would silently win method resolution.
    fn to_addr_bits(self) -> u128;

    /// Build the address from a 128-bit integer.
    ///
    /// # Errors
    ///
    /// Returns the integer back if it does not name an address of this type: out of range for v4,
    /// or -- for the unicast forms -- not a unicast address.
    fn try_from_bits(bits: u128) -> Result<Self, u128>;
}

/// The unicast-constrained form of an address type.
///
/// See the [module docs](self) for what this expresses on a struct field.
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

    /// The shape the trait exists to enable: one parameter fixing the version of both fields, and
    /// the constraint that separates a source address from a destination.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Pattern<Ip: IpAddress> {
        src: Unicast<Ip>,
        dst: Ip,
    }

    /// Weakening, written once and generically. That this compiles at all is the property under
    /// test: it needs `Unicast<Ip>` to be an address type, which is the `IpAddress<..>` half of the
    /// bound on [`IpAddress::Unicast`], and it needs `Unicast<Unicast<Ip>> == Unicast<Ip>`, which
    /// is the `Unicast = Self::Unicast` half.
    fn relax<Ip: IpAddress>(pattern: Pattern<Unicast<Ip>>) -> Pattern<Ip> {
        Pattern {
            src: pattern.src,
            dst: pattern.dst.into(),
        }
    }

    // Idempotence, stated to the compiler rather than to a reader. Without it `relax` above does
    // not typecheck, so this assertion is what that function silently depends on.
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

    /// Narrowing to the constrained form applies the unicast check as well as the version check.
    /// This is what makes `Unicast<Ip>` usable as a parse target and not merely as a marker.
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
