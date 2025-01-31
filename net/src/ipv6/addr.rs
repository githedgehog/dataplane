// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv6 address subclasses

#[allow(unused_imports)] // deliberate re-export
#[cfg(any(test, feature = "arbitrary"))]
pub use contract::*;
use std::net::Ipv6Addr;

/// A type representing the set of unicast ipv6 addresses.
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnicastIpv6Address(Ipv6Addr);

impl UnicastIpv6Address {
    /// Returns the supplied [`Ipv6Addr`] as a [`UnicastIpv6Address`]
    /// after confirming that it is in fact unicast.
    ///
    /// # Errors
    ///
    /// Returns the supplied [`Ipv6Addr`] in the [`Err`] case if the supplied address is multicast.
    pub fn new(addr: Ipv6Addr) -> Result<UnicastIpv6Address, Ipv6Addr> {
        if addr.is_multicast() {
            Err(addr)
        } else {
            Ok(UnicastIpv6Address(addr))
        }
    }

    /// Return the inner (unqualified) [`Ipv6Addr`]
    #[must_use]
    pub const fn inner(self) -> Ipv6Addr {
        self.0
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ipv6::addr::UnicastIpv6Address;
    use arbitrary::{Arbitrary, Unstructured};
    use std::net::Ipv6Addr;

    impl<'a> Arbitrary<'a> for UnicastIpv6Address {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            loop {
                let ip = Ipv6Addr::arbitrary(u)?;
                if !ip.is_multicast() {
                    return Ok(UnicastIpv6Address(ip));
                }
            }
        }

        fn size_hint(_depth: usize) -> (usize, Option<usize>) {
            (size_of::<Ipv6Addr>(), None) // no formal upper bound on the number of attempts required
        }
    }
}

#[cfg(test)]
mod test {
    use crate::ipv4::addr::UnicastIpv4Addr;

    #[test]
    fn generated_unicast_ipv4_address_is_unicast() {
        bolero::check!()
            .with_arbitrary()
            .for_each(|unicast: &UnicastIpv4Addr| assert!(!unicast.inner().is_multicast()));
    }
}
