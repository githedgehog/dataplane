// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv4 address types

use std::net::Ipv4Addr;

/// Thin wrapper around [`Ipv4Addr`]
///
/// This wrapper scopes addresses to be unicast.
///
/// This wrapper is zero cost save for the need to check that the [`Ipv4Addr`] is in fact unicast.
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnicastIpv4Addr(Ipv4Addr);

impl UnicastIpv4Addr {
    /// Map an unqualified [`Ipv4Addr`] to a [`UnicastIpv4Addr`].
    ///
    /// # Errors
    ///
    /// Returns the supplied address back in the [`Err`] case if it is not a unicast address.
    pub fn new(ip: Ipv4Addr) -> Result<UnicastIpv4Addr, Ipv4Addr> {
        if ip.is_multicast() {
            Err(ip)
        } else {
            Ok(UnicastIpv4Addr(ip))
        }
    }

    /// Get the inner (wrapped) [`Ipv4Addr`]
    #[must_use]
    pub fn inner(&self) -> Ipv4Addr {
        self.0
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ipv4::addr::UnicastIpv4Addr;
    use arbitrary::{Arbitrary, Unstructured};
    use std::net::Ipv4Addr;

    impl<'a> Arbitrary<'a> for UnicastIpv4Addr {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            loop {
                let ip = Ipv4Addr::arbitrary(u)?;
                if !ip.is_multicast() {
                    return Ok(UnicastIpv4Addr(ip));
                }
            }
        }

        fn size_hint(_depth: usize) -> (usize, Option<usize>) {
            (size_of::<Ipv4Addr>(), None) // no formal upper bound on the number of attempts required
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
            .for_each(|unicast: &UnicastIpv4Addr| assert!(!unicast.0.is_multicast()));
    }
}
