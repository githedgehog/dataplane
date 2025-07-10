// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::ipv4::Ipv4Prefix;
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "bolero"))]
#[allow(unused_imports)] // re-export
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use std::marker::PhantomData;

pub trait AbstractAddr:
    Copy + Clone + Debug + PartialEq + Eq + PartialOrd + Ord + Hash + Deserialize<'static> + Serialize
{
    const LENGTH: u8;
}

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    thiserror::Error,
)]
#[error("Invalid prefix length: {0}")]
pub struct InvalidPrefixLength<P>(u8, PhantomData<P>)
where
    P: AbstractPrefix;

impl<P: AbstractPrefix> InvalidPrefixLength<P> {
    pub const fn new_checked(prefix: u8) -> Result<Self, InvalidPrefixLength<P>> {
        if prefix > P::Length {
            Err(InvalidPrefixLength(prefix, PhantomData))
        } else {
            Ok(InvalidPrefixLength(prefix, PhantomData))
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct InvalidPrefix<P: AbstractPrefix>(P::Addr, u8);

pub trait AbstractPrefix: Copy + PartialOrd + Ord {
    type Addr: AbstractAddr + Serialize + Deserialize<'static>;
    type Length: Copy + Ord;

    /// The root prefix, e.g. 0.0.0.0/0 for ipv4
    const ROOT: Self;

    /// Constructor which validates the arguments provided.
    ///
    /// # Errors
    ///
    /// * Returns [`InvalidIpv4Network::InvalidPrefix`] if the provided prefix length is greater
    ///   than [`Ipv4PrefixLen::MAX_LEN`].
    /// * Returns [`InvalidIpv4Network::AddressContainsNonNetworkBits`] if the provided address
    ///   contains non-network bits.
    fn new_strict(
        addr: impl Into<Self::Addr> + Debug,
        prefix: impl TryInto<Self::Length, Error = InvalidPrefixLength<Self>> + Debug,
    ) -> Result<Self, InvalidPrefix<Self>>;

    /// Create an [`Ipv4Prefix`] even if the argument contains non-network bits.
    ///
    /// This method is useful in the cases that
    ///
    /// 1. You can't trust your routing input and still don't wish to reject the routes (ideally,
    ///    this does not happen).
    /// 2. You need to convert an interface address assignment into a route
    ///
    /// This method should log a debug event if the provided address contains non-network bits.
    ///
    /// # Errors
    ///
    /// * Returns an error if the provided prefix length is greater than [`Ipv4PrefixLen::MAX_LEN`].
    fn new_tolerant<E>(
        addr: impl Into<Self::Addr> + Debug,
        prefix: impl TryInto<Self::Length, Error = E> + Debug,
    ) -> Result<Self, E>;

    /// Returns the address of the network.
    #[must_use]
    fn address(&self) -> Self::Addr;

    /// Returns the prefix length of the network.
    #[must_use]
    fn length(&self) -> Self::Length;

    fn contains(&self, other: Self) -> bool;
}
