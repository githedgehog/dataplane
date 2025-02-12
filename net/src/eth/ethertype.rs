// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ethernet type related fields and parsing

use etherparse::EtherType;

#[cfg(any(test, feature = "arbitrary"))]
#[allow(unused_imports)] // just re-exporting conditionally included feature
pub use contract::*;

/// The ethernet header's ethertype field.
///
/// This is a transparent wrapper around the type provided by etherparse.
/// The main point of wrapping this type is to
///
/// 1. Eventually (potentially) 1.0 our crate without requiring the same of etherparse,
/// 2. Permit the implementation of the `TypeGenerator` trait on this type
///    to allow us to property test the rest of our code.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthType(pub(crate) EtherType);

impl EthType {
    /// Ethernet type for [address resolution protocol](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
    pub const ARP: EthType = EthType(EtherType::ARP);
    /// Ethernet type for [IPv4](https://en.wikipedia.org/wiki/IPv4)
    pub const IPV4: EthType = EthType(EtherType::IPV4);
    /// Ethernet type for [IPv6](https://en.wikipedia.org/wiki/IPv6)
    pub const IPV6: EthType = EthType(EtherType::IPV6);
    /// Ethernet type for [VLAN](https://en.wikipedia.org/wiki/IEEE_802.1Q)
    pub const VLAN: EthType = EthType(EtherType::VLAN_TAGGED_FRAME);
    /// Ethernet type for [QinQ (old standard ethtype)](https://en.wikipedia.org/wiki/IEEE_802.1ad#cite_ref-2)
    pub const VLAN_DOUBLE_TAGGED: EthType = EthType(EtherType::VLAN_DOUBLE_TAGGED_FRAME);
    /// Ethernet type for [QinQ (aka provider bridging)](https://en.wikipedia.org/wiki/IEEE_802.1ad)
    pub const VLAN_QINQ: EthType = EthType(EtherType::PROVIDER_BRIDGING);

    /// Map a raw (native-endian) u16 into an [`EthType`]
    #[must_use]
    pub const fn new(raw: u16) -> EthType {
        EthType(EtherType(raw))
    }

    /// Map a raw (big-endian) u16 into an [`EthType`]
    #[must_use]
    pub const fn new_from_be_bytes(raw: [u8; 2]) -> EthType {
        EthType(EtherType(u16::from_be_bytes(raw)))
    }

    /// get the raw `u16` value (native-endian)
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0 .0
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use super::EthType;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for EthType {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            Some(EthType::new(u.gen()?))
        }
    }
}
