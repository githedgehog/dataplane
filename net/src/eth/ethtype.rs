// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ethernet type related fields and parsing

#[cfg(any(test, feature = "arbitrary"))]
#[allow(unused_imports)] // just re-exporting conditionally included feature
pub use contract::*;
use etherparse::EtherType;
use std::fmt::{Display, Formatter};

/// The ethernet header's ethertype field.
///
/// This is a transparent wrapper around the type provided by etherparse.
/// The main point of wrapping this type is to
///
/// 1. Eventually (potentially) 1.0 our crate without requiring the same of etherparse,
/// 2. Permit the implementation of the `TypeGenerator` trait on this type
///    to allow us to property test the rest of our code.
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(try_from = "u16", into = "u16")]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthType(pub(crate) EtherType);

#[derive(Debug, thiserror::Error)]
pub enum EthTypeError {
    #[error("EthType smaller than 0x5dc (1500) are historical and are not supported: received {0}")]
    EthernetIIUnsupported(u16),
    #[error(
        "EthType values between 1501 (0x05dd) and 1536 (0x600) (inclusive) have ambiguous meaning.  Received {0}"
    )]
    Ambiguous(u16),
}

impl Display for EthType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#06x}", self.0.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EthTypeParseError {
    #[error("Invalid EthType syntax: {0}")]
    SyntaxInvalid(String),
    #[error(transparent)]
    SemanticsInvalid(EthTypeError),
}

// impl FromStr for EthType {
//     type Err = EthTypeParseError;
//
//     fn from_str(s: &str) -> Result<Self, EthTypeParseError> {
//         match u16::from_str_radix(s.trim_start_matches("0x"), 16) {
//             Ok(val) => {}
//             Err(_) => {}
//         }
//     }
// }

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
    ///
    /// # Errors
    ///
    /// Returns an [`EthTypeError`] if raw is a legacy or ambiguously defined ethertype.
    ///
    /// Values between 0 and 1500 (inclusive) have only historical meaning, while values between
    /// 1501 and 1536 have no clear meaning in modern ethernet networks.
    pub const fn new(raw: u16) -> Result<EthType, EthTypeError> {
        match raw {
            0..=1500 => Err(EthTypeError::EthernetIIUnsupported(raw)),
            1501..=0x600 => Err(EthTypeError::Ambiguous(raw)),
            _ => Ok(EthType(EtherType(raw))),
        }
    }

    /// Map a raw (big-endian) u16 into an [`EthType`]
    ///
    /// # Errors
    ///
    /// Returns an [`EthTypeError`] if raw is a legacy or ambiguously defined ethertype.
    ///
    /// Values between 0 and 1500 (inclusive) have only historical meaning, while values between
    /// 1501 and 1536 have no clear meaning in modern ethernet networks.
    pub const fn new_from_be_bytes(raw: [u8; 2]) -> Result<EthType, EthTypeError> {
        EthType::new(u16::from_be_bytes(raw))
    }

    /// get the raw `u16` value (native-endian)
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        self.0.0
    }
}

impl TryFrom<u16> for EthType {
    type Error = EthTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        EthType::new(value)
    }
}

impl From<EthType> for u16 {
    fn from(value: EthType) -> Self {
        value.to_u16()
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use super::EthType;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for EthType {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let raw = match u.produce::<u16>()? {
                0..=1536 => 0x800,
                other => other,
            };
            Some(EthType::new(raw).unwrap_or_else(|_| unreachable!()))
        }
    }

    /// The set of commonly used (supported) and easily generated [`EthType`]s
    ///
    /// This type is useful in guiding the fuzzer toward more plausible packets to better exercise
    /// our test infrastructure.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, bolero::TypeGenerator)]
    pub enum CommonEthType {
        /// The IPV4 [`EthType`] (see [`EthType::IPV4`])
        Ipv4,
        /// The IPV6 [`EthType`] (see [`EthType::IPV6`])
        Ipv6,
    }

    impl From<CommonEthType> for EthType {
        fn from(value: CommonEthType) -> Self {
            match value {
                CommonEthType::Ipv4 => EthType::IPV4,
                CommonEthType::Ipv6 => EthType::IPV6,
            }
        }
    }
}

#[cfg(test)]
mod tests {}
