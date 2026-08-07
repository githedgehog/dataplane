// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod acl;
pub mod bgp;
pub mod crd;
pub mod expose;
pub mod gateway;
pub mod gwgroups;
pub mod interface;
pub mod logs;
pub mod peering;
pub mod spec;
pub mod support;
pub mod vpc;

use std::collections::BTreeMap;

use lpm::prefix::Prefix;

/// Which flavour of NAT an expose uses, if any.
///
/// The flavour has to be chosen *before* the expose's prefixes are drawn, because each one imposes
/// its own rules on the shape and none of them can be satisfied afterwards. Static NAT needs both
/// sides to cover the same number of address-port pairs; port forwarding needs exactly one prefix
/// per side of equal length, matched port ranges and no exclusion prefixes at all; masquerade needs
/// a non-empty translation range and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NatFlavour {
    /// No translation: the expose offers its prefixes as they are.
    None,
    /// Many private addresses behind fewer public ones.
    Masquerade,
    /// One private address per public address.
    Static,
    /// One prefix and port range mapped onto another, positionally.
    PortForward,
}

impl NatFlavour {
    /// Every flavour, which is what a generator draws from unless told otherwise.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::None,
            Self::Masquerade,
            Self::Static,
            Self::PortForward,
        ]
    }

    /// Whether this flavour permits exclusion prefixes.
    ///
    /// Port forwarding does not, and static NAT's matched-size rule is easiest to satisfy without
    /// them -- an exclusion has to be mirrored on both sides to keep the sizes equal.
    #[must_use]
    pub fn allows_exclusions(self) -> bool {
        matches!(self, Self::None | Self::Masquerade)
    }

    /// Whether this flavour needs a translation range at all.
    #[must_use]
    pub fn needs_translation(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether this flavour keeps per-flow state.
    ///
    /// The two manifests of a peering may not *both* use a stateful flavour: masquerade opposite
    /// masquerade, masquerade opposite port forwarding, and port forwarding opposite port forwarding
    /// are all refused. No NAT and static NAT are compatible with anything.
    #[must_use]
    pub fn is_stateful(self) -> bool {
        matches!(self, Self::Masquerade | Self::PortForward)
    }
}

/// Which address family an expose is built in.
///
/// One family per expose, always: an expose mixing the two is refused, since NAT46 and NAT64 are
/// not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    /// Both families.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![Self::V4, Self::V6]
    }

    #[must_use]
    pub fn is_v4(self) -> bool {
        matches!(self, Self::V4)
    }
}

/// A type on which implement `bolero::TypeGenerator` for legal values of `T`
///
/// Generally, `bolero` type generators should generate all possible values of `T` so that it is possible to test validation logic, etc.
/// But often it is desirable to generate only legal values.
/// Instead of having a custom named `bolero::ValueGenerator` struct, it is easier to implement `bolero::TypeGenerator` for `LegalValue<T>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LegalValue<T>(T);

impl<T> LegalValue<T> {
    pub fn take(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for LegalValue<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/// A trait which implements a normalization function for testing
///
/// Sometimes, there are two equivalent values for a type, but a naive `PartialEq` implementation may not consider them equal.
/// This trait provides a way to normalize values before comparison.
pub trait Normalize {
    #[must_use]
    fn normalize(&self) -> Self;
}

impl<T> Normalize for Vec<T>
where
    T: Normalize,
{
    fn normalize(&self) -> Self {
        self.iter().map(T::normalize).collect()
    }
}

impl<K, V> Normalize for BTreeMap<K, V>
where
    K: Ord + Clone,
    V: Normalize,
{
    fn normalize(&self) -> Self {
        self.iter()
            .map(|(k, v)| (k.clone(), v.normalize()))
            .collect()
    }
}

// This is distinct from the SubnetMap in config/converters/k8s
// since this type is only for the test library.  It should be
// compatible with the SubnetMap in config/converters/k8s
pub(crate) type SubnetMap = BTreeMap<String, Prefix>;

// This is distinct from the VpcSubnetMap in config/converters/k8s
// since this type is only for the test library.  It should be
// compatible with the SubnetMap in config/converters/k8s
pub(crate) type VpcSubnetMap = BTreeMap<String, SubnetMap>;
