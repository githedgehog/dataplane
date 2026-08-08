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
pub mod mutate;
pub mod peering;
pub mod spec;
pub mod support;
pub mod vpc;

use std::collections::BTreeMap;

use lpm::prefix::Prefix;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NatFlavour {
    None,
    Masquerade,
    Static,
    PortForward,
}

impl NatFlavour {
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::None,
            Self::Masquerade,
            Self::Static,
            Self::PortForward,
        ]
    }

    #[must_use]
    pub fn allows_exclusions(self) -> bool {
        matches!(self, Self::None | Self::Masquerade)
    }

    #[must_use]
    pub fn needs_translation(self) -> bool {
        !matches!(self, Self::None)
    }

    #[must_use]
    pub fn is_stateful(self) -> bool {
        matches!(self, Self::Masquerade | Self::PortForward)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
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
