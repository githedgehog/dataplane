// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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
type SubnetMap = BTreeMap<String, Prefix>;

// This is distinct from the VpcSubnetMap in config/converters/k8s
// since this type is only for the test library.  It should be
// compatible with the SubnetMap in config/converters/k8s
type VpcSubnetMap = BTreeMap<String, SubnetMap>;
