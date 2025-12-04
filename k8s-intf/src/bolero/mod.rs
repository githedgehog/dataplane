// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod bgp;
pub mod interface;
pub mod support;

use std::collections::BTreeMap;

/// A type on which implement `bolero::TypeGenerator` for legal values of `T`
///
/// Generally, `bolero` type generators should generate all possible values of `T` so that it is possible to test validation logic, etc.
/// But often it is desirable to generate only legal values.
/// Instead of having a custom named `bolero::ValueGenerator` struct, it is easier to implement `bolero::TypeGenerator` for `LegalValue<T>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LegalValue<T>(T);

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
