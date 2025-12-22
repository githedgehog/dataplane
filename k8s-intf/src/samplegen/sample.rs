// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Implements trait `Sample` to generate sample json objects from the CRD

use kube::api::ObjectMeta;
use std::collections::BTreeMap;
use std::time::Duration;

/// Somewhat dummy trait to generate sample data.
/// We implement this trait for all of the types present in our CRD.
pub trait Sample {
    fn sample() -> Self;
}

impl Sample for String {
    fn sample() -> Self {
        "FIXME".to_string()
    }
}
impl Sample for bool {
    fn sample() -> Self {
        false
    }
}
impl Sample for u8 {
    fn sample() -> Self {
        0
    }
}
impl Sample for i32 {
    fn sample() -> Self {
        0
    }
}
impl Sample for i64 {
    fn sample() -> Self {
        0
    }
}
impl Sample for u32 {
    fn sample() -> Self {
        0
    }
}
impl Sample for u64 {
    fn sample() -> Self {
        0
    }
}
impl Sample for f64 {
    fn sample() -> Self {
        0.0
    }
}
impl Sample for Duration {
    fn sample() -> Self {
        Duration::new(0, 0)
    }
}
impl Sample for ObjectMeta {
    fn sample() -> Self {
        ObjectMeta::default()
    }
}
impl<T: Sample> Sample for Option<T> {
    fn sample() -> Self {
        Some(T::sample())
    }
}
impl<T: Sample> Sample for Vec<T> {
    fn sample() -> Self {
        vec![T::sample(), T::sample()]
    }
}

// impl<K: Sample + Default + Ord, V: Sample> Sample for BTreeMap<K, V> {
//     fn sample() -> Self {
//         let mut tree = BTreeMap::new();
//         tree.insert(K::default(), V::sample());
//         tree
//     }
// }

impl<V: Sample> Sample for BTreeMap<String, V> {
    fn sample() -> Self {
        let mut tree = BTreeMap::new();
        tree.insert("fixme-key-1".to_string(), V::sample());
        tree.insert("fixme-key-2".to_string(), V::sample());
        tree
    }
}
