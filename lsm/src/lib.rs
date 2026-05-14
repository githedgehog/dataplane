// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library to implement Log Structured Merge Tree (LSM) functions.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::similar_names)]

// use concurrency::sync::Arc;

// pub struct LsmTreeImpl<K, V> {
//     working: WorkingStore<K, V>,
//     backing: arc_swap::ArcSwap<Arc<BackingStore<K, V>>>,
// }

// pub struct WorkingStore<K, V> {
//     map: dashmap::DashMap<K, V>,
// }

// // pub struct BackingStore<K, V> {
// //     merge_queue: Wo,
// //     ground: hashbrown::HashMap<K, V>,
// // }

// pub trait LsmTree {
//     type Key;
//     type Value;

//     fn insert(&mut self, key: Self::Key, value: Self::Value);
//     fn get(&self, key: &Self::Key) -> Option<&Self::Value>;

// }
