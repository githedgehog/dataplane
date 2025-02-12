// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::IpAddr;

#[derive(Default, Debug, Clone)]
struct TrieNode<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    children: HashMap<K, TrieNode<K, V>>,
    value: Option<V>,
}

#[derive(Default, Debug, Clone)]
pub struct PrefixTrie<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    root: TrieNode<K, V>,
}

impl<K, V> PrefixTrie<K, V>
where
    K: Clone + Eq + Hash + Default + Debug,
    V: Clone + Default + Debug,
{
    #[tracing::instrument(level = "trace")]
    pub fn new() -> Self {
        Self {
            root: TrieNode::default(),
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn insert(&mut self, keys: Vec<K>, value: V) -> bool {
        let mut node = &mut self.root;

        for key in keys {
            node = node.children.entry(key).or_default();
        }

        if node.value.is_some() {
            return false; // Prefix already exists
        }

        node.value = Some(value);
        true
    }

    #[tracing::instrument(level = "trace")]
    pub fn find(&self, keys: Vec<K>) -> Option<V> {
        let mut node = &self.root;
        let mut best_match = None;

        for key in keys {
            if let Some(val) = &node.value {
                best_match = Some(val.clone());
            }
            if let Some(child) = node.children.get(&key) {
                node = child;
            } else {
                break;
            }
        }

        best_match
    }

    #[tracing::instrument(level = "trace")]
    pub fn ip_to_bits(ip: &IpAddr, prefix_len: u8) -> Vec<u8> {
        let mut bits = Vec::new();
        match ip {
            IpAddr::V4(ipv4) => {
                for i in 0..prefix_len {
                    bits.push((ipv4.octets()[i as usize / 8] >> (7 - (i % 8))) & 1);
                }
            }
            IpAddr::V6(ipv6) => {
                for i in 0..prefix_len {
                    bits.push((ipv6.octets()[i as usize / 8] >> (7 - (i % 8))) & 1);
                }
            }
        }
        bits
    }
}
