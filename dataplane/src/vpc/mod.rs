// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::vpc::prefix_trie::PrefixTrie;
use net::vxlan::Vni;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

pub mod prefix_trie;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Pif {
    pub name: String,
    pub endpoints: Vec<(IpAddr, u8)>, // List of (IP or Prefix, length) -- SMATOV: TODO: Change to CIDR
    pub ips: Vec<(IpAddr, u8)>,       // List of (IP or Prefix, length) SMATOV: TODO: Change to CIDR
    pub vpc: String,                  // Name of the associated VPC
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Vpc {
    pub name: String,
    pub vni: Vni,
    #[serde(skip)]
    // SMATOV: TMP: Skip serialization of PIF table cause its not present in the YAML
    #[allow(dead_code)]
    pub pif_table: PifTable,
}

impl Vpc {
    #[tracing::instrument(level = "trace")]
    fn new(name: String, vni: Vni) -> Self {
        Self {
            name,
            vni,
            pif_table: PifTable::new(),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct PifTable {
    pifs: HashMap<String, Pif>,
    endpoint_trie: PrefixTrie<u8, String>, // Trie for endpoint-based lookups
}

impl PifTable {
    #[tracing::instrument(level = "trace")]
    pub fn new() -> Self {
        Self {
            pifs: HashMap::new(),
            endpoint_trie: PrefixTrie::new(),
        }
    }

    #[tracing::instrument(level = "info")]
    pub fn add_pif(&mut self, pif: Pif) -> bool {
        if self.pifs.contains_key(&pif.name) {
            return false; // Duplicate PIF name
        }

        for (endpoint, prefix_len) in &pif.endpoints {
            let bits = PrefixTrie::<u8, String>::ip_to_bits(endpoint, *prefix_len);
            if !self.endpoint_trie.insert(bits, pif.name.clone()) {
                return false; // Overlapping endpoints
            }
        }

        self.pifs.insert(pif.name.clone(), pif);
        true
    }

    #[tracing::instrument(level = "trace")]
    pub fn find_pif_by_endpoint(&self, ip: &IpAddr) -> Option<String> {
        let bits = PrefixTrie::<u8, String>::ip_to_bits(ip, 32);
        self.endpoint_trie.find(bits)
    }
}

// Implement Serialize and Deserialize for PifTable
impl Serialize for PifTable {
    #[tracing::instrument(level = "info", skip(serializer))]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize only the `pifs` field
        let pifs = &self.pifs;
        pifs.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PifTable {
    #[tracing::instrument(level = "info", skip(deserializer))]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize only the `pifs` field
        let pifs: HashMap<String, Pif> = Deserialize::deserialize(deserializer)?;
        let mut pif_table = PifTable::new();

        // Rebuild the endpoint trie
        for pif in pifs.values() {
            for (endpoint, prefix_len) in &pif.endpoints {
                let bits = PrefixTrie::<u8, String>::ip_to_bits(endpoint, *prefix_len);
                pif_table.endpoint_trie.insert(bits, pif.name.clone());
            }
        }

        pif_table.pifs = pifs;
        Ok(pif_table)
    }
}
