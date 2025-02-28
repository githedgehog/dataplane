// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::nat::prefixtrie::{PrefixTrie, TrieError};

use net::vxlan::Vni;
use routing::prefix::Prefix;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Pif {
    name: String,
    endpoints: Vec<Prefix>,
    ips: Vec<Prefix>,
    vpc: String,
    peerings: Vec<String>,
}

impl Pif {
    #[tracing::instrument(level = "trace")]
    pub fn new(name: String, vpc: String) -> Self {
        Self {
            name,
            endpoints: Vec::new(),
            ips: Vec::new(),
            vpc,
            peerings: Vec::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn name(&self) -> &String {
        &self.name
    }

    #[tracing::instrument(level = "trace")]
    pub fn vpc(&self) -> &String {
        &self.vpc
    }

    #[tracing::instrument(level = "trace")]
    pub fn iter_endpoints(&self) -> impl Iterator<Item = &Prefix> {
        self.endpoints.iter()
    }

    #[tracing::instrument(level = "trace")]
    pub fn iter_ips(&self) -> impl Iterator<Item = &Prefix> {
        self.ips.iter()
    }

    #[tracing::instrument(level = "trace")]
    pub fn iter_peerings(&self) -> impl Iterator<Item = &String> {
        self.peerings.iter()
    }

    #[tracing::instrument(level = "trace")]
    pub fn add_endpoint(&mut self, endpoint: Prefix) {
        self.endpoints.push(endpoint);
    }

    #[tracing::instrument(level = "trace")]
    pub fn add_ip(&mut self, ip: Prefix) {
        self.ips.push(ip);
    }

    #[tracing::instrument(level = "trace")]
    pub fn add_peering(&mut self, peering: String) {
        self.peerings.push(peering);
    }

    #[tracing::instrument(level = "trace")]
    pub fn find_prefix(&self, ip: &IpAddr) -> Option<&Prefix> {
        self.iter_endpoints().find(|&prefix| prefix.covers_addr(ip))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PeeringPolicy {
    name: String,
    vnis: [Vni; 2],
    pifs: [String; 2],
}

impl PeeringPolicy {
    #[tracing::instrument(level = "trace")]
    pub fn new(name: String, vnis: [Vni; 2], pifs: [String; 2]) -> Self {
        Self { name, vnis, pifs }
    }

    #[tracing::instrument(level = "trace")]
    pub fn name(&self) -> &String {
        &self.name
    }

    #[tracing::instrument(level = "trace")]
    pub fn vnis(&self) -> &[Vni; 2] {
        &self.vnis
    }

    #[tracing::instrument(level = "trace")]
    pub fn pifs(&self) -> &[String; 2] {
        &self.pifs
    }

    #[tracing::instrument(level = "trace")]
    pub fn get_index(&self, pif: &Pif) -> usize {
        usize::from(self.pifs[0] != pif.name)
    }

    #[tracing::instrument(level = "trace")]
    pub fn get_peer_index(&self, pif: &Pif) -> usize {
        return self.get_index(pif) ^ 1;
    }

    #[tracing::instrument(level = "trace")]
    pub fn get_peer(&self, pif: &Pif) -> &String {
        &self.pifs[self.get_peer_index(pif)]
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Vpc {
    name: String,
    vni: Vni,
    pif_table: PifTable,
}

impl Vpc {
    #[tracing::instrument(level = "trace")]
    pub fn new(name: String, vni: Vni) -> Self {
        Self {
            name,
            vni,
            pif_table: PifTable::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn name(&self) -> &String {
        &self.name
    }

    #[tracing::instrument(level = "trace")]
    pub fn vni(&self) -> Vni {
        self.vni
    }

    #[tracing::instrument(level = "trace")]
    pub fn add_pif(&mut self, pif: Pif) -> Result<(), TrieError> {
        self.pif_table.add_pif(pif)
    }

    #[tracing::instrument(level = "trace")]
    pub fn find_pif_by_endpoint(&self, ip: &IpAddr) -> Option<String> {
        self.pif_table.find_pif_by_endpoint(ip)
    }

    #[tracing::instrument(level = "trace")]
    pub fn get_pif(&self, name: &String) -> Option<&Pif> {
        self.pif_table.pifs.get(name)
    }

    #[tracing::instrument(level = "trace")]
    pub fn iter_pifs(&self) -> impl Iterator<Item = &Pif> {
        self.pif_table.pifs.values()
    }
}

#[derive(Debug, Default, Clone)]
struct PifTable {
    pifs: HashMap<String, Pif>,
    endpoint_trie: PrefixTrie,
}

impl PifTable {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            pifs: HashMap::new(),
            endpoint_trie: PrefixTrie::new(),
        }
    }

    #[tracing::instrument(level = "info")]
    fn add_pif(&mut self, pif: Pif) -> Result<(), TrieError> {
        if self.pifs.contains_key(&pif.name) {
            return Err(TrieError::EntryExists);
        }

        for prefix in &pif.endpoints {
            self.endpoint_trie.insert(prefix, pif.name.clone())?;
            // TODO: Rollback on error?
        }

        self.pifs.insert(pif.name.clone(), pif);
        Ok(())
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_endpoint(&self, ip: &IpAddr) -> Option<String> {
        self.endpoint_trie.find_ip(ip)
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
            for prefix in &pif.endpoints {
                pif_table
                    .endpoint_trie
                    .insert(prefix, pif.name.clone())
                    .or(Err(serde::de::Error::custom(
                        "Failed to insert endpoint into trie",
                    )))?;
            }
        }

        pif_table.pifs = pifs;
        Ok(pif_table)
    }
}
