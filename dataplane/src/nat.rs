// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::pipeline::{MetaPacket, PipelineStage};
use net::vxlan::Vni;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::hash::Hash;
use std::net::IpAddr;
use std::path::Path;
use tracing::{error, warn};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct Pif {
    name: String,
    endpoints: Vec<(IpAddr, u8)>, // List of (IP or Prefix, length) -- SMATOV: TODO: Change to CIDR
    ips: Vec<(IpAddr, u8)>,       // List of (IP or Prefix, length) SMATOV: TODO: Change to CIDR
    vpc: String,                  // Name of the associated VPC
}

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
struct PrefixTrie<K, V>
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
    fn new() -> Self {
        Self {
            root: TrieNode::default(),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn insert(&mut self, keys: Vec<K>, value: V) -> bool {
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
    fn find(&self, keys: Vec<K>) -> Option<V> {
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
    fn ip_to_bits(ip: &IpAddr, prefix_len: u8) -> Vec<u8> {
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

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Vpc {
    name: String,
    vni: Vni,
    #[serde(skip)]
    // SMATOV: TMP: Skip serialization of PIF table cause its not present in the YAML
    pif_table: PifTable,
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
struct PifTable {
    pifs: HashMap<String, Pif>,
    endpoint_trie: PrefixTrie<u8, String>, // Trie for endpoint-based lookups
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
    fn add_pif(&mut self, pif: Pif) -> bool {
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
    fn find_pif_by_endpoint(&self, ip: &IpAddr) -> Option<String> {
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

#[derive(Clone, Debug)]
struct GlobalContext {
    vpcs: HashMap<String, Vpc>,
    global_pif_trie: PrefixTrie<u8, String>, // Global PIF lookup by IP
}

impl GlobalContext {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            vpcs: HashMap::new(),
            global_pif_trie: PrefixTrie::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn build(&mut self) {
        self.load_vpcs(Path::new("src").join("nat").join("vpcs").as_path());
        self.load_pifs(Path::new("src").join("nat").join("pifs").as_path());
    }

    #[tracing::instrument(level = "info")]
    fn load_vpcs(&mut self, directory: &Path) {
        let paths = fs::read_dir(directory).expect("Failed to read VPCs directory");

        for entry in paths.flatten() {
            let file_path = entry.path();
            if file_path
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                let file_content = fs::read_to_string(&file_path).expect("Failed to read file");
                let vpc: Vpc = serde_yml::from_str(&file_content).expect("Failed to parse YAML");
                self.vpcs.insert(vpc.name.clone(), vpc);
            }
        }
    }

    #[tracing::instrument(level = "info")]
    fn load_pifs(&mut self, directory: &Path) {
        let paths = fs::read_dir(directory).expect("Failed to read PIFs directory");

        for entry in paths.flatten() {
            let file_path = entry.path();
            if file_path
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                let file_content = fs::read_to_string(&file_path).expect("Failed to read file");
                let pif: Pif = serde_yml::from_str(&file_content).expect("Failed to parse YAML");

                if let Some(vpc) = self.vpcs.get_mut(&pif.vpc) {
                    vpc.pif_table.add_pif(pif.clone());
                } else {
                    error!("VPC {} not found for PIF {}", pif.vpc, pif.name);
                }

                for (ip, prefix_len) in &pif.ips {
                    let bits = PrefixTrie::<u8, String>::ip_to_bits(ip, *prefix_len);
                    self.global_pif_trie.insert(bits, pif.name.clone());
                }
            }
        }
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_ip(&self, ip: &IpAddr) -> Option<String> {
        let bits = PrefixTrie::<u8, String>::ip_to_bits(ip, 32);
        self.global_pif_trie.find(bits)
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_in_vpc(&self, vpc_name: &str, ip: &IpAddr) -> Option<String> {
        let vpc = self.vpcs.get(vpc_name)?;
        vpc.pif_table.find_pif_by_endpoint(ip)
    }
}

#[derive(Clone, Debug)]
pub struct NatProcessor {
    context: GlobalContext,
}

impl NatProcessor {
    #[tracing::instrument(level = "trace")]
    pub fn new() -> Self {
        let mut context = GlobalContext::new();
        context.build();
        Self { context }
    }

    #[tracing::instrument(level = "trace")]
    fn nat_needed(&self, _pkt: &mut MetaPacket) -> bool {
        false
    }

    #[tracing::instrument(level = "trace")]
    fn nat(&self, pkt: &mut MetaPacket) {
        // Apply NAT

        println!("{:?}", self.context);

        let ip = match &pkt.packet.net {
            Some(net::packet::Net::Ipv4(ipv4)) => Some(IpAddr::V4(ipv4.source().inner())),
            Some(net::packet::Net::Ipv6(ipv6)) => Some(IpAddr::V6(ipv6.source().inner())),
            _ => None,
        };
        match ip {
            Some(ip) => {
                if let Some(pif_name) = self.context.find_pif_by_ip(&ip) {
                    warn!("Found PIF for IP {ip}: {pif_name}");
                } else {
                    warn!("No PIF found for IP {ip}");
                }
            }
            _ => warn!("No IP found in packet"),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn process_packet(&self, metapacket: &mut MetaPacket) {
        if self.nat_needed(metapacket) {
            self.nat(metapacket);
        }
    }
}

impl PipelineStage for NatProcessor {
    #[tracing::instrument(level = "info")]
    fn start(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    #[tracing::instrument(level = "trace")]
    fn update_config(
        &mut self,
        config: &crate::config::Config,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn process(
        &mut self,
        packets: Box<dyn Iterator<Item = MetaPacket>>,
    ) -> Box<dyn Iterator<Item = MetaPacket>> {
        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{info, warn};
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn basic_test() {
        // Load VPCs and PIFs
        let mut context = GlobalContext::new();
        context.build();

        warn!(
            "pwd: {pwd}",
            pwd = std::env::current_dir().unwrap().display()
        );

        // Example global lookup
        let ip: IpAddr = "11.11.0.5".parse().unwrap();
        if let Some(pif_name) = context.find_pif_by_ip(&ip) {
            info!("Found PIF for IP {ip}: {pif_name}");
        } else {
            panic!("No PIF found for IP {ip}");
        }

        // Example VPC lookup
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        if let Some(pif_name) = context.find_pif_in_vpc("VPC1", &ip) {
            info!("Found PIF in VPC1 for IP {ip}: {pif_name}");
        } else {
            panic!("No PIF found in VPC1 for IP {ip}");
        }
    }
}
