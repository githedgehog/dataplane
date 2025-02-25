// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod prefixtrie;

use crate::nat::prefixtrie::{PrefixTrie, TrieError};

use net::vxlan::Vni;
use routing::prefix::Prefix;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use tracing::error;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct Pif {
    name: String,
    endpoints: Vec<Prefix>,
    ips: Vec<Prefix>,
    vpc: String,
}

impl Pif {
    #[tracing::instrument(level = "trace")]
    pub fn new(name: String, vpc: String) -> Self {
        Self {
            name,
            endpoints: Vec::new(),
            ips: Vec::new(),
            vpc,
        }
    }

    fn name(&self) -> &String {
        &self.name
    }

    fn vpc(&self) -> &String {
        &self.vpc
    }

    fn iter_ips(&self) -> impl Iterator<Item = &Prefix> {
        self.ips.iter()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Vpc {
    name: String,
    vni: Vni,
    #[serde(skip)]
    // SMATOV: TMP: Skip serialization of PIF table cause its not present in the YAML
    #[allow(dead_code)]
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

    fn name(&self) -> &String {
        &self.name
    }

    fn add_pif(&mut self, pif: Pif) -> Result<(), TrieError> {
        self.pif_table.add_pif(pif)
    }

    fn find_pif_by_endpoint(&self, ip: &IpAddr) -> Option<String> {
        self.pif_table.find_pif_by_endpoint(ip)
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
        if self.pifs.contains_key(pif.name()) {
            return Err(TrieError::EntryExists);
        }

        for prefix in &pif.endpoints {
            self.endpoint_trie.insert(prefix, pif.name().clone())?;
            // TODO: Rollback on error?
        }

        self.pifs.insert(pif.name().clone(), pif);
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
                    .insert(prefix, pif.name().clone())
                    .or(Err(serde::de::Error::custom(
                        "Failed to insert endpoint into trie",
                    )))?;
            }
        }

        pif_table.pifs = pifs;
        Ok(pif_table)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct GlobalContext {
    vpcs: HashMap<String, Vpc>,
    global_pif_trie: PrefixTrie,
}

impl GlobalContext {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            vpcs: HashMap::new(),
            global_pif_trie: PrefixTrie::new(),
        }
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
                self.vpcs.insert(vpc.name().clone(), vpc);
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

                if let Some(vpc) = self.vpcs.get_mut(pif.vpc()) {
                    if vpc.add_pif(pif.clone()).is_err() {
                        error!("Failed to add PIF {} to table", pif.name());
                    }
                } else {
                    error!("VPC {} not found for PIF {}", pif.vpc(), pif.name());
                }

                for prefix in pif.iter_ips() {
                    if self
                        .global_pif_trie
                        .insert(prefix, pif.name().clone())
                        .is_err()
                    {
                        error!(
                            "Failed to insert endpoint {} for PIF {} into global trie",
                            prefix,
                            pif.name()
                        );
                    }
                }
            }
        }
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_ip(&self, ip: &IpAddr) -> Option<String> {
        self.global_pif_trie.find_ip(ip)
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_in_vpc(&self, vpc_name: &str, ip: &IpAddr) -> Option<String> {
        let vpc = self.vpcs.get(vpc_name)?;
        vpc.find_pif_by_endpoint(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{info, warn};

    #[test]
    fn basic_test() {
        let mut context = GlobalContext::new();

        warn!(
            "pwd: {pwd}",
            pwd = std::env::current_dir().unwrap().display()
        );
        // Load VPCs and PIFs
        context.load_vpcs(Path::new("src").join("nat").join("vpcs").as_path());
        context.load_pifs(Path::new("src").join("nat").join("pifs").as_path());

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
