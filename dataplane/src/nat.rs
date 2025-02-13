// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use iptrie::{map::RTrieMap, Ipv4Prefix, Ipv6Prefix};
use net::vxlan::Vni;
use routing::prefix::Prefix;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use tracing::{error, warn};

#[derive(thiserror::Error, Debug)]
pub enum NatError {
    #[error("PIF already exists")]
    PifExists,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct Pif {
    name: String,
    endpoints: Vec<Prefix>,
    ips: Vec<Prefix>,
    vpc: String,
}

#[derive(Default, Clone)]
struct PrefixTrie {
    trie_ipv4: RTrieMap<Ipv4Prefix, String>,
    trie_ipv6: RTrieMap<Ipv6Prefix, String>,
}

impl PrefixTrie {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            trie_ipv4: RTrieMap::new(),
            trie_ipv6: RTrieMap::new(),
        }
    }

    #[inline(always)]
    fn insert_ipv4(&mut self, prefix: &Ipv4Prefix, value: String) -> Result<(), NatError> {
        // Insertion always succeeds even if the key already in the map.
        // So we first need to ensure the key is not already in use.
        //
        // TODO: This is not thread-safe.
        if self.trie_ipv4.get(prefix).is_some() {
            return Err(NatError::PifExists);
        }
        self.trie_ipv4.insert(*prefix, value);
        Ok(())
    }

    #[inline(always)]
    fn insert_ipv6(&mut self, prefix: &Ipv6Prefix, value: String) -> Result<(), NatError> {
        // See comment for IPv4
        if self.trie_ipv6.get(prefix).is_some() {
            return Err(NatError::PifExists);
        }
        self.trie_ipv6.insert(*prefix, value);
        Ok(())
    }

    #[tracing::instrument(level = "trace")]
    fn insert(&mut self, prefix: &Prefix, value: String) -> Result<(), NatError> {
        match prefix {
            Prefix::IPV4(p) => self.insert_ipv4(p, value),
            Prefix::IPV6(p) => self.insert_ipv6(p, value),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn find(&self, prefix: &Prefix) -> Option<String> {
        match prefix {
            Prefix::IPV4(p) => {
                let (k, v) = self.trie_ipv4.lookup(p);
                // The RTrieMap lookup always return an entry; if no better
                // match, it returns the root of the map, which always exists.
                // This means that to check if the result is "empty", we need to
                // check whether the returned entry is the root for the map.
                if Prefix::IPV4(*k).is_root() {
                    None
                } else {
                    Some(v.to_string())
                }
            }
            Prefix::IPV6(p) => {
                let (k, v) = self.trie_ipv6.lookup(p);
                if Prefix::IPV6(*k).is_root() {
                    None
                } else {
                    Some(v.to_string())
                }
            }
        }
    }

    #[tracing::instrument(level = "trace")]
    fn find_ip(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(_) => self.find(&Prefix::from((*ip, 32))),
            IpAddr::V6(_) => self.find(&Prefix::from((*ip, 128))),
        }
    }
}

impl Debug for PrefixTrie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_map()
            .entries(self.trie_ipv4.iter())
            .entries(self.trie_ipv6.iter())
            .finish()
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
    fn add_pif(&mut self, pif: Pif) -> Result<(), NatError> {
        if self.pifs.contains_key(&pif.name) {
            return Err(NatError::PifExists);
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
                    if vpc.pif_table.add_pif(pif.clone()).is_err() {
                        error!("Failed to add PIF {} to table", pif.name);
                    }
                } else {
                    error!("VPC {} not found for PIF {}", pif.vpc, pif.name);
                }

                for prefix in &pif.ips {
                    if self
                        .global_pif_trie
                        .insert(prefix, pif.name.clone())
                        .is_err()
                    {
                        error!(
                            "Failed to insert endpoint {} for PIF {} into global trie",
                            prefix, pif.name
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
        vpc.pif_table.find_pif_by_endpoint(ip)
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
