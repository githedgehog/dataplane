// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use iptrie::{Ipv4Prefix, Ipv6Prefix, RTrieMap};
use net::vxlan::Vni;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use tracing::{error, warn};

#[derive(thiserror::Error, Debug)]
pub enum NatError {
    #[error("Failed to create IP prefix")]
    BadPrefix,
    #[error("PIF already exists")]
    PifExists,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct Pif {
    name: String,
    endpoints: Vec<(IpAddr, u8)>, // List of (IP or Prefix, length) -- SMATOV: TODO: Change to CIDR
    ips: Vec<(IpAddr, u8)>,       // List of (IP or Prefix, length) SMATOV: TODO: Change to CIDR
    vpc: String,                  // Name of the associated VPC
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

    #[tracing::instrument(level = "trace")]
    fn insert(&mut self, addr: &IpAddr, len: &u8, value: String) -> Result<(), NatError> {
        match addr {
            IpAddr::V4(ip) => {
                let prefix = Ipv4Prefix::new(*ip, *len).or(Err(NatError::BadPrefix))?;
                // Insertion always succeeds even if the key already in the map.
                // So we first need to ensure the key is not already in use.
                //
                // TODO: This is not thread-safe.
                if self.trie_ipv4.get(&prefix).is_some() {
                    return Err(NatError::PifExists);
                }
                self.trie_ipv4.insert(prefix, value);
            }
            IpAddr::V6(ip) => {
                // See comment for IPv4.
                let prefix = Ipv6Prefix::new(*ip, *len).or(Err(NatError::BadPrefix))?;
                if self.trie_ipv6.get(&prefix).is_some() {
                    return Err(NatError::PifExists);
                }
                self.trie_ipv6.insert(prefix, value);
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace")]
    fn find(&self, ip: &IpAddr) -> Option<String> {
        let res = match ip {
            IpAddr::V4(ip) => self.trie_ipv4.lookup(ip).1,
            IpAddr::V6(ip) => self.trie_ipv6.lookup(ip).1,
        };

        // The RTrieMap lookup always return an entry; if no better match, it
        // returns the root of the map, which always exists. This means that to
        // check if the result is "empty", we need to check whether the value
        // from the returned entry is equal to the value of the root. What's the
        // value of the root? We don't set it when creating the map, so it uses
        // the default value for the type: an empty string. So we assume we have
        // no result if the value attached to the returned entry is an empty
        // string, which works but assumes we never accept empty strings as
        // valid values in the map for subsequent entries.
        if res.is_empty() {
            None
        } else {
            Some(res.to_string())
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

        for (endpoint, prefix_len) in &pif.endpoints {
            self.endpoint_trie
                .insert(endpoint, prefix_len, pif.name.clone())?;
            // TODO: Rollback?
        }

        self.pifs.insert(pif.name.clone(), pif);
        Ok(())
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_endpoint(&self, ip: &IpAddr) -> Option<String> {
        self.endpoint_trie.find(ip)
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
                pif_table
                    .endpoint_trie
                    .insert(endpoint, prefix_len, pif.name.clone())
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

                for (endpoint, prefix_len) in &pif.ips {
                    if self
                        .global_pif_trie
                        .insert(endpoint, prefix_len, pif.name.clone())
                        .is_err()
                    {
                        error!(
                            "Failed to insert endpoint {} for PIF {} into global trie",
                            endpoint, pif.name
                        );
                    }
                }
            }
        }
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_ip(&self, ip: &IpAddr) -> Option<String> {
        self.global_pif_trie.find(ip)
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
