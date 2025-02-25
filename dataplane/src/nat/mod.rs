// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod fabric;
mod prefixtrie;

use crate::nat::fabric::{Pif, Vpc};
use crate::nat::prefixtrie::PrefixTrie;

use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use tracing::error;

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
