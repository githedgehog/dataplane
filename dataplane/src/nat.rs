// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::vpc::prefix_trie::PrefixTrie;
use crate::vpc::{Pif, Vpc};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use tracing::{error, warn};

#[derive(Debug)]
#[allow(dead_code)]
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
