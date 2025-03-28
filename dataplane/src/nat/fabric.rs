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

/// From a current address prefix, find the target address prefix.
#[derive(Debug, Clone)]
struct NatPrefixRuleTable {
    rules: PrefixTrie<Prefix>,
}

/// From a current address prefix, find the relevant [`NatPrefixRuleTable`] for
/// the target prefix lookup.
#[derive(Debug)]
struct NatPeeringRuleTable {
    rules: PrefixTrie<usize>,
}

impl NatPrefixRuleTable {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            rules: PrefixTrie::with_roots(Prefix::root_v4(), Prefix::root_v6()),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn insert(&mut self, key: &Prefix, value: Prefix) -> Result<(), TrieError> {
        self.rules.insert(key, value)
    }

    #[tracing::instrument(level = "trace")]
    fn lookup(&self, addr: &IpAddr) -> Option<(Prefix, &Prefix)> {
        self.rules.lookup(addr)
    }
}

impl NatPeeringRuleTable {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            rules: PrefixTrie::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn insert(&mut self, prefix: &Prefix, target_index: usize) -> Result<(), TrieError> {
        self.rules.insert(prefix, target_index)
    }

    #[tracing::instrument(level = "trace")]
    fn find(&self, addr: &IpAddr) -> Option<usize> {
        self.rules.find_ip(addr).copied()
    }
}

#[derive(Debug, Clone)]
pub struct PeeringIps {
    pub cidr: Prefix,
}

#[derive(Debug, Clone)]
pub struct PeeringAs {
    pub cidr: Prefix,
}

#[derive(Debug, Clone)]
pub struct PeeringEntry {
    pub internal: Vec<PeeringIps>,
    pub external: Vec<PeeringAs>,
}

#[derive(Debug, Clone)]
pub struct Peering {
    pub name: String,
    pub entries: HashMap<String, PeeringEntry>,
}

#[derive(Debug)]
pub struct Vrf {
    name: String,
    vni: Vni,
    pif_table: PifTable,
    table_dst_nat: NatPrefixRuleTable,
    table_src_nat_peering: NatPeeringRuleTable,
    table_src_nat_prefixes: Vec<NatPrefixRuleTable>,
}

impl Vrf {
    #[tracing::instrument(level = "trace")]
    pub fn new(name: String, vni: Vni) -> Self {
        Self {
            name,
            vni,
            pif_table: PifTable::new(),
            table_dst_nat: NatPrefixRuleTable::new(),
            table_src_nat_peering: NatPeeringRuleTable::new(),
            table_src_nat_prefixes: Vec::new(),
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
    pub fn find_pif_by_endpoint(&self, ip: &IpAddr) -> Option<&String> {
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

    #[tracing::instrument(level = "trace")]
    pub fn add_peering(&mut self, peering: &Peering) -> Result<(), TrieError> {
        peering.entries.iter().try_for_each(|(name, entry)| {
            match name {
                n if *n == self.name => {
                    // Create new peering table for source NAT
                    let mut peering_table = NatPrefixRuleTable::new();
                    entry
                        .internal
                        .iter()
                        .zip(entry.external.iter())
                        .try_for_each(|(internal, external)| {
                            peering_table.insert(&internal.cidr, external.cidr.clone())
                        })?;
                    self.table_src_nat_prefixes.push(peering_table);

                    // Update peering table to make relevant prefixes point to
                    // the new peering table
                    let peering_index = self.table_src_nat_prefixes.len() - 1;
                    entry.internal.iter().try_for_each(|internal| {
                        self.table_src_nat_peering
                            .rules
                            .insert(&internal.cidr, peering_index)
                    })
                }
                _ => {
                    // Update table for destination NAT
                    entry
                        .internal
                        .iter()
                        .zip(entry.external.iter())
                        .try_for_each(|(internal, external)| {
                            self.table_dst_nat
                                .insert(&external.cidr, internal.cidr.clone())
                        })
                }
            }
        })
    }

    #[tracing::instrument(level = "trace")]
    pub fn lookup_src_prefix(&self, addr: &IpAddr) -> Option<(Prefix, &Prefix)> {
        // Find relevant prefix table for involved peering
        let peering_index = self.table_src_nat_peering.find(addr)?;

        // Look up for the NAT prefix in that table
        if let Some(table) = self.table_src_nat_prefixes.get(peering_index) {
            table.lookup(addr)
        } else {
            None
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn lookup_dst_prefix(&self, addr: &IpAddr) -> Option<(Prefix, &Prefix)> {
        self.table_dst_nat.lookup(addr)
    }
}

#[derive(Debug, Default, Clone)]
struct PifTable {
    pifs: HashMap<String, Pif>,
    endpoint_trie: PrefixTrie<String>,
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
    fn find_pif_by_endpoint(&self, ip: &IpAddr) -> Option<&String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use iptrie::{Ipv4Prefix, Ipv6Prefix};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn prefix_v4(s: &str) -> Prefix {
        Ipv4Prefix::from_str(s).expect("Invalid IPv4 prefix").into()
    }

    fn prefix_v6(s: &str) -> Prefix {
        Ipv6Prefix::from_str(s).expect("Invalid IPv6 prefix").into()
    }

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn addr_v6(s: &str) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from_str(s).expect("Invalid IPv6 address"))
    }

    #[test]
    fn test_fabric_legacy() {
        // Create a VPC

        let mut vpc1 = Vrf::new(
            "test_vpc_1".into(),
            Vni::new_checked(100).expect("Failed to create VNI"),
        );

        assert_eq!(vpc1.name(), "test_vpc_1");
        assert_eq!(vpc1.vni().as_u32(), 100);

        // Create a PIF

        let mut pif1 = Pif::new("pif1".into(), "test_vpc_1".into());

        assert_eq!(pif1.name, "pif1");
        assert_eq!(pif1.vpc, "test_vpc_1");

        pif1.add_endpoint(prefix_v4("10.0.0.0/24"));
        pif1.add_endpoint(prefix_v6("1111::/32"));

        pif1.add_ip(prefix_v4("192.168.0.0/24"));
        pif1.add_ip(prefix_v6("aaaa::/32"));

        assert_eq!(pif1.endpoints.len(), 2);
        assert_eq!(pif1.ips.len(), 2);

        assert_eq!(
            pif1.find_prefix(&addr_v4("10.0.0.1")),
            Some(&prefix_v4("10.0.0.0/24"))
        );
        assert_eq!(
            pif1.find_prefix(&addr_v6("1111::3")),
            Some(&prefix_v6("1111::/32"))
        );
        assert_eq!(pif1.find_prefix(&addr_v4("22.22.22.22")), None);
        assert_eq!(pif1.find_prefix(&addr_v6("2222::2222")), None);

        // Create another VPC

        let mut vpc2 = Vrf::new(
            "test_vpc_2".into(),
            Vni::new_checked(200).expect("Failed to create VNI"),
        );

        // Create another PIF

        let mut pif2 = Pif::new("pif2".into(), "test_vpc_2".into());
        pif2.add_endpoint(prefix_v4("10.0.2.0/24"));
        pif2.add_endpoint(prefix_v4("10.0.3.0/24"));
        pif2.add_ip(prefix_v4("192.168.2.0/24"));
        pif2.add_ip(prefix_v4("192.168.3.0/24"));

        // Create a peering policy

        let peering_policy = PeeringPolicy::new(
            "test_peering_policy".into(),
            [
                Vni::new_checked(100).expect("Failed to create VNI"),
                Vni::new_checked(200).expect("Failed to create VNI"),
            ],
            [pif1.name().clone(), pif2.name().clone()],
        );
        assert_eq!(peering_policy.name(), &"test_peering_policy".to_string());
        assert_eq!(peering_policy.vnis[0].as_u32(), 100);
        assert_eq!(peering_policy.vnis[1].as_u32(), 200);
        assert_eq!(peering_policy.pifs[0], "pif1".to_string());
        assert_eq!(peering_policy.pifs[1], "pif2".to_string());

        assert_eq!(peering_policy.get_index(&pif1), 0);
        assert_eq!(peering_policy.get_index(&pif2), 1);
        assert_eq!(peering_policy.get_peer_index(&pif1), 1);
        assert_eq!(peering_policy.get_peer_index(&pif2), 0);
        assert_eq!(peering_policy.get_peer(&pif1), &"pif2".to_string());
        assert_eq!(peering_policy.get_peer(&pif2), &"pif1".to_string());

        // Back-reference peering policy from PIFs

        pif1.add_peering(peering_policy.name().clone());
        pif2.add_peering(peering_policy.name().clone());

        assert_eq!(pif1.iter_peerings().collect::<Vec<_>>().len(), 1);
        assert_eq!(pif2.iter_peerings().collect::<Vec<_>>().len(), 1);

        // Insert the PIFs into the VPCs

        vpc1.add_pif(pif1.clone()).expect("Failed to add PIF");
        assert_eq!(vpc1.pif_table.pifs.len(), 1);
        vpc2.add_pif(pif2.clone()).expect("Failed to add PIF");
        assert_eq!(vpc2.pif_table.pifs.len(), 1);

        assert_eq!(vpc1.get_pif(&"pif1".into()), Some(&pif1));
        assert_eq!(vpc2.get_pif(&"pif2".into()), Some(&pif2));

        // Look up for IPs in the VPC

        assert_eq!(
            vpc1.find_pif_by_endpoint(&addr_v4("10.0.0.1")),
            Some(&pif1.name)
        );
        assert_eq!(
            vpc1.find_pif_by_endpoint(&addr_v4("10.0.0.27")),
            Some(&pif1.name)
        );
        assert_eq!(
            vpc1.find_pif_by_endpoint(&addr_v6("1111::27")),
            Some(&pif1.name)
        );

        assert_eq!(
            vpc2.find_pif_by_endpoint(&addr_v4("10.0.2.2")),
            Some(&pif2.name)
        );
        assert_eq!(
            vpc2.find_pif_by_endpoint(&addr_v4("10.0.3.255")),
            Some(&pif2.name)
        );

        assert_eq!(vpc1.find_pif_by_endpoint(&addr_v4("22.22.22.22")), None);
        assert_eq!(vpc1.find_pif_by_endpoint(&addr_v6("2222::2222")), None);
        assert_eq!(vpc2.find_pif_by_endpoint(&addr_v4("10.0.0.1")), None);

        /*
        // Serialize, deserialize

        let serialized = serde_yml::to_string(&vpc1).expect("Failed to serialize");
        println!("{serialized}");

        let deserialized: Vrf = serde_yml::from_str(&serialized).expect("Failed to deserialize");
        println!("{serialized:?}");

        assert_eq!(deserialized.pif_table.pifs.len(), 1);
        assert_eq!(deserialized.get_pif(&"pif1".into()), Some(&pif1));
        */
    }

    #[test]
    fn test_bad_pif() {
        let mut vpc = Vrf::new(
            "test_vpc".into(),
            Vni::new_checked(100).expect("Failed to create VNI"),
        );
        let pif1 = Pif::new("test_pif".into(), "test_vpc".into());
        let pif2 = Pif::new("test_pif".into(), "test_vpc".into());

        vpc.add_pif(pif1).expect("Failed to add PIF");
        vpc.add_pif(pif2)
            .expect_err("Should fail to add PIF with duplicate name");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_fabric() {
        let mut vpc1 = Vrf::new(
            "test_vpc1".into(),
            Vni::new_checked(100).expect("Failed to create VNI"),
        );
        let mut vpc2 = Vrf::new(
            "test_vpc2".into(),
            Vni::new_checked(200).expect("Failed to create VNI"),
        );

        assert_eq!(vpc1.name(), "test_vpc1");
        assert_eq!(vpc1.vni().as_u32(), 100);
        assert_eq!(vpc2.name(), "test_vpc2");
        assert_eq!(vpc2.vni().as_u32(), 200);

        let mut peering = Peering {
            name: "test_peering".into(),
            entries: HashMap::new(),
        };
        peering.entries.insert(
            "test_vpc1".into(),
            PeeringEntry {
                internal: vec![
                    PeeringIps {
                        cidr: prefix_v4("1.2.3.0/24"),
                    },
                    PeeringIps {
                        cidr: prefix_v4("4.5.6.0/24"),
                    },
                    PeeringIps {
                        cidr: prefix_v4("7.8.9.0/24"),
                    },
                    PeeringIps {
                        cidr: prefix_v6("abcd::/64"),
                    },
                ],
                external: vec![
                    PeeringAs {
                        cidr: prefix_v4("10.0.1.0/24"),
                    },
                    PeeringAs {
                        cidr: prefix_v4("10.0.2.0/24"),
                    },
                    PeeringAs {
                        cidr: prefix_v4("10.0.3.0/24"),
                    },
                    PeeringAs {
                        cidr: prefix_v6("1234::/64"),
                    },
                ],
            },
        );
        peering.entries.insert(
            "test_vpc2".into(),
            PeeringEntry {
                internal: vec![
                    PeeringIps {
                        cidr: prefix_v4("9.9.0.0/16"),
                    },
                    PeeringIps {
                        cidr: prefix_v4("99.99.0.0/16"),
                    },
                ],
                external: vec![
                    PeeringAs {
                        cidr: prefix_v4("1.1.0.0/16"),
                    },
                    PeeringAs {
                        cidr: prefix_v4("1.2.0.0/16"),
                    },
                ],
            },
        );

        assert_eq!(peering.name, "test_peering");
        assert_eq!(peering.entries.len(), 2);
        assert_eq!(
            peering
                .entries
                .get("test_vpc1")
                .expect("Failed to get entry")
                .internal
                .len(),
            4
        );
        assert_eq!(
            peering
                .entries
                .get("test_vpc2")
                .expect("Failed to get entry")
                .external
                .len(),
            2
        );

        assert_eq!(vpc1.table_src_nat_prefixes.len(), 0);

        vpc1.add_peering(&peering).expect("Failed to add peering");
        vpc2.add_peering(&peering).expect("Failed to add peering");

        assert_eq!(vpc1.table_src_nat_prefixes.len(), 1);

        assert_eq!(
            vpc1.lookup_src_prefix(&addr_v4("1.2.3.4")),
            Some((prefix_v4("1.2.3.0/24"), &prefix_v4("10.0.1.0/24")))
        );

        assert_eq!(
            vpc1.lookup_dst_prefix(&addr_v4("1.2.3.4")),
            Some((prefix_v4("1.2.0.0/16"), &prefix_v4("99.99.0.0/16")))
        );

        assert_eq!(
            vpc1.lookup_src_prefix(&addr_v6("abcd::5678")),
            Some((prefix_v6("abcd::/64"), &prefix_v6("1234::/64")))
        );
    }
}
