// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateless::NatTables;
use crate::stateless::config::prefixtrie::PrefixTrie;
use crate::stateless::config::tables::{
    NatPeerRuleTable, NatPrefixRuleTable, PerVniTable, TrieValue,
};
use routing::prefix::Prefix;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Debug;

#[allow(clippy::too_many_lines)]
#[must_use]
pub fn build_reference_nat_tables() -> NatTables {
    fn new_prefixtrie<T, const N: usize>(entries: [(Prefix, T); N]) -> PrefixTrie<T>
    where
        T: Default + Debug,
    {
        let mut trie = PrefixTrie::new();
        for (prefix, value) in entries {
            let _ = trie.insert(&prefix, value);
        }
        trie
    }

    NatTables {
        tables: HashMap::from([(
            100,
            PerVniTable {
                dst_nat: NatPrefixRuleTable {
                    rules: new_prefixtrie([
                        ("0.0.0.0/0".into(), None),
                        (
                            "3.0.0.0/16".into(),
                            Some(TrieValue::new(
                                BTreeSet::from(["8.0.0.0/17".into(), "9.0.0.0/17".into()]),
                                BTreeSet::from(["8.0.0.0/24".into()]),
                                BTreeSet::from(["3.0.0.0/16".into()]),
                                BTreeSet::from(["3.0.1.0/24".into()]),
                            )),
                        ),
                        ("3.0.1.0/24".into(), None),
                        (
                            "1.1.0.0/17".into(),
                            Some(TrieValue::new(
                                BTreeSet::from(["10.0.0.0/16".into()]),
                                BTreeSet::from(["10.0.1.0/24".into(), "10.0.2.0/24".into()]),
                                BTreeSet::from(["1.1.0.0/17".into(), "1.2.0.0/17".into()]),
                                BTreeSet::from(["1.2.0.0/24".into(), "1.2.8.0/24".into()]),
                            )),
                        ),
                        (
                            "1.2.0.0/17".into(),
                            Some(TrieValue::new(
                                BTreeSet::from(["10.0.0.0/16".into()]),
                                BTreeSet::from(["10.0.1.0/24".into(), "10.0.2.0/24".into()]),
                                BTreeSet::from(["1.1.0.0/17".into(), "1.2.0.0/17".into()]),
                                BTreeSet::from(["1.2.0.0/24".into(), "1.2.8.0/24".into()]),
                            )),
                        ),
                        ("1.2.0.0/24".into(), None),
                        ("1.2.8.0/24".into(), None),
                        ("::/0".into(), None),
                    ]),
                },
                src_nat_peers: NatPeerRuleTable {
                    rules: new_prefixtrie([
                        ("0.0.0.0/0".into(), 0),
                        ("1.1.0.0/16".into(), 0),
                        ("1.2.0.0/16".into(), 0),
                        ("3.0.0.0/16".into(), 1),
                        ("::/0".into(), 0),
                    ]),
                },
                src_nat_prefixes: vec![
                    NatPrefixRuleTable {
                        rules: new_prefixtrie([
                            ("0.0.0.0/0".into(), None),
                            (
                                "1.1.0.0/16".into(),
                                Some(TrieValue::new(
                                    BTreeSet::from(["1.1.0.0/16".into(), "1.2.0.0/16".into()]),
                                    BTreeSet::from([
                                        "1.1.1.0/24".into(),
                                        "1.1.3.0/24".into(),
                                        "1.1.5.0/24".into(),
                                        "1.2.2.0/24".into(),
                                    ]),
                                    BTreeSet::from(["2.1.0.0/16".into(), "2.2.0.0/16".into()]),
                                    BTreeSet::from([
                                        "2.1.8.0/24".into(),
                                        "2.2.1.0/24".into(),
                                        "2.2.2.0/24".into(),
                                        "2.2.10.0/24".into(),
                                    ]),
                                )),
                            ),
                            (
                                "1.2.0.0/16".into(),
                                Some(TrieValue::new(
                                    BTreeSet::from(["1.1.0.0/16".into(), "1.2.0.0/16".into()]),
                                    BTreeSet::from([
                                        "1.1.1.0/24".into(),
                                        "1.1.3.0/24".into(),
                                        "1.1.5.0/24".into(),
                                        "1.2.2.0/24".into(),
                                    ]),
                                    BTreeSet::from(["2.1.0.0/16".into(), "2.2.0.0/16".into()]),
                                    BTreeSet::from([
                                        "2.1.8.0/24".into(),
                                        "2.2.1.0/24".into(),
                                        "2.2.2.0/24".into(),
                                        "2.2.10.0/24".into(),
                                    ]),
                                )),
                            ),
                            ("1.1.1.0/24".into(), None),
                            ("1.1.3.0/24".into(), None),
                            ("1.1.5.0/24".into(), None),
                            ("1.2.2.0/24".into(), None),
                            ("::/0".into(), None),
                        ]),
                    },
                    NatPrefixRuleTable {
                        rules: new_prefixtrie([
                            ("0.0.0.0/0".into(), None),
                            (
                                "3.0.0.0/16".into(),
                                Some(TrieValue::new(
                                    BTreeSet::from(["3.0.0.0/16".into()]),
                                    BTreeSet::new(),
                                    BTreeSet::from(["4.0.0.0/16".into()]),
                                    BTreeSet::new(),
                                )),
                            ),
                            ("::/0".into(), None),
                        ]),
                    },
                ],
            },
        )]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NatDirection;
    use crate::StatelessNat;
    use net::headers::TryIpv4;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::vxlan::Vni;
    use pipeline::NetworkFunction;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn vni_100() -> Vni {
        Vni::new_checked(100).expect("Failed to create VNI")
    }

    #[test]
    fn test_dst_nat_stateless_44() {
        let nat_tables = build_reference_nat_tables();
        let mut nat = StatelessNat::new(NatDirection::DstNat);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()]
            .into_iter()
            .map(|mut packet| {
                packet.get_meta_mut().src_vni = Some(vni_100());
                packet
            });

        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.destination(), addr_v4("10.0.132.4"));
    }

    #[test]
    fn test_src_nat_stateless_44() {
        let nat_tables = build_reference_nat_tables();
        let mut nat = StatelessNat::new(NatDirection::SrcNat);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()]
            .into_iter()
            .map(|mut packet| {
                packet.get_meta_mut().src_vni = Some(vni_100());
                packet
            });

        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.source().inner(), addr_v4("2.2.0.4"));
    }
}
