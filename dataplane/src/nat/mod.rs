// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod fabric;
#[allow(dead_code)]
mod iplist;
mod prefixtrie;

use crate::nat::fabric::{PeeringPolicy, Pif, Vpc};
use crate::nat::prefixtrie::PrefixTrie;

use net::vxlan::Vni;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;

#[derive(Debug)]
#[allow(dead_code)]
struct GlobalContext {
    vpcs: HashMap<u32, Vpc>,
    global_pif_trie: PrefixTrie,
    peerings: HashMap<String, PeeringPolicy>,
}

impl GlobalContext {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            vpcs: HashMap::new(),
            global_pif_trie: PrefixTrie::new(),
            peerings: HashMap::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn insert_vpc(&mut self, vni: Vni, vpc: Vpc) {
        vpc.iter_pifs().for_each(|pif| {
            pif.iter_ips().for_each(|prefix| {
                let _ = self.global_pif_trie.insert(prefix, pif.name().clone());
            });
        });
        let _ = self.vpcs.insert(vni.as_u32(), vpc);
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_ip(&self, ip: &IpAddr) -> Option<String> {
        self.global_pif_trie.find_ip(ip)
    }

    #[tracing::instrument(level = "trace")]
    fn get_vpc(&self, vni: Vni) -> Option<&Vpc> {
        self.vpcs.get(&vni.as_u32())
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_name(&self, name: &String) -> Option<&Pif> {
        self.vpcs.values().find_map(|vpc| vpc.get_pif(name))
    }
}
