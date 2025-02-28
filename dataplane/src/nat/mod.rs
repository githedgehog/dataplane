// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod fabric;
mod prefixtrie;

use crate::nat::fabric::Vpc;
use crate::nat::prefixtrie::PrefixTrie;

use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;

#[derive(Debug)]
#[allow(dead_code)]
struct GlobalContext {
    vpcs: HashMap<u32, Vpc>,
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

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_ip(&self, ip: &IpAddr) -> Option<String> {
        self.global_pif_trie.find_ip(ip)
    }
}
