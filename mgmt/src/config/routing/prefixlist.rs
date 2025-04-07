// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: prefix list

use routing::prefix::Prefix;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Ord, Eq, PartialOrd, PartialEq)]
pub enum PrefixListAction {
    Deny,
    Permit,
}

#[derive(Debug, Ord, Eq, PartialOrd, PartialEq)]
pub enum PrefixListPrefix {
    Prefix(Prefix),
    Any,
}

#[derive(Debug, Ord, Eq, PartialOrd, PartialEq)]
pub enum PrefixListMatchLen {
    Ge(u8),
    Le(u8),
}

#[derive(Debug, Ord, Eq, PartialOrd, PartialEq)]
pub struct PrefixListEntry {
    pub seq: u32,
    pub action: PrefixListAction,
    pub prefix: PrefixListPrefix,
    pub len_match: Option<PrefixListMatchLen>,
}

#[derive(Debug, Default)]
pub struct PrefixList {
    pub name: String,
    pub description: Option<String>,
    pub entries: BTreeSet<PrefixListEntry>,
}

#[derive(Debug, Default)]
pub struct PrefixListTable(BTreeMap<String, PrefixList>);

/* Impl basic ops */
impl PrefixList {
    pub fn new(name: &str, description: Option<String>) -> Self {
        Self {
            name: name.to_owned(),
            description,
            entries: BTreeSet::new(),
        }
    }
    pub fn add_entry(&mut self, entry: PrefixListEntry) {
        self.entries.insert(entry);
    }
}
impl PrefixListEntry {
    pub fn new(
        seq: u32,
        action: PrefixListAction,
        prefix: PrefixListPrefix,
        len_match: Option<PrefixListMatchLen>,
    ) -> Self {
        Self {
            seq,
            action,
            prefix,
            len_match,
        }
    }
}
impl PrefixListTable {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_prefix_list(&mut self, plist: PrefixList) {
        self.0.insert(plist.name.clone(), plist);
    }
    pub fn values(&self) -> impl Iterator<Item = &PrefixList> {
        self.0.values()
    }
}
