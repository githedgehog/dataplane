// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: prefix list

use routing::prefix::Prefix;
use std::collections::BTreeSet;

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

#[derive(Debug)]
pub struct PrefixList {
    pub name: String,
    pub description: Option<String>,
    pub entries: BTreeSet<PrefixListEntry>,
}

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
