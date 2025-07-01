// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: prefix list

use routing::prefix::Prefix;
use std::collections::{BTreeMap, BTreeSet};
use std::default;
use tracing::error;

use crate::models::external::{ConfigError, ConfigResult};

#[derive(Clone, Debug, Ord, Eq, PartialOrd, PartialEq)]
pub enum PrefixListAction {
    Deny,
    Permit,
}

#[derive(Clone, Debug, Ord, Eq, PartialOrd, PartialEq)]
pub enum PrefixListPrefix {
    Prefix(Prefix),
    Any,
}

#[derive(Clone, Debug, Ord, Eq, PartialOrd, PartialEq)]
pub enum PrefixListMatchLen {
    Ge(u8),
    Le(u8),
}

#[derive(Clone, Debug, Ord, Eq, PartialOrd, PartialEq)]
pub struct PrefixListEntry {
    pub action: PrefixListAction,
    pub prefix: PrefixListPrefix,
    pub len_match: Option<PrefixListMatchLen>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum IpVer {
    #[default]
    V4,
    V6,
}

#[derive(Clone, Debug, Default)]
pub struct PrefixList {
    pub name: String,
    pub ipver: IpVer,
    pub description: Option<String>,
    next_seq: u32,
    pub entries: BTreeMap<u32, PrefixListEntry>,
}

#[derive(Clone, Debug, Default)]
pub struct PrefixListTable(BTreeMap<String, PrefixList>);

/* Impl basic ops */
impl PrefixList {
    pub fn new(name: &str, ipver: IpVer, description: Option<String>) -> Self {
        Self {
            name: name.to_owned(),
            ipver,
            description,
            next_seq: 1,
            entries: BTreeMap::new(),
        }
    }
    pub fn add_entry(&mut self, seq: Option<u32>, mut entry: PrefixListEntry) -> ConfigResult {
        if !entry.is_version_compatible(self.ipver) {
            let msg = format!(
                "attempted to insert entry with incompatible version in prefix list {}",
                self.name
            );
            error!("{msg}");
            return Err(ConfigError::InternalFailure(msg));
        }
        let seq = match seq {
            Some(n) => n,
            None => {
                let value = self.next_seq;
                self.next_seq += 1;
                value
            }
        };
        if self.entries.contains_key(&seq) {
            let msg = format!(
                "Duplicate prefix list seq {} in prefix list {}",
                seq, self.name
            );
            error!("{msg}");
            return Err(ConfigError::InternalFailure(msg));
        }
        self.entries.insert(seq, entry);
        Ok(())
    }
    pub fn add_entries(
        &mut self,
        entries: impl IntoIterator<Item = PrefixListEntry>,
    ) -> ConfigResult {
        for entry in entries {
            self.add_entry(None, entry)?;
        }
        Ok(())
    }
}
impl PrefixListEntry {
    pub fn new(
        action: PrefixListAction,
        prefix: PrefixListPrefix,
        len_match: Option<PrefixListMatchLen>,
    ) -> Self {
        Self {
            action,
            prefix,
            len_match,
        }
    }
    /// Tell if a `PrefixListEntry` can be added to a `PrefixList` depending on
    /// the prefix it contains (ipv4 of ipv6) and the `PrefixList` `IpVer` value
    pub fn is_version_compatible(&self, ipver: IpVer) -> bool {
        match self.prefix {
            PrefixListPrefix::Prefix(prefix) => match ipver {
                IpVer::V4 => prefix.is_ipv4(),
                IpVer::V6 => prefix.is_ipv6(),
            },
            PrefixListPrefix::Any => true,
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
    pub fn add_prefix_lists(&mut self, plists: impl IntoIterator<Item = PrefixList>) {
        for plist in plists {
            self.add_prefix_list(plist);
        }
    }
    pub fn values(&self) -> impl Iterator<Item = &PrefixList> {
        self.0.values()
    }
}
