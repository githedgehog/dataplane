// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: priority to community table

use std::collections::HashMap;
use std::fmt::Display;

use crate::ConfigError;

#[derive(Clone, Debug, Default)]
pub struct PriorityCommunityTable(HashMap<u32, String>);
impl PriorityCommunityTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    /// Get a reference to the inner map
    pub fn inner(&self) -> &HashMap<u32, String> {
        &self.0
    }
    /// Insert a priority-to-community mapping
    pub fn insert(&mut self, prio: u32, community: &str) -> Result<(), ConfigError> {
        if self.0.iter().any(|(_, comm)| comm == community) {
            return Err(ConfigError::DuplicateCommunity(community.to_string()));
        }
        self.0.insert(prio, community.to_owned());
        Ok(())
    }
    /// Get the community for a given priority
    pub fn get_community(&self, prio: u32) -> Result<&String, ConfigError> {
        self.0.get(&prio).ok_or(ConfigError::UnmappedPriority(prio))
    }
}

macro_rules! COMMUNITY_MAPPING_FMT {
    ($prio:expr, $community:expr) => {
        format_args!("   {:>6} {:<16}", $prio, $community)
    };
}

impl Display for PriorityCommunityTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  ━━━━━━━ Community mappings ━━━━━━━")?;
        writeln!(f, "{}", COMMUNITY_MAPPING_FMT!("prio", "community"))?;
        for (prio, comm) in self.inner() {
            writeln!(f, "{}", COMMUNITY_MAPPING_FMT!(prio, comm))?;
        }
        Ok(())
    }
}
