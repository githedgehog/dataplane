// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: preference to community table

use std::collections::HashMap;
use std::fmt::Display;

use crate::ConfigError;

#[derive(Clone, Debug, Default)]
pub struct PriorityCommunityTable(HashMap<usize, String>);
impl PriorityCommunityTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Insert a community
    pub fn insert(&mut self, order: usize, community: &str) -> Result<(), ConfigError> {
        if self.0.iter().any(|(_, comm)| comm == community) {
            return Err(ConfigError::DuplicateCommunity(community.to_string()));
        }
        self.0.insert(order, community.to_owned());
        Ok(())
    }
    #[must_use]
    /// Get the community for a given order. Smaller corresponds to higher priority
    pub fn get_community(&self, order: usize) -> Option<&String> {
        self.0.get(&order)
    }
}

macro_rules! COMMUNITY_MAPPING_FMT {
    ($rank:expr, $community:expr) => {
        format_args!("   {:>6} {:<16}", $rank, $community)
    };
}

impl Display for PriorityCommunityTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  ━━━━━━━ Community mappings ━━━━━━━")?;
        writeln!(f, "{}", COMMUNITY_MAPPING_FMT!("rank", "community"))?;
        for (rank, comm) in &self.0 {
            writeln!(f, "{}", COMMUNITY_MAPPING_FMT!(rank, comm))?;
        }
        Ok(())
    }
}
