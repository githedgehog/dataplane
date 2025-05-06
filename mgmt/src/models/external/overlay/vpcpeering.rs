// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc peering

use routing::prefix::Prefix;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::models::external::{ConfigError, ConfigResult};
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExpose {
    pub ips: BTreeSet<Prefix>,
    pub nots: BTreeSet<Prefix>,
    pub as_range: BTreeSet<Prefix>,
    pub not_as: BTreeSet<Prefix>,
}
impl VpcExpose {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn ip(mut self, prefix: Prefix) -> Self {
        self.ips.insert(prefix);
        self
    }
    pub fn not(mut self, prefix: Prefix) -> Self {
        self.nots.insert(prefix);
        self
    }
    pub fn as_range(mut self, prefix: Prefix) -> Self {
        self.as_range.insert(prefix);
        self
    }
    pub fn not_as(mut self, prefix: Prefix) -> Self {
        self.not_as.insert(prefix);
        self
    }
    pub fn validate(&self) -> ConfigResult {
        // TODO
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcManifest {
    pub name: String, /* key: name of vpc */
    pub exposes: Vec<VpcExpose>,
}
impl VpcManifest {
    pub fn new(vpc_name: &str) -> Self {
        Self {
            name: vpc_name.to_owned(),
            ..Default::default()
        }
    }
    pub fn add_expose(&mut self, expose: VpcExpose) -> ConfigResult {
        expose.validate()?;
        self.exposes.push(expose);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct VpcPeering {
    pub name: String,       /* name of peering (key in table) */
    pub left: VpcManifest,  /* manifest for one side of the peering */
    pub right: VpcManifest, /* manifest for the other side */
}
impl VpcPeering {
    pub fn new(name: &str, left: VpcManifest, right: VpcManifest) -> Self {
        Self {
            name: name.to_owned(),
            left,
            right,
        }
    }
    pub fn validate(&self) -> ConfigResult {
        if self.name.is_empty() {
            return Err(ConfigError::MissingPeeringName);
        }
        Ok(())
    }
    /// Given a peering fetch the manifests, orderly depending on the provided vpc name
    pub fn get_peering_manifests(&self, vpc: &str) -> (&VpcManifest, &VpcManifest) {
        if self.left.name == vpc {
            (&self.left, &self.right)
        } else {
            (&self.right, &self.left)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct VpcPeeringTable(BTreeMap<String, VpcPeering>);
impl VpcPeeringTable {
    /// Create a new, empty [`VpcPeeringTable`]
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of peerings in [`VpcPeeringTable`]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Tells if [`VpcPeeringTable`] contains peerings or not
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Add a [`VpcPeering`] to a [`VpcPeeringTable`]
    pub fn add(&mut self, peering: VpcPeering) -> ConfigResult {
        peering.validate()?;
        if let Some(peering) = self.0.insert(peering.name.to_owned(), peering) {
            Err(ConfigError::DuplicateVpcPeeringId(peering.name.clone()))
        } else {
            Ok(())
        }
    }
    /// Iterate over all [`VpcPeering`]s in a [`VpcPeeringTable`]
    pub fn values(&self) -> impl Iterator<Item = &VpcPeering> {
        self.0.values()
    }
    /// Produce iterator of [`VpcPeering`]s that involve the vpc with the provided name
    pub fn peerings_vpc(&self, vpc: &str) -> impl Iterator<Item = &VpcPeering> {
        self.0
            .values()
            .filter(move |p| p.left.name == vpc || p.right.name == vpc)
    }
}
