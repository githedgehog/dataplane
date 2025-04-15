// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc peering

use routing::prefix::Prefix;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::rpc::{ApiError, ApiResult};

#[derive(Debug, Default)]
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
    pub fn validate(&self) -> ApiResult {
        // TODO
        Ok(())
    }
}

#[derive(Debug, Default)]
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
    pub fn add_expose(&mut self, expose: VpcExpose) -> ApiResult {
        expose.validate()?;
        self.exposes.push(expose);
        Ok(())
    }
}

#[derive(Debug)]
pub struct VpcPeering {
    pub name: String, /* key: name of peering */
    pub left: Option<VpcManifest>,
    pub right: Option<VpcManifest>,
}
impl VpcPeering {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            left: None,
            right: None,
        }
    }
    pub fn validate(&self) -> ApiResult {
        if self.name.is_empty() {
            return Err(ApiError::MissingPeeringName);
        }
        if self.left.is_none() || self.right.is_none() {
            Err(ApiError::IncompletePeeringData(self.name.clone()))
        } else {
            Ok(())
        }
    }
    pub fn set_one(&mut self, exp_manifest: VpcManifest) {
        self.left = Some(exp_manifest);
    }
    pub fn set_two(&mut self, exp_manifest: VpcManifest) {
        self.right = Some(exp_manifest);
    }

    // TODO add all exposes to the VpcPeering
}

#[derive(Debug, Default)]
pub struct VpcPeeringTable(BTreeMap<String, VpcPeering>);
impl VpcPeeringTable {
    /// Create a new, empty [`VpcPeeringTable`]
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a [`VpcPeering`] to a [`VpcPeeringTable`]
    pub fn add(&mut self, peering: VpcPeering) -> ApiResult {
        peering.validate()?;
        if let Some(peering) = self.0.insert(peering.name.to_owned(), peering) {
            Err(ApiError::DuplicateVpcPeeringId(peering.name.clone()))
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
        self.0.values().filter(|peering| {
            // VPCs are options to ease builders but should always be there
            let name1 = peering.left.as_ref().map(|m| m.name.as_str());
            let name2 = peering.right.as_ref().map(|m| m.name.as_str());
            if name1.is_none() || name2.is_none() {
                false
            } else {
                name1 == Some(vpc) || name2 == Some(vpc)
            }
        })
    }
}
