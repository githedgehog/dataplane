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
pub struct VpcExposeManifest {
    pub name: String, /* key: name of vpc */
    pub exposes: Vec<VpcExpose>,
}
impl VpcExposeManifest {
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
    pub vpc1: Option<VpcExposeManifest>,
    pub vpc2: Option<VpcExposeManifest>,
}
impl VpcPeering {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            vpc1: None,
            vpc2: None,
        }
    }
    pub fn validate(&self) -> ApiResult {
        if self.name.is_empty() {
            return Err(ApiError::MissingPeeringName);
        }
        if self.vpc1.is_none() || self.vpc2.is_none() {
            Err(ApiError::IncompletePeeringData(self.name.clone()))
        } else {
            Ok(())
        }
    }
    pub fn set_one(&mut self, exp_manifest: VpcExposeManifest) {
        self.vpc1 = Some(exp_manifest);
    }
    pub fn set_two(&mut self, exp_manifest: VpcExposeManifest) {
        self.vpc2 = Some(exp_manifest);
    }

    // TODO add all exposes to the VpcPeering
}

#[derive(Debug, Default)]
pub struct VpcPeeringTable(BTreeMap<String, VpcPeering>);
impl VpcPeeringTable {
    /// Create new vpc peering table table
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, peering: VpcPeering) -> ApiResult {
        peering.validate()?;
        if let Some(peering) = self.0.insert(peering.name.to_owned(), peering) {
            Err(ApiError::DuplicateVpcPeeringId(peering.name.clone()))
        } else {
            Ok(())
        }
    }
    pub fn values(&self) -> impl Iterator<Item = &VpcPeering> {
        self.0.values()
    }
}
