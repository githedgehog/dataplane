// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc

#![allow(unused)]

use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::rpc::{ApiError, ApiResult};

/// Representation of a VPC from the RPC
#[derive(Debug, PartialEq)]
pub struct Vpc {
    pub name: String, /* key */
    pub vni: Vni,     /* mandatory */
}
impl Vpc {
    pub fn new(name: &str, vni: u32) -> Result<Self, ApiError> {
        let vni = Vni::new_checked(vni).map_err(|_| ApiError::InvalidVpcVni(vni))?;
        Ok(Self {
            name: name.to_owned(),
            vni,
        })
    }
}

#[derive(Debug, Default)]
pub struct VpcTable {
    vpcs: BTreeMap<String, Vpc>,
    vnis: BTreeSet<Vni>,
}
impl VpcTable {
    /// Create new vpc table
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a [`Vpc`] to the vpc table
    pub fn add(&mut self, vpc: Vpc) -> ApiResult {
        // Vni must have not been used before
        if !self.vnis.insert(vpc.vni) {
            return Err(ApiError::DuplicateVpcVni(vpc.vni.as_u32()));
        }
        if let Some(vpc) = self.vpcs.insert(vpc.name.to_owned(), vpc) {
            Err(ApiError::DuplicateVpcId(vpc.name.clone()))
        } else {
            Ok(())
        }
    }
    /// Get a [`Vpc`] from the vpc table by name
    pub fn get_vpc(&self, vpc_name: &str) -> Option<&Vpc> {
        self.vpcs.get(vpc_name)
    }
    /// Iterate over [`Vpc`]s in a [`VpcTable`]
    pub fn values(&self) -> impl Iterator<Item = &Vpc> {
        self.vpcs.values()
    }
}
