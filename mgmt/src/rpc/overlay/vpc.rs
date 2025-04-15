// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc

#![allow(unused)]

use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::rpc::overlay::VpcManifest;
use crate::rpc::overlay::VpcPeeringTable;
use crate::rpc::{ApiError, ApiResult};

#[derive(Debug, PartialEq)]
pub struct Peering {
    pub name: String,        /* name of peering */
    pub local: VpcManifest,  /* local manifest */
    pub remote: VpcManifest, /* remote manifest */
}

/// Representation of a VPC from the RPC
#[derive(Debug, PartialEq)]
pub struct Vpc {
    pub name: String,           /* key */
    pub vni: Vni,               /* mandatory */
    pub peerings: Vec<Peering>, /* peerings of this VPC - NOT set via gRPC */
}
impl Vpc {
    pub fn new(name: &str, vni: u32) -> Result<Self, ApiError> {
        let vni = Vni::new_checked(vni).map_err(|_| ApiError::InvalidVpcVni(vni))?;
        Ok(Self {
            name: name.to_owned(),
            vni,
            peerings: vec![],
        })
    }
    /// Collect all peerings from the [`VpcPeeringTable`] table that involve this vpc
    pub fn collect_peerings(&mut self, peering_table: &VpcPeeringTable) {
        self.peerings = peering_table
            .peerings_vpc(&self.name)
            .map(|p| {
                let (local, remote) = p.get_peers(&self.name);
                Peering {
                    name: p.name.clone(),
                    local: local.clone(),
                    remote: remote.clone(),
                }
            })
            .collect();
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
    /// Iterate over [`Vpc`]s in a [`VpcTable`] mutably
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut Vpc> {
        self.vpcs.values_mut()
    }
    /// Collect peerings for all [`Vpc`]s in this [`VpcTable`]
    pub fn collect_peerings(&mut self, peering_table: &VpcPeeringTable) {
        self.values_mut()
            .for_each(|vpc| vpc.collect_peerings(peering_table));
    }
}
