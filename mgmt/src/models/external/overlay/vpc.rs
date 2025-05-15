// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc

#![allow(unused)]

use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use tracing::{debug, warn};

use crate::models::external::overlay::VpcManifest;
use crate::models::external::overlay::VpcPeeringTable;
use crate::models::external::{ConfigError, ConfigResult};
use crate::models::internal::interfaces::interface::{InterfaceConfig, InterfaceConfigTable};

#[cfg(doc)]
use crate::models::external::overlay::vpcpeering::VpcPeering;

/// This is nearly identical to [`VpcPeering`], but with some subtle differences.
/// [`Peering`] is owned by a Vpc while [`VpcPeering`] remains in the [`VpcPeeringTable`].
/// Most importantly, [`Peering`] has a notion of local and remote, while [`VpcPeering`] is symmetrical.
#[derive(Clone, Debug, PartialEq)]
pub struct Peering {
    pub name: String,        /* name of peering */
    pub local: VpcManifest,  /* local manifest */
    pub remote: VpcManifest, /* remote manifest */
    pub remote_id: VpcId,
}

#[derive(Clone, Debug, PartialEq, Ord, PartialOrd, Eq)]
/// Type for a fixed-sized VPC unique id
pub struct VpcId(pub(crate) [char; 5]);
impl VpcId {
    pub fn new(a: char, b: char, c: char, d: char, e: char) -> Self {
        Self([a, b, c, d, e])
    }
}
impl TryFrom<&str> for VpcId {
    type Error = ConfigError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 5 {
            return Err(ConfigError::BadVpcId(value.to_owned()));
        }
        if !value.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(ConfigError::BadVpcId(value.to_owned()));
        }
        let chars: Vec<char> = value.chars().collect();
        Ok(VpcId::new(chars[0], chars[1], chars[2], chars[3], chars[4]))
    }
}

pub(crate) type VpcIdMap = BTreeMap<String, VpcId>;

/// Representation of a VPC from the RPC
#[derive(Clone, Debug, PartialEq)]
pub struct Vpc {
    pub name: String,                     /* name of vpc, used as key */
    pub id: VpcId,                        /* internal Id, unique*/
    pub vni: Vni,                         /* mandatory */
    pub interfaces: InterfaceConfigTable, /* user-defined interfaces in this VPC */
    pub peerings: Vec<Peering>,           /* peerings of this VPC - NOT set via gRPC */
}
impl Vpc {
    pub fn new(name: &str, id: &str, vni: u32) -> Result<Self, ConfigError> {
        let vni = Vni::new_checked(vni).map_err(|_| ConfigError::InvalidVpcVni(vni))?;
        Ok(Self {
            name: name.to_owned(),
            id: VpcId::try_from(id)?,
            vni,
            interfaces: InterfaceConfigTable::new(),
            peerings: vec![],
        })
    }
    /// Add an [`InterfaceConfig`] to this [`Vpc`]
    pub fn add_interface_config(&mut self, if_cfg: InterfaceConfig) {
        self.interfaces.add_interface_config(if_cfg);
    }

    /// Collect all peerings from the [`VpcPeeringTable`] table this vpc participates in
    pub fn collect_peerings(&mut self, peering_table: &VpcPeeringTable, idmap: &VpcIdMap) {
        debug!("Collecting peerings for vpc '{}'...", self.name);
        self.peerings = peering_table
            .peerings_vpc(&self.name)
            .map(|p| {
                let (local, remote) = p.get_peering_manifests(&self.name);
                let remote_id = idmap.get(&remote.name).unwrap();
                Peering {
                    name: p.name.clone(),
                    local: local.clone(),
                    remote: remote.clone(),
                    remote_id: remote_id.clone(),
                }
            })
            .collect();

        if self.peerings.is_empty() {
            warn!("Warning, VPC {} has no configured peerings", &self.name);
        } else {
            debug!("Vpc '{}' has {} peerings", self.name, self.peerings.len());
        }
    }
    /// Tell how many peerings this VPC has
    pub fn num_peerings(&self) -> usize {
        self.peerings.len()
    }
}

#[derive(Clone, Debug, Default)]
pub struct VpcTable {
    vpcs: BTreeMap<String, Vpc>,
    vnis: BTreeSet<Vni>,
    ids: BTreeSet<VpcId>,
}
impl VpcTable {
    /// Create new vpc table
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of VPCs in [`VpcTable`]
    pub fn len(&self) -> usize {
        self.vpcs.len()
    }
    /// Tells if [`VpcTable`] is empty
    pub fn is_empty(&self) -> bool {
        self.vpcs.is_empty()
    }

    /// Add a [`Vpc`] to the vpc table
    pub fn add(&mut self, vpc: Vpc) -> ConfigResult {
        if self.vnis.contains(&vpc.vni) {
            return Err(ConfigError::DuplicateVpcVni(vpc.vni.as_u32()));
        }
        if self.ids.contains(&vpc.id) {
            return Err(ConfigError::DuplicateVpcId(vpc.id));
        }
        if self.vpcs.contains_key(&vpc.name) {
            return Err(ConfigError::DuplicateVpcName(vpc.name.clone()));
        }
        self.vnis.insert(vpc.vni);
        self.ids.insert(vpc.id.clone());
        self.vpcs.insert(vpc.name.to_owned(), vpc);
        Ok(())
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
    pub fn collect_peerings(&mut self, peering_table: &VpcPeeringTable, idmap: &VpcIdMap) {
        debug!("Collecting peerings for all VPCs..");
        self.values_mut()
            .for_each(|vpc| vpc.collect_peerings(peering_table, idmap));
    }
    /// Clear set of vnis
    pub fn clear_vnis(&mut self) {
        self.vnis.clear();
    }
    /// Clear set of ids
    pub fn clear_ids(&mut self) {
        self.ids.clear();
    }
    /// Validate the [`VpcTable`]
    pub fn validate(&self) -> ConfigResult {
        for vpc in self.values() {
            let mut peers = BTreeSet::new();
            // For each VPC, loop over all peerings
            for peering in &vpc.peerings {
                // Check whether we have duplicate remote VPCs between peerings.
                // If we fail to insert, this means the remote VPC ID is already in our set,
                // and we have a duplicate peering: this is a configuration error.
                if (!peers.insert(peering.remote_id.clone())) {
                    return Err(ConfigError::DuplicateVpcPeerings(peering.name.clone()));
                }
            }
            peers.clear();
        }
        Ok(())
    }
}
