// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc

#![allow(unused)]

use multi_index_map::MultiIndexMap;
use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use tracing::{debug, warn};

use crate::models::external::overlay::VpcManifest;
use crate::models::external::overlay::VpcPeeringTable;
use crate::models::external::{ConfigError, ConfigResult};
use crate::models::internal::interfaces::interface::{InterfaceConfig, InterfaceConfigTable};

/// This is nearly identical to [`VpcPeering`], but with some subtle differences.
/// [`Peering`] is owned by a Vpc while [`VpcPeering`] remains in the [`VpcPeeringTable`].
/// Most importantly, [`Peering`] has a notion of local and remote, while [`VpcPeering`] is symmetrical.
///
/// [`VpcPeering`]: crate::models::external::overlay::vpcpeering::VpcPeering
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
    fn new_unchecked(a: char, b: char, c: char, d: char, e: char) -> Self {
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
        Ok(VpcId::new_unchecked(
            chars[0], chars[1], chars[2], chars[3], chars[4],
        ))
    }
}

pub(crate) type VpcIdMap = BTreeMap<String, VpcId>;

/// Representation of a VPC from the RPC
#[derive(Clone, Debug, PartialEq, MultiIndexMap)]
#[multi_index_derive(Clone, Debug)]
pub struct Vpc {
    #[multi_index(ordered_unique)]
    pub name: String,
    #[multi_index(ordered_unique)]
    pub id: VpcId,
    #[multi_index(ordered_unique)]
    pub vni: Vni,
    pub interfaces: InterfaceConfigTable, /* user-defined interfaces in this VPC */
    pub peerings: Vec<Peering>,           /* peerings of this VPC - NOT set via gRPC */
}

impl Vpc {
    #[tracing::instrument(level = "info")]
    pub fn new(name: &str, id: &str, vni: u32) -> Result<Self, ConfigError> {
        let vni = Vni::new_checked(vni).map_err(ConfigError::InvalidVpcVni)?;
        let mut ret = Self {
            name: name.to_owned(),
            id: VpcId::try_from(id)?,
            vni,
            interfaces: InterfaceConfigTable::new(),
            peerings: vec![],
        };
        let mut map = VpcIdMap::default();
        map.insert(ret.name.clone(), ret.id.clone());
        ret.collect_peerings(&VpcPeeringTable::default(), &map);
        Ok(ret)
    }

    // TODO: OPEN QUESTION: do we need this in the context of the vpc/interface manager?
    /// Add an [`InterfaceConfig`] to this [`Vpc`]
    #[tracing::instrument(level = "info")]
    pub fn add_interface_config(&mut self, if_cfg: InterfaceConfig) {
        self.interfaces.add_interface_config(if_cfg);
    }

    /// Collect all peerings from the [`VpcPeeringTable`] table this vpc participates in
    #[tracing::instrument(level = "debug")]
    fn collect_peerings(&mut self, peering_table: &VpcPeeringTable, idmap: &VpcIdMap) {
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
            // TODO: why is this a warning?
            warn!("Warning, VPC {} has no configured peerings", &self.name);
        } else {
            // TODO: should this be trace?
            debug!("Vpc '{}' has {} peerings", self.name, self.peerings.len());
        }
    }
}

impl MultiIndexVpcMap {
    #[tracing::instrument(level = "debug")]
    pub(crate) fn collect_peerings(&mut self, peering_table: &VpcPeeringTable) {
        debug!("collecting peerings");
        let idmap = self
            .iter_by_name()
            .map(|vpc| (vpc.name.clone(), vpc.id.clone()))
            .collect();
        #[allow(unsafe_code)] // obeys the requirement to not mutate indexed fields
        unsafe { self.iter_mut() }.for_each(|(_, vpc)| vpc.collect_peerings(peering_table, &idmap));
    }
}
