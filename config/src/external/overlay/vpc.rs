// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc

#![allow(unused)]
#![allow(clippy::missing_errors_doc)]

use lpm::prefix::IpRangeWithPorts;
use net::vxlan::Vni;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use tracing::{debug, error, warn};

use crate::converters::k8s::config::peering;
use crate::external::overlay::VpcManifest;
use crate::external::overlay::VpcPeeringTable;
use crate::internal::interfaces::interface::{InterfaceConfig, InterfaceConfigTable};
use crate::{ConfigError, ConfigResult};

#[cfg(doc)]
use crate::external::overlay::vpcpeering::VpcPeering;

/// This is nearly identical to [`VpcPeering`], but with some subtle differences.
/// [`Peering`] is owned by a Vpc while [`VpcPeering`] remains in the [`VpcPeeringTable`].
/// Most importantly, [`Peering`] has a notion of local and remote, while [`VpcPeering`] is symmetrical.
#[derive(Clone, Debug, PartialEq)]
pub struct Peering {
    pub name: String,                 /* name of peering */
    pub local: VpcManifest,           /* local manifest */
    pub remote: VpcManifest,          /* remote manifest */
    pub remote_id: VpcId,             /* Id of peer */
    pub gwgroup: Option<String>,      /* gateway group serving this peering */
    pub adv_communities: Vec<String>, /* communities with which to advertise prefixes in this peering */
}

impl Peering {
    fn validate(&self) -> ConfigResult {
        debug!(
            "Validating manifest of VPC {} in peering {}",
            self.local.name, self.name
        );
        self.local.validate()?;
        if false {
            // not needed will be validated when validating the remote vpc
            self.remote.validate()?;
        }

        self.validate_nat_combinations()
    }

    fn validate_nat_combinations(&self) -> ConfigResult {
        // If stateful NAT is set up on one side of the peering, we don't support NAT (stateless or
        // stateful) on the other side.
        let mut local_has_nat = false;
        let mut local_has_stateful_nat = false;
        for expose in &self.local.exposes {
            if expose.has_stateful_nat() {
                local_has_stateful_nat = true;
                local_has_nat = true;
                break;
            } else if expose.has_stateless_nat() {
                local_has_nat = true;
            }
        }

        if !local_has_nat {
            return Ok(());
        }

        for expose in &self.remote.exposes {
            if expose.has_stateful_nat() {
                return Err(ConfigError::StatefulNatOnBothSides(self.name.clone()));
            }
            if expose.has_stateless_nat() && local_has_stateful_nat {
                return Err(ConfigError::StatefulPlusStatelessNat(self.name.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Ord, PartialOrd, Eq)]
/// Type for a fixed-sized VPC unique id
pub struct VpcId(pub(crate) [char; 5]);
impl VpcId {
    #[must_use]
    pub fn new(chars: [char; 5]) -> Self {
        Self(chars)
    }
}
impl TryFrom<&str> for VpcId {
    type Error = ConfigError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        const ID_LEN: usize = 5;
        if value.len() != ID_LEN {
            return Err(ConfigError::BadVpcId(value.to_owned()));
        }
        if !value.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(ConfigError::BadVpcId(value.to_owned()));
        }
        let mut chars = value.chars().take(ID_LEN);
        // unwrap cannot fail here because we checked the length earlier
        Ok(VpcId::new(
            [(); 5].map(|i| chars.next().unwrap_or_else(|| unreachable!())),
        ))
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
    pub fn set_peerings(&mut self, peering_table: &VpcPeeringTable, idmap: &VpcIdMap) {
        debug!("Collecting peerings for vpc '{}'...", self.name);
        self.peerings = peering_table
            .peerings_vpc(&self.name)
            .map(|p| {
                let (local, remote) = p.get_peering_manifests(&self.name);
                let remote_id = idmap.get(&remote.name).unwrap_or_else(|| unreachable!());
                Peering {
                    name: p.name.clone(),
                    local: local.clone(),
                    remote: remote.clone(),
                    remote_id: remote_id.clone(),
                    gwgroup: p.gw_group.clone(),
                    adv_communities: vec![],
                }
            })
            .collect();

        if self.peerings.is_empty() {
            warn!("Warning, VPC {} has no configured peerings", &self.name);
        } else {
            debug!("Vpc '{}' has {} peerings", self.name, self.peerings.len());
        }
    }

    /// Check that a [`Vpc`] does not peer more than once with another.
    fn check_peering_count(&self) -> ConfigResult {
        debug!("Checking peering duplicates for for VPC {}...", self.name);
        // We use the VPC Ids to identify peer VPCs.
        let mut peers = BTreeSet::new();
        for peering in &self.peerings {
            if (!peers.insert(peering.remote_id.clone())) {
                error!(
                    "VPC {} peers more than once with peer {}",
                    self.name, peering.remote.name
                );
                return Err(ConfigError::DuplicateVpcPeerings(peering.name.clone()));
            }
        }
        Ok(())
    }

    /// Check the peerings that a VPC participates in
    fn check_peerings(&self) -> ConfigResult {
        debug!("Checking peerings of VPC {}...", self.name);
        for peering in &self.peerings {
            peering.validate()?;
        }
        Ok(())
    }

    /// Check that prefixes exposed to a given VPC do not overlap (except with default expose).
    /// Also check that at most one default expose is exposed to the VPC.
    fn check_overlap_and_default(&self) -> ConfigResult {
        let mut found_default = false;

        // FIXME: Find a less expensive approach to find overlapping prefixes
        for (i, current_peering) in self.peerings.iter().enumerate() {
            // Check we don't have multiple default expose blocks in the peering
            for expose in &current_peering.remote.exposes {
                if expose.default {
                    if found_default {
                        error!(
                            "Multiple 'default' expose blocks for a same peering in VPC {}",
                            self.name
                        );
                        return Err(ConfigError::Forbidden(
                            "Multiple 'default' expose blocks for a same peering",
                        ));
                    }
                    found_default = true;
                }
            }

            // Check we don't have non-default, overlapping prefixes exposed to the VPC
            for other_peering in &self.peerings[i + 1..] {
                for current_expose in &current_peering.remote.exposes {
                    for other_expose in &other_peering.remote.exposes {
                        match (current_expose.default, other_expose.default) {
                            (true, true) => {
                                // We support at most one default destination exposed to any VPC
                                error!(
                                    "Multiple 'default' destinations exposed to VPC {}",
                                    self.name
                                );
                                return Err(ConfigError::Forbidden(
                                    "Multiple 'default' destinations exposed to VPC",
                                ));
                            }
                            (true, false) | (false, true) => {
                                // Overlap is allowed between a prefix and a default expose
                                continue;
                            }
                            (false, false) => { /* keep processing */ }
                        }
                        for current_prefix in current_expose.public_ips() {
                            for other_prefix in other_expose.public_ips() {
                                if current_prefix.overlaps(other_prefix) {
                                    error!(
                                        "Prefixes exposed to VPC {} overlap: {} and {}",
                                        self.name, current_prefix, other_prefix
                                    );
                                    return Err(ConfigError::OverlappingPrefixes(
                                        *current_prefix,
                                        *other_prefix,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate a [`Vpc`]
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating config for VPC {}...", self.name);
        self.check_peering_count()?;
        self.check_peerings()?;
        self.check_overlap_and_default()?;
        Ok(())
    }

    /// Tell how many peerings this VPC has
    #[must_use]
    pub fn num_peerings(&self) -> usize {
        self.peerings.len()
    }

    /// Tell if the peerings of this VPC have host routes
    #[must_use]
    pub fn has_peers_with_host_prefixes(&self) -> bool {
        self.peerings
            .iter()
            .filter(|peering| peering.remote.has_host_prefixes())
            .count()
            > 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct VpcTable {
    vpcs: BTreeMap<String, Vpc>,
    vnis: BTreeSet<Vni>,
    ids: BTreeMap<VpcId, String>, // name of vpc
}
impl VpcTable {
    /// Create new vpc table
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of VPCs in [`VpcTable`]
    #[must_use]
    pub fn len(&self) -> usize {
        self.vpcs.len()
    }
    /// Tells if [`VpcTable`] is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vpcs.is_empty()
    }

    /// Add a [`Vpc`] to the vpc table
    pub fn add(&mut self, vpc: Vpc) -> ConfigResult {
        if self.vnis.contains(&vpc.vni) {
            return Err(ConfigError::DuplicateVpcVni(vpc.vni.as_u32()));
        }
        if self.ids.contains_key(&vpc.id) {
            return Err(ConfigError::DuplicateVpcId(vpc.id));
        }
        if self.vpcs.contains_key(&vpc.name) {
            return Err(ConfigError::DuplicateVpcName(vpc.name.clone()));
        }
        self.vnis.insert(vpc.vni);
        self.ids.insert(vpc.id.clone(), vpc.name.clone());
        self.vpcs.insert(vpc.name.clone(), vpc);
        Ok(())
    }

    /// Get a [`Vpc`] from the vpc table by name
    #[must_use]
    pub fn get_vpc(&self, vpc_name: &str) -> Option<&Vpc> {
        self.vpcs.get(vpc_name)
    }
    /// Get a [`Vpc`] by [`VpcId`]
    #[must_use]
    pub fn get_vpc_by_vpcid(&self, vpcid: &VpcId) -> Option<&Vpc> {
        match self.ids.get(vpcid) {
            Some(name) => self.vpcs.get(name),
            None => None,
        }
    }
    /// Get the [`Vni`] of the remote [`Vpc`] for a given [`Peering`]
    #[must_use]
    pub fn get_remote_vni(&self, peering: &Peering) -> Vni {
        self.get_vpc_by_vpcid(&peering.remote_id)
            .unwrap_or_else(|| unreachable!())
            .vni
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
            .for_each(|vpc| vpc.set_peerings(peering_table, idmap));
    }

    /// Validate the [`VpcTable`]
    pub fn validate(&self) -> ConfigResult {
        for vpc in self.values() {
            vpc.validate()?;
        }
        Ok(())
    }
}
