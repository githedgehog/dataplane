// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc

#![allow(clippy::missing_errors_doc)]

use lpm::prefix::IpRangeWithPorts;
use net::vxlan::Vni;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
#[allow(unused)]
use tracing::{debug, error, warn};

use crate::external::overlay::VpcManifest;
use crate::external::overlay::VpcPeeringTable;
use crate::external::overlay::vpcpeering::ValidatedManifest;
use crate::external::overlay::vpcpeering::VpcExposeNatConfig;
use crate::internal::interfaces::interface::InterfaceConfigTable;
use crate::{ConfigError, ConfigResult};

#[cfg(doc)]
use crate::external::overlay::vpcpeering::VpcPeering;

/// This is nearly identical to [`VpcPeering`], but with some subtle differences.
/// [`Peering`] is owned by a Vpc while [`VpcPeering`] remains in the [`VpcPeeringTable`].
/// Most importantly, [`Peering`] has a notion of local and remote, while [`VpcPeering`] is symmetrical.
#[derive(Clone, Debug, PartialEq)]
pub struct Peering {
    pub name: String,            /* name of peering */
    pub local: VpcManifest,      /* local manifest */
    pub remote: VpcManifest,     /* remote manifest */
    pub remote_id: VpcId,        /* Id of peer */
    pub gwgroup: Option<String>, /* gateway group serving this peering */
}

impl Peering {
    pub fn validate(&self) -> Result<ValidatedPeering, ConfigError> {
        debug!(
            "Validating manifest of VPC {} in peering {}",
            self.local.name, self.name
        );

        if self.local.default_expose().is_some() && self.remote.default_expose().is_some() {
            return Err(ConfigError::Forbidden(
                "A default expose cannot be peered with another default expose",
            ));
        }

        let valid_peering_candidate = ValidatedPeering {
            name: self.name.clone(),
            local: self.local.validate()?,
            remote: self.remote.validate()?,
            remote_id: self.remote_id.clone(),
            gwgroup: self.gwgroup.clone(),
        };
        valid_peering_candidate.validate_nat_combinations()?;

        Ok(valid_peering_candidate)
    }

    /// FOR TESTS ONLY. Fake validation for a VPC peering.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    #[must_use]
    pub unsafe fn fake_validated_peering_for_tests(&self) -> ValidatedPeering {
        let (fake_local, fake_remote) = unsafe {
            (
                self.local.fake_valid_manifest_for_tests(),
                self.remote.fake_valid_manifest_for_tests(),
            )
        };
        ValidatedPeering {
            name: self.name.clone(),
            local: fake_local,
            remote: fake_remote,
            remote_id: self.remote_id.clone(),
            gwgroup: self.gwgroup.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedPeering {
    name: String,              /* name of peering */
    local: ValidatedManifest,  /* local manifest */
    remote: ValidatedManifest, /* remote manifest */
    remote_id: VpcId,          /* Id of peer */
    gwgroup: Option<String>,   /* gateway group serving this peering */
}

impl ValidatedPeering {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn local(&self) -> &ValidatedManifest {
        &self.local
    }

    #[must_use]
    pub fn remote(&self) -> &ValidatedManifest {
        &self.remote
    }

    #[must_use]
    pub fn remote_id(&self) -> &VpcId {
        &self.remote_id
    }

    #[must_use]
    pub fn gwgroup(&self) -> Option<&String> {
        self.gwgroup.as_ref()
    }

    fn validate_nat_combinations(&self) -> ConfigResult {
        // If stateful NAT is set up on one side of the peering, we don't support NAT (stateless or
        // stateful) on the other side.
        let mut local_has_stateless_nat = false;
        let mut local_has_stateful_nat = false;
        let mut local_has_port_forwarding = false;
        for expose in self.local.valexp() {
            match expose.nat_config() {
                Some(VpcExposeNatConfig::Stateful { .. }) => {
                    local_has_stateful_nat = true;
                }
                Some(VpcExposeNatConfig::Stateless { .. }) => {
                    local_has_stateless_nat = true;
                }
                Some(VpcExposeNatConfig::PortForwarding { .. }) => {
                    local_has_port_forwarding = true;
                }
                None => {}
            }
        }
        let local_has_nat =
            local_has_stateless_nat || local_has_stateful_nat || local_has_port_forwarding;

        if !local_has_nat {
            return Ok(());
        }

        let local_has_stateless_nat_only =
            local_has_stateless_nat && !local_has_stateful_nat && !local_has_port_forwarding;

        // Allowed:
        //
        // - no NAT ------------ *
        // - stateless NAT ----- stateless NAT
        //
        // Disallowed (some of them may be supported in the future):
        //
        // - stateful NAT ------ stateless NAT
        // - stateful NAT ------ stateful NAT
        // - stateful NAT ------ port forwarding
        // - port forwarding --- port forwarding
        // - port forwarding --- stateless NAT

        for remote_expose in self.remote.valexp() {
            if !remote_expose.has_nat() {
                continue;
            }
            if local_has_stateless_nat_only && remote_expose.has_stateless_nat() {
                continue;
            }
            // Other combinations are rejected
            return Err(ConfigError::IncompatibleNatModes(self.name.clone()));
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
            [(); 5].map(|()| chars.next().unwrap_or_else(|| unreachable!())),
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

    /// Collect all peerings from the [`VpcPeeringTable`] table this vpc participates in
    fn set_peerings(&mut self, peering_table: &VpcPeeringTable, idmap: &VpcIdMap) {
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
                    gwgroup: p.gwgroup.clone(),
                }
            })
            .collect();

        if !self.peerings.is_empty() {
            debug!("Vpc '{}' has {} peerings", self.name, self.peerings.len());
        }
    }

    /// Check that a [`Vpc`] does not peer more than once with another.
    fn check_peering_count(&self) -> ConfigResult {
        debug!("Checking peering duplicates for for VPC {}...", self.name);
        // We use the VPC Ids to identify peer VPCs.
        let mut peers = BTreeSet::new();
        for peering in &self.peerings {
            if !peers.insert(peering.remote_id.clone()) {
                error!(
                    "VPC {} peers more than once with peer {}",
                    self.name, peering.remote.name
                );
                return Err(ConfigError::DuplicateVpcPeerings(peering.name.clone()));
            }
        }
        Ok(())
    }

    /// Validate a [`Vpc`] and produce a [`ValidatedVpc`] if it passes validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the VPC configuration is invalid.
    pub fn validate(&self) -> Result<ValidatedVpc, ConfigError> {
        debug!("Validating config for VPC {}...", self.name);
        self.check_peering_count()?;

        debug!("Checking peerings of VPC {}...", self.name);
        let validated_peerings: Vec<ValidatedPeering> = self
            .peerings
            .iter()
            .map(Peering::validate)
            .collect::<Result<_, _>>()?;

        let valid_vpc_candidate = ValidatedVpc {
            name: self.name.clone(),
            id: self.id.clone(),
            vni: self.vni,
            interfaces: self.interfaces.clone(),
            peerings: validated_peerings,
        };

        valid_vpc_candidate.check_overlap_and_default()?;
        Ok(valid_vpc_candidate)
    }

    /// FOR TESTS ONLY. Fake validation for the VPC peering manifests.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    #[must_use]
    pub unsafe fn fake_validated_vpc_for_tests(&self) -> ValidatedVpc {
        let fake_validated_peerings = self
            .peerings
            .iter()
            .map(|peering| {
                let (fake_local, fake_remote) = unsafe {
                    (
                        peering.local.fake_valid_manifest_for_tests(),
                        peering.remote.fake_valid_manifest_for_tests(),
                    )
                };
                ValidatedPeering {
                    name: peering.name.clone(),
                    local: fake_local,
                    remote: fake_remote,
                    remote_id: peering.remote_id.clone(),
                    gwgroup: peering.gwgroup.clone(),
                }
            })
            .collect::<Vec<_>>();

        ValidatedVpc {
            name: self.name.clone(),
            id: self.id.clone(),
            vni: self.vni,
            interfaces: self.interfaces.clone(),
            peerings: fake_validated_peerings,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedVpc {
    name: String,                     /* name of vpc, used as key */
    id: VpcId,                        /* internal Id, unique*/
    vni: Vni,                         /* mandatory */
    interfaces: InterfaceConfigTable, /* user-defined interfaces in this VPC */
    peerings: Vec<ValidatedPeering>,  /* peerings of this VPC - NOT set via gRPC */
}

impl ValidatedVpc {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn id(&self) -> &VpcId {
        &self.id
    }

    #[must_use]
    pub fn vni(&self) -> Vni {
        self.vni
    }

    #[must_use]
    pub fn interfaces(&self) -> &InterfaceConfigTable {
        &self.interfaces
    }

    #[must_use]
    pub fn peerings(&self) -> &[ValidatedPeering] {
        &self.peerings
    }

    /// Tell how many peerings this VPC has
    #[must_use]
    pub fn num_peerings(&self) -> usize {
        self.peerings.len()
    }

    /// Provide an iterator over all peerings that have either masquerade or port-forwarding
    /// exposes locally.
    pub fn local_stateful_nat_peerings(&self) -> impl Iterator<Item = &ValidatedPeering> {
        self.peerings().iter().filter(|p| {
            p.local()
                .valexp()
                .iter()
                .any(|e| e.has_port_forwarding() || e.has_stateful_nat())
        })
    }

    /// Check that prefixes exposed to a given VPC do not overlap. Exceptions:
    ///
    /// - overlap is allowed between a prefix and a default expose (it overlaps by design)
    /// - overlap is allowed between prefixes from different exposes if both their exposes use
    ///   stateful NAT (we can fall back to the flow table to disambiguate the destination VPC)
    ///
    /// Also check that at most one default expose is exposed to the VPC.
    fn check_overlap_and_default(&self) -> ConfigResult {
        // FIXME: Find a less expensive approach to find overlapping prefixes
        for (i, current_peering) in self.peerings().iter().enumerate() {
            // Check we don't have non-default, overlapping prefixes exposed to the VPC
            for other_peering in &self.peerings()[i + 1..] {
                for current_expose in current_peering.remote().valexp() {
                    for other_expose in other_peering.remote().valexp() {
                        if current_expose.has_stateful_nat() && other_expose.has_stateful_nat() {
                            // Overlap is allowed if both expose blocks use stateful NAT
                            continue;
                        }
                        match (current_expose.is_default(), other_expose.is_default()) {
                            (true, true) => {
                                // We support at most one default destination exposed to any VPC
                                error!(
                                    "Multiple 'default' destinations exposed to VPC {}",
                                    self.name()
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
                                        self.name(),
                                        current_prefix,
                                        other_prefix
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

    /// Iterate over [`Vpc`]s in a [`VpcTable`]
    pub fn values(&self) -> impl Iterator<Item = &Vpc> {
        self.vpcs.values()
    }

    /// Iterate over [`Vpc`]s in a [`VpcTable`] mutably
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut Vpc> {
        self.vpcs.values_mut()
    }

    /// Iterate over all of the [`Peering`]s of all [`Vpc`]s immutably
    pub fn peerings(&self) -> impl Iterator<Item = &Peering> {
        self.vpcs.values().flat_map(|vpc| vpc.peerings.iter())
    }

    /// Collect peerings for all [`Vpc`]s in this [`VpcTable`]
    pub(crate) fn collect_peerings(&mut self, peering_table: &VpcPeeringTable, idmap: &VpcIdMap) {
        debug!("Collecting peerings for all VPCs..");
        self.values_mut()
            .for_each(|vpc| vpc.set_peerings(peering_table, idmap));
    }

    /// Validate the [`VpcTable`]
    pub fn validate(&mut self) -> ConfigResult {
        for vpc in self.values_mut() {
            vpc.validate()?;
        }
        Ok(())
    }

    /// Consume `self` and produce a [`ValidatedVpcTable`] if it passes validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the table is invalid.
    pub fn validated(mut self) -> Result<ValidatedVpcTable, ConfigError> {
        self.validate()?;
        Ok(ValidatedVpcTable(self))
    }
}

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct ValidatedVpcTable(VpcTable);

impl ValidatedVpcTable {
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.vpcs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.vpcs.is_empty()
    }

    pub fn values(&self) -> impl Iterator<Item = &ValidatedVpc> {
        // SAFETY: ValidatedVpc is #[repr(transparent)] over Vpc, and a ValidatedVpcTable can only
        // be obtained from a successful `VpcTable::validated`, which validates every Vpc.
        #[allow(unsafe_code)]
        self.0
            .vpcs
            .values()
            .map(|vpc| unsafe { &*(&raw const *vpc).cast::<ValidatedVpc>() })
    }

    #[must_use]
    pub fn get_vpc(&self, vpc_name: &str) -> Option<&ValidatedVpc> {
        self.0.get_vpc(vpc_name).map(|vpc| {
            // SAFETY: ValidatedVpc is `#[repr(transparent)]` over Vpc, and a `ValidatedVpcTable`
            // can only be obtained from `VpcTable::validated`, which validates every Vpc.
            #[allow(unsafe_code)]
            unsafe {
                &*(&raw const *vpc).cast::<ValidatedVpc>()
            }
        })
    }

    #[must_use]
    pub fn get_remote_vni(&self, peering: &ValidatedPeering) -> Vni {
        self.0
            .get_vpc_by_vpcid(peering.remote_id())
            .unwrap_or_else(|| unreachable!())
            .vni
    }
}
