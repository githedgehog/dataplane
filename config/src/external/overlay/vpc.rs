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

use crate::external::overlay::VpcManifest;
use crate::external::overlay::VpcPeeringTable;
use crate::external::overlay::vpcpeering::ValidatedManifest;
use crate::external::overlay::vpcpeering::VpcExposeNatConfig;
use crate::internal::interfaces::interface::{InterfaceConfig, InterfaceConfigTable};
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
    fn validate(&mut self) -> ConfigResult {
        debug!(
            "Validating manifest of VPC {} in peering {}",
            self.local.name, self.name
        );
        self.local.validate()?;
        self.remote.validate()?;

        if self.local.default_expose().is_some() && self.remote.default_expose().is_some() {
            return Err(ConfigError::Forbidden(
                "A default expose cannot be peered with another default expose",
            ));
        }

        self.validate_nat_combinations()
    }

    /// Consume `self` and produce a [`ValidatedPeering`] if it passes validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the peering configuration is invalid.
    pub fn validated(mut self) -> Result<ValidatedPeering, ConfigError> {
        self.validate()?;
        Ok(ValidatedPeering(self))
    }

    fn validate_nat_combinations(&self) -> ConfigResult {
        // If stateful NAT is set up on one side of the peering, we don't support NAT (stateless or
        // stateful) on the other side.
        let mut local_has_stateless_nat = false;
        let mut local_has_stateful_nat = false;
        let mut local_has_port_forwarding = false;
        for expose in &self.local.exposes {
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

        for remote_expose in &self.remote.exposes {
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

#[repr(transparent)]
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedPeering(Peering);

impl ValidatedPeering {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0.name
    }

    #[must_use]
    pub fn local(&self) -> &ValidatedManifest {
        // SAFETY: ValidatedManifest is #[repr(transparent)] over VpcManifest.
        // A ValidatedPeering is only ever obtained from `Peering::validated`,
        // which validated the local manifest.
        #[allow(unsafe_code)]
        unsafe {
            &*(&raw const self.0.local).cast::<ValidatedManifest>()
        }
    }

    #[must_use]
    pub fn remote(&self) -> &ValidatedManifest {
        // SAFETY: ValidatedManifest is #[repr(transparent)] over VpcManifest.
        // A ValidatedPeering is only ever obtained from `Peering::validated`,
        // which validated the remote manifest.
        #[allow(unsafe_code)]
        unsafe {
            &*(&raw const self.0.remote).cast::<ValidatedManifest>()
        }
    }

    #[must_use]
    pub fn remote_id(&self) -> &VpcId {
        &self.0.remote_id
    }

    #[must_use]
    pub fn gwgroup(&self) -> Option<&String> {
        self.0.gwgroup.as_ref()
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
    fn check_peerings(&mut self) -> ConfigResult {
        debug!("Checking peerings of VPC {}...", self.name);
        for peering in &mut self.peerings {
            peering.validate()?;
        }
        Ok(())
    }

    /// Validate a [`Vpc`]
    pub(crate) fn validate(&mut self) -> ConfigResult {
        debug!("Validating config for VPC {}...", self.name);
        self.check_peering_count()?;
        self.check_peerings()?;

        // SAFETY: `ValidatedVpc` is `#[repr(transparent)]` over `Vpc`, so the cast is
        // layout-compatible. The only invariant `check_overlap_and_default` relies on is that
        // every peering's `local`/`remote` manifest has its `valexp` populated -- which is
        // exactly what `check_peerings` (via `Peering::validate` -> `VpcManifest::validate`)
        // guarantees on the line above. We are not yet returning an `&ValidatedVpc` to the
        // outside world; this view is purely internal so we can call the post-collapse overlap
        // check that lives on the validated wrapper.
        #[allow(unsafe_code)]
        let validated_vpc = unsafe {
            (&raw const *self)
                .cast::<ValidatedVpc>()
                .as_ref()
                .unwrap_or_else(|| unreachable!())
        };
        validated_vpc.check_overlap_and_default()
    }

    /// Consume `self` and produce a [`ValidatedVpc`] if it passes validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the VPC configuration is invalid.
    pub fn validated(mut self) -> Result<ValidatedVpc, ConfigError> {
        self.validate()?;
        Ok(ValidatedVpc(self))
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

    /// Provide an iterator over all peerings that have either masquerade or port-forwarding exposes locally
    pub fn local_stateful_nat_peerings(&self) -> impl Iterator<Item = &Peering> {
        self.peerings.iter().filter(|p| {
            p.local
                .exposes
                .iter()
                .any(|e| e.has_port_forwarding() || e.has_stateful_nat())
        })
    }

    /// FOR TESTS ONLY. Fake validation for the VPC peering manifests.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    #[must_use]
    pub unsafe fn fake_validated_vpc_for_tests(mut self) -> ValidatedVpc {
        for peering in &mut self.peerings {
            unsafe {
                peering.local.fake_expose_validation_for_tests();
                peering.remote.fake_expose_validation_for_tests();
            }
        }
        ValidatedVpc(self)
    }
}

#[repr(transparent)]
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedVpc(Vpc);

impl ValidatedVpc {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0.name
    }

    #[must_use]
    pub fn id(&self) -> &VpcId {
        &self.0.id
    }

    #[must_use]
    pub fn vni(&self) -> Vni {
        self.0.vni
    }

    #[must_use]
    pub fn interfaces(&self) -> &InterfaceConfigTable {
        &self.0.interfaces
    }

    #[must_use]
    pub fn peerings(&self) -> &[ValidatedPeering] {
        // SAFETY: ValidatedPeering is #[repr(transparent)] over Peering, so [Peering] and
        // [ValidatedPeering] have identical layout. Every Peering in a ValidatedVpc has been
        // validated (established by Vpc::validate, which calls Peering::validate on each element).
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts(
                self.0.peerings.as_ptr().cast::<ValidatedPeering>(),
                self.0.peerings.len(),
            )
        }
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

    #[must_use]
    pub fn inner(&self) -> &Vpc {
        &self.0
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

    /// Iterate over all of the [`Peering`]s of all [`Vpc`]s immutably
    pub fn peerings(&self) -> impl Iterator<Item = &Peering> {
        self.vpcs.values().flat_map(|vpc| vpc.peerings.iter())
    }

    /// Collect peerings for all [`Vpc`]s in this [`VpcTable`]
    pub fn collect_peerings(&mut self, peering_table: &VpcPeeringTable, idmap: &VpcIdMap) {
        debug!("Collecting peerings for all VPCs..");
        self.values_mut()
            .for_each(|vpc| vpc.set_peerings(peering_table, idmap));
    }

    /// Validate the [`VpcTable`]
    pub(crate) fn validate(&mut self) -> ConfigResult {
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
