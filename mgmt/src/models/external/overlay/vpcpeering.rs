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
            return Err(ConfigError::MissingIdentifier("Peering name"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use iptrie::Ipv4Prefix;
    use std::str::FromStr;

    fn prefix_v4(s: &str) -> Prefix {
        Ipv4Prefix::from_str(s).expect("Invalid IPv4 prefix").into()
    }

    #[test]
    fn test_manifest_expose() {
        let expose1 = VpcExpose::empty()
            .ip(prefix_v4("1.1.0.0/16"))
            .not(prefix_v4("1.1.5.0/24"))
            .not(prefix_v4("1.1.3.0/24"))
            .not(prefix_v4("1.1.1.0/24"))
            .ip(prefix_v4("1.2.0.0/16"))
            .not(prefix_v4("1.2.2.0/24"))
            .as_range(prefix_v4("2.2.0.0/16"))
            .not_as(prefix_v4("2.1.10.0/24"))
            .not_as(prefix_v4("2.1.1.0/24"))
            .not_as(prefix_v4("2.1.8.0/24"))
            .not_as(prefix_v4("2.1.2.0/24"))
            .as_range(prefix_v4("2.1.0.0/16"));
        let expose2 = VpcExpose::empty()
            .ip(prefix_v4("3.0.0.0/16"))
            .as_range(prefix_v4("4.0.0.0/16"));

        let mut manifest1 = VpcManifest::new("test_manifest1");
        manifest1.add_expose(expose1).expect("Failed to add expose");
        manifest1.add_expose(expose2).expect("Failed to add expose");

        let expose3 = VpcExpose::empty()
            .ip(prefix_v4("8.0.0.0/17"))
            .not(prefix_v4("8.0.0.0/24"))
            .ip(prefix_v4("9.0.0.0/17"))
            .as_range(prefix_v4("3.0.0.0/16"))
            .not_as(prefix_v4("3.0.1.0/24"));
        let expose4 = VpcExpose::empty()
            .ip(prefix_v4("10.0.0.0/16"))
            .not(prefix_v4("10.0.1.0/24"))
            .not(prefix_v4("10.0.2.0/24"))
            .as_range(prefix_v4("1.1.0.0/17"))
            .as_range(prefix_v4("1.2.0.0/17"))
            .not_as(prefix_v4("1.2.0.0/24"))
            .not_as(prefix_v4("1.2.8.0/24"));

        let mut manifest2 = VpcManifest::new("test_manifest2");
        manifest2.add_expose(expose3).expect("Failed to add expose");
        manifest2.add_expose(expose4).expect("Failed to add expose");

        let peering = VpcPeering::new("test_peering", manifest1.clone(), manifest2.clone());

        assert_eq!(
            peering.get_peering_manifests("test_manifest1"),
            (&manifest1, &manifest2)
        );
    }

    #[test]
    fn test_validate_peering() {
        let mut manifest1 = VpcManifest::new("test_manifest1");
        manifest1
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .as_range(prefix_v4("2.0.0.0/16")),
            )
            .expect("Failed to add expose");
        let mut manifest2 = VpcManifest::new("test_manifest2");
        manifest2
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("192.168.1.0/24"))
                    .as_range(prefix_v4("192.168.8.0/24")),
            )
            .expect("Failed to add expose");
        let peering = VpcPeering::new("test_peering", manifest1.clone(), manifest2.clone());
        assert_eq!(peering.validate(), Ok(()));
        assert_eq!(peering.name, "test_peering");
        assert_eq!(peering.left.name, "test_manifest1");
        assert_eq!(peering.right.name, "test_manifest2");

        // Incorrect: Missing peering name
        let peering = VpcPeering::new("", manifest1.clone(), manifest2.clone());
        assert_eq!(
            peering.validate(),
            Err(ConfigError::MissingIdentifier("Peering name"))
        );
    }

    #[test]
    fn test_peering_table_add() {
        let mut manifest1 = VpcManifest::new("VPC-1");
        manifest1
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .as_range(prefix_v4("2.0.0.0/16")),
            )
            .expect("Failed to add expose");
        let mut manifest2 = VpcManifest::new("VPC-2");
        manifest2
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("192.168.1.0/24"))
                    .as_range(prefix_v4("192.168.8.0/24")),
            )
            .expect("Failed to add expose");
        let mut table = VpcPeeringTable::new();
        let peering = VpcPeering::new("test_peering1", manifest1.clone(), manifest2.clone());
        assert_eq!(table.add(peering.clone()), Ok(()));
        assert_eq!(table.len(), 1);

        // Incorrect: Duplicate peering name
        let mut manifest3 = VpcManifest::new("VPC-3");
        manifest3
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("3.0.0.0/16"))
                    .as_range(prefix_v4("4.0.0.0/16")),
            )
            .expect("Failed to add expose");
        let mut manifest4 = VpcManifest::new("VPC-4");
        manifest4
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("5.0.0.0/16"))
                    .as_range(prefix_v4("6.0.0.0/16")),
            )
            .expect("Failed to add expose");

        let peering3 = VpcPeering::new("test_peering1", manifest3.clone(), manifest4.clone());
        assert_eq!(
            table.add(peering3),
            Err(ConfigError::DuplicateVpcPeeringId(
                "test_peering1".to_string()
            ))
        );

        let peering4 = VpcPeering::new("test_peering4", manifest3.clone(), manifest4.clone());
        assert_eq!(table.add(peering4), Ok(()));
        assert_eq!(table.len(), 2);
    }
}
