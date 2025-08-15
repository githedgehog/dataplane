// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless NAT configuration model

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(clippy::missing_errors_doc)]

pub mod range_builder;
pub mod tables;

use crate::stateless::NatTableValue;
use crate::stateless::NatTables;
use crate::stateless::PerVniTable;

use config::ConfigError;
use config::external::overlay::vpc::Peering;
use config::external::overlay::vpc::VpcTable;
use config::external::overlay::vpcpeering::VpcExpose;
use config::utils::{ConfigUtilError, collapse_prefixes_peering};

use lpm::prefix::Prefix;
use net::vxlan::Vni;
use std::collections::BTreeSet;

#[derive(thiserror::Error, Debug, Clone)]
pub enum NatPeeringError {
    #[error("entry already exists")]
    EntryExists,
    #[error("failed to split prefix {0}")]
    SplitPrefixError(Prefix),
    #[error("malformed peering")]
    MalformedPeering,
}

fn generate_nat_values<'a>(
    prefixes_to_update: &'a BTreeSet<Prefix>,
    prefixes_to_point_to: &'a BTreeSet<Prefix>,
) -> impl Iterator<Item = Result<NatTableValue, NatPeeringError>> {
    range_builder::RangeBuilder::<'a>::new(prefixes_to_update, prefixes_to_point_to)
}

fn generate_public_values(
    expose: &VpcExpose,
) -> impl Iterator<Item = Result<NatTableValue, NatPeeringError>> {
    generate_nat_values(&expose.ips, &expose.as_range)
}

fn generate_private_values(
    expose: &VpcExpose,
) -> impl Iterator<Item = Result<NatTableValue, NatPeeringError>> {
    generate_nat_values(&expose.as_range, &expose.ips)
}

impl PerVniTable {
    /// Add a [`Peering`] to a [`PerVniTable`]
    ///
    /// # Errors
    ///
    /// Returns an error if some lists of prefixes contain duplicates
    pub(crate) fn add_peering(
        &mut self,
        peering: &Peering,
        dst_vni: Vni,
    ) -> Result<(), NatPeeringError> {
        let new_peering = collapse_prefixes_peering(peering).map_err(|e| match e {
            ConfigUtilError::SplitPrefixError(prefix) => NatPeeringError::SplitPrefixError(prefix),
        })?;

        new_peering.local.exposes.iter().try_for_each(|expose| {
            if expose.as_range.is_empty() {
                // Nothing to do for source NAT, get out of here
                return Ok(());
            }

            // If we don't have a NAT rules table for this destination VPC already, create it
            let peering_table = self.src_nat.entry(dst_vni).or_default();

            // For each private prefix, add an entry containing the set of public prefixes
            generate_public_values(expose).try_for_each(|value| {
                peering_table
                    .insert(&value?)
                    .map_err(|_| NatPeeringError::EntryExists)
            })
        })?;

        // Update table for destination NAT
        new_peering.remote.exposes.iter().try_for_each(|expose| {
            // For each public prefix, add an entry containing the set of private prefixes
            generate_private_values(expose).try_for_each(|value| {
                self.dst_nat
                    .insert(&value?)
                    .map_err(|_| NatPeeringError::EntryExists)
            })
        })?;

        Ok(())
    }
}

/// Main function to build the NAT configuration (`NatTables`) for a given `Overlay` configuration.
pub fn build_nat_configuration(vpc_table: &VpcTable) -> Result<NatTables, ConfigError> {
    let mut nat_tables = NatTables::new();
    for vpc in vpc_table.values() {
        let mut table = PerVniTable::new(vpc.vni);
        for peering in &vpc.peerings {
            let dst_vni = vpc_table.get_remote_vni(peering);
            table
                .add_peering(peering, dst_vni)
                .map_err(|e| ConfigError::FailureApply(e.to_string()))?;
        }
        nat_tables.add_table(table);
    }
    Ok(nat_tables)
}
#[cfg(test)]
mod tests {
    use super::*;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::VpcManifest;
    use net::vxlan::Vni;

    #[test]
    fn test_fabric() {
        let expose1 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .not("1.1.5.0/24".into())
            .not("1.1.3.0/24".into())
            .not("1.1.1.0/24".into())
            .ip("1.2.0.0/16".into())
            .not("1.2.2.0/24".into())
            .as_range("2.2.0.0/16".into())
            .not_as("2.1.10.0/24".into())
            .not_as("2.1.1.0/24".into())
            .not_as("2.1.8.0/24".into())
            .not_as("2.1.2.0/24".into())
            .as_range("2.1.0.0/16".into());
        let expose2 = VpcExpose::empty()
            .ip("3.0.0.0/16".into())
            .as_range("4.0.0.0/16".into());

        let mut manifest1 = VpcManifest::new("VPC-1");
        manifest1.add_expose(expose1).expect("Failed to add expose");
        manifest1.add_expose(expose2).expect("Failed to add expose");

        let expose3 = VpcExpose::empty()
            .ip("1::/64".into())
            .not("1::/128".into())
            .as_range("1:1::/64".into())
            .not_as("1:1::/128".into());
        let expose4 = VpcExpose::empty()
            .ip("2::/64".into())
            .not("2::/128".into())
            .as_range("2:4::/64".into())
            .not_as("2:4::/128".into());

        let mut manifest2 = VpcManifest::new("VPC-2");
        manifest2.add_expose(expose3).expect("Failed to add expose");
        manifest2.add_expose(expose4).expect("Failed to add expose");

        let peering: Peering = Peering {
            name: "test_peering".into(),
            local: manifest1,
            remote: manifest2,
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
        };

        let src_vni = Vni::new_checked(100).unwrap();
        let dst_vni = Vni::new_checked(200).unwrap();
        let mut vpctable = VpcTable::new();
        let mut src_vpc = Vpc::new("VPC", "12345", src_vni.as_u32()).unwrap();
        src_vpc.peerings.push(peering.clone());
        vpctable.add(src_vpc).unwrap();

        let mut vni_table = PerVniTable::new(src_vni);
        vni_table
            .add_peering(&peering, dst_vni)
            .expect("Failed to build NAT tables");
    }
}
