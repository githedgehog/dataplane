// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT internal models: tables for NAT rules
//!
//! This module provides the internal models for NAT rules, including the code to build the rule
//! tables from a configuration object

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]

mod collapse;
mod range_builder;

use crate::external::overlay::vpc::{Peering, VpcTable};
use crate::external::overlay::vpcpeering::VpcExpose;
use lpm::prefix::Prefix;
use nat::stateless::config::tables::{NatPrefixRuleTable, NatTableValue, PerVniTable};
use net::vxlan::Vni;
use std::collections::BTreeSet;

/// Error type for NAT peering table extension operations.
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
    vni: Vni,
    prefixes_to_update: &'a BTreeSet<Prefix>,
    prefixes_to_point_to: &'a BTreeSet<Prefix>,
) -> impl Iterator<Item = Result<NatTableValue, NatPeeringError>> {
    range_builder::RangeBuilder::<'a>::new(vni, prefixes_to_update, prefixes_to_point_to)
}

fn generate_public_values(
    vni: Vni,
    expose: &VpcExpose,
) -> impl Iterator<Item = Result<NatTableValue, NatPeeringError>> {
    generate_nat_values(vni, &expose.ips, &expose.as_range)
}

fn generate_private_values(
    vni: Vni,
    expose: &VpcExpose,
) -> impl Iterator<Item = Result<NatTableValue, NatPeeringError>> {
    generate_nat_values(vni, &expose.as_range, &expose.ips)
}

// Note: add_peering(table, peering) should be part of PerVniTable, but we prefer to keep it in a
// separate submodule because it relies on definitions from the external models, unlike the rest of
// the PerVniTable implementation.
//
/// Add a [`Peering`] to a [`PerVniTable`]
///
/// # Errors
///
/// Returns an error if some lists of prefixes contain duplicates
pub fn add_peering(
    table: &mut PerVniTable,
    peering: &Peering,
    vpc_table: &VpcTable,
) -> Result<(), NatPeeringError> {
    let new_peering = collapse::collapse_prefixes_peering(peering)?;

    let mut local_expose_indices = vec![];

    new_peering.local.exposes.iter().try_for_each(|expose| {
        if expose.as_range.is_empty() {
            // Nothing to do for source NAT, get out of here
            return Ok(());
        }
        // Create new peering table for source NAT
        let mut peering_table = NatPrefixRuleTable::new();

        // For each private prefix, add an entry containing the set of public prefixes
        generate_public_values(table.vni, expose).try_for_each(|value| {
            peering_table
                .insert(&value?)
                .map_err(|_| NatPeeringError::EntryExists)
        })?;

        // Add peering table to PerVniTable
        table.src_nat_prefixes.push(peering_table);
        local_expose_indices.push(table.src_nat_prefixes.len() - 1);
        Ok(())
    })?;

    /* get vni for remote manifest */
    let remote_vni = vpc_table
        .get_vpc_by_vpcid(&new_peering.remote_id)
        .unwrap_or_else(|| unreachable!())
        .vni;

    // Update table for destination NAT
    new_peering.remote.exposes.iter().try_for_each(|expose| {
        // For each public prefix, add an entry containing the set of private prefixes
        generate_private_values(remote_vni, expose).try_for_each(|value| {
            table
                .dst_nat
                .insert(&value?)
                .map_err(|_| NatPeeringError::EntryExists)
        })?;

        // Update peering table to make relevant prefixes point to the new peering table, for each
        // private prefix.
        //
        // Note that the public IPs are not always from the as_range list: if this list is empty,
        // then there's no NAT required for the expose, meaning that the public IPs are those from
        // the "ips" list.
        let remote_public_prefixes = expose.public_ips();
        remote_public_prefixes.iter().try_for_each(|prefix| {
            table
                .src_nat_peers
                .rules
                .insert(prefix, local_expose_indices.clone())
                .map_err(|_| NatPeeringError::EntryExists)
        })
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external::overlay::vpc::Vpc;
    use crate::external::overlay::vpcpeering::VpcManifest;
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

        let vni = Vni::new_checked(100).unwrap();
        let mut vpctable = VpcTable::new();
        let mut vpc = Vpc::new("VPC", "12345", vni.as_u32()).unwrap();
        vpc.peerings.push(peering.clone());
        vpctable.add(vpc);

        let mut vni_table = PerVniTable::new(vni);
        add_peering(&mut vni_table, &peering, &vpctable).expect("Failed to build NAT tables");
    }
}
