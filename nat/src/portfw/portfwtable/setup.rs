// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port-forwarding build configuration routines.
//! These are the functions to convert the configuration into port-forwarding rules.

use config::ConfigError;
use config::external::overlay::vpc::VpcTable;

use crate::portfw::PortFwEntry;

pub fn build_port_forwarding_configuration(
    _vpc_table: &VpcTable,
) -> Result<Vec<PortFwEntry>, ConfigError> {
    // TODO: for all Vpcs in the vpc table, check those whose peering exposes have port forwarding
    // configuration and build a collection of port-forwarding rules (`PortFwEntry`s).
    // and build the appropriate rules
    let ruleset: Vec<PortFwEntry> = vec![];

    Ok(ruleset)
}
