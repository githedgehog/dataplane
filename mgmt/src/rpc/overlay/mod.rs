// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod tests;
pub mod vpc;
pub mod vpcpeering;

use crate::rpc::overlay::vpc::VpcTable;
use crate::rpc::overlay::vpcpeering::VpcPeeringTable;

pub struct Overlay {
    pub vpc_table: VpcTable,
    pub peering_table: VpcPeeringTable,
}

impl Overlay {}
