// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Converter for gateway-schema k8s objects to internal config

#![deny(clippy::all, clippy::pedantic)]

pub mod bgp;
pub mod device;
pub mod expose;
pub mod gateway_config;
pub mod interface;
pub mod overlay;
pub mod peering;
pub mod tracecfg;
pub mod underlay;
pub mod vpc;

use std::collections::BTreeMap;

use lpm::prefix::Prefix;

pub type SubnetMap = BTreeMap<String, Prefix>;
pub type VpcSubnetMap = BTreeMap<String, SubnetMap>;
