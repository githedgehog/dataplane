// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Defines the cli protocol for the dataplane

use enum_primitive::enum_from_primitive;
use log::Level;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

/// Arguments to a cli request
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct RequestArgs {
    pub connpath: Option<String>,     /* connection path; this is local */
    pub address: Option<IpAddr>,      /* an IP address */
    pub prefix: Option<(IpAddr, u8)>, /* an IP prefix */
    pub vrf: Option<String>,          /* name of a VRF */
    pub ifname: Option<String>,       /* name of interface */
    pub loglevel: Option<Level>,      /* loglevel, from crate log */
}

/// A Cli request
#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
pub struct CliRequest {
    pub action: CliAction,
    pub args: RequestArgs,
}

#[derive(Error, Debug)]
pub enum CliSerdeError {
    #[error("Serialization error")]
    Serialize,
    #[error("Deserialization error")]
    Deserialize,
}
impl CliRequest {
    pub fn serialize(&self) -> Result<Vec<u8>, CliSerdeError> {
        bincode2::serialize(self).map_err(|_| CliSerdeError::Serialize)
    }
    pub fn deserialize(buf: &[u8]) -> Result<Self, CliSerdeError> {
        bincode2::deserialize(buf).map_err(|_| CliSerdeError::Deserialize)
    }
}
impl CliResponse {
    pub fn serialize(&self) -> Result<Vec<u8>, CliSerdeError> {
        bincode2::serialize(self).map_err(|_| CliSerdeError::Serialize)
    }
    pub fn deserialize(buf: &[u8]) -> Result<Self, CliSerdeError> {
        bincode2::deserialize(buf).map_err(|_| CliSerdeError::Deserialize)
    }
}

/// A Cli response
#[derive(Debug, Serialize, Deserialize)]
pub struct CliResponse {
    pub request: CliRequest,
    // here we would add a union for the distinct objects which
    // would need to implement Serialize & Deserialize
    // For the time being, we let the dataplane send a string, until
    // all objects are defined and implement those traits
    pub data: String,
}

#[allow(unused)]
impl CliRequest {
    pub fn new(action: CliAction, args: RequestArgs) -> Self {
        Self { action, args }
    }
}

#[allow(unused)]
impl CliResponse {
    pub fn from_request(request: CliRequest, data: String) -> Self {
        Self { request, data }
    }
}

enum_from_primitive! {
#[allow(unused)]
#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum CliAction {
    Clear,
    Connect,
    Disconnect,
    Help,
    Quit,

    Restart,
    SetLoglevel,

    // vpcs
    ShowVpc,
    ShowVpcPifs,
    ShowVpcPolicies,

    // pipelines
    ShowPipeline,
    ShowPipelineStages,
    ShowPipelineStats,

    // router
    ShowRouterInterfaces,
    ShowRouterVrfs,
    ShowRouterIpv4Routes,
    ShowRouterIpv6Routes,
    ShowRouterIpv4Addresses,
    ShowRouterIpv6Addresses,
    ShowRouterEvpnVrfs,
    ShowRouterEvpnRmacStore,

    // DPDK
    ShowDpdkPort,
    ShowDpdkPortStats,

    // kernel
    ShowKernelInterfaces,

    // nat
    ShowNatRules,
    ShowNatPortUsage,
}
}
