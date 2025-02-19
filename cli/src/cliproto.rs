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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub trait CliSerialize {
    fn serialize(&self) -> Result<Vec<u8>, CliSerdeError>
    where
        Self: Serialize,
    {
        bincode2::serialize(self).map_err(|_| CliSerdeError::Serialize)
    }
    fn serialized_size(&self) -> Result<u64, CliSerdeError>
    where
        Self: Serialize,
    {
        bincode2::serialized_size(self).map_err(|_| CliSerdeError::Serialize)
    }
    fn deserialize<'a>(buf: &'a [u8]) -> Result<Self, CliSerdeError>
    where
        Self: Deserialize<'a>,
    {
        bincode2::deserialize(buf).map_err(|_| CliSerdeError::Deserialize)
    }
}

impl CliSerialize for CliRequest {}
impl CliSerialize for CliResponse {}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum CliError {
    #[error("Internal error")]
    InternalError,
    #[error("Could not find {0}")]
    NotFound(String),
    #[error("Not supported")]
    NotSupported(String),
}

/// A Cli response
#[derive(Debug, Serialize, Deserialize)]
pub struct CliResponse {
    pub request: CliRequest,
    // here we would add a union for the distinct objects which
    // would need to implement Serialize & Deserialize, or , maybe
    // pass a trait object implementing some sort of Serde.
    // For the time being, we let the dataplane send a string, until
    // all objects are defined and implement those traits.
    pub result: Result<String, CliError>,
}

#[allow(unused)]
impl CliRequest {
    pub fn new(action: CliAction, args: RequestArgs) -> Self {
        Self { action, args }
    }
}

#[allow(unused)]
impl CliResponse {
    pub fn from_request_ok(request: CliRequest, data: String) -> Self {
        Self {
            request,
            result: Ok(data),
        }
    }
    pub fn from_request_fail(request: CliRequest, error: CliError) -> Self {
        Self {
            request,
            result: Err(error),
        }
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
