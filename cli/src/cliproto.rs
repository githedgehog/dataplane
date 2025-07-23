// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Defines the cli protocol for the dataplane

use log::Level;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use strum::IntoEnumIterator;
use strum::{AsRefStr, EnumIter, EnumString};
use thiserror::Error;

#[derive(AsRefStr, EnumString, Debug, Clone, Serialize, Deserialize, EnumIter)]
#[strum(ascii_case_insensitive)]
pub enum RouteProtocol {
    Local,
    Connected,
    Static,
    Ospf,
    Isis,
    Bgp,
}

/// Arguments to a cli request
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct RequestArgs {
    pub address: Option<IpAddr>,         /* an IP address */
    pub prefix: Option<(IpAddr, u8)>,    /* an IP prefix */
    pub vrfid: Option<u32>,              /* Id of a VRF */
    pub vni: Option<u32>,                /* Vxlan vni */
    pub ifname: Option<String>,          /* name of interface */
    pub loglevel: Option<Level>,         /* loglevel, from crate log */
    pub protocol: Option<RouteProtocol>, /* a type of route or routing protocol */
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
    #[error("Could not find: {0}")]
    NotFound(String),
    #[error("Not supported: {0}")]
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

#[repr(u16)]
#[allow(unused)]
#[derive(Debug, Clone, Serialize, Deserialize, EnumIter)]
pub enum CliAction {
    Clear = 0,
    Connect,
    Disconnect,
    Help,
    Quit,

    SetLoglevel,

    // cpi
    ShowCpiStats,
    CpiRequestRefresh,

    // frrmi
    ShowFrrmiStats,
    ShowFrrmiLastConfig,
    FrrmiApplyLastConfig,

    // Eventlog
    RouterEventLog,

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
    ShowRouterInterfaceAddresses,
    ShowRouterVrfs,
    ShowRouterIpv4Routes,
    ShowRouterIpv6Routes,
    ShowRouterIpv4NextHops,
    ShowRouterIpv6NextHops,
    ShowRouterEvpnVrfs,
    ShowRouterEvpnRmacStore,
    ShowRouterEvpnVtep,
    ShowAdjacencies,
    ShowRouterIpv4FibEntries,
    ShowRouterIpv6FibEntries,
    ShowRouterIpv4FibGroups,
    ShowRouterIpv6FibGroups,

    // DPDK
    ShowDpdkPort,
    ShowDpdkPortStats,

    // kernel
    ShowKernelInterfaces,

    // nat
    ShowNatRules,
    ShowNatPortUsage,
}

impl CliAction {
    fn discriminant(&self) -> u16 {
        unsafe { *<*const _>::from(self).cast::<u16>() }
    }
}
impl TryFrom<u16> for CliAction {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        for a in CliAction::iter() {
            if a.discriminant() == value {
                return Ok(a);
            }
        }
        Err(())
    }
}
