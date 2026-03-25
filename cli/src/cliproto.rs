// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Defines the cli protocol for the dataplane

use log::Level;
use std::net::IpAddr;
use strum::IntoEnumIterator;
use strum::{AsRefStr, EnumIter, EnumString};
use thiserror::Error;

/// A log level for use in CLI protocol messages.
///
/// This mirrors [`log::Level`] but implements the [`rkyv`] serialization
/// traits that `Level` itself does not provide.  Use the [`From`] /
/// [`Into`] conversions to interoperate with [`log::Level`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub enum CliLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<Level> for CliLogLevel {
    fn from(level: Level) -> Self {
        match level {
            Level::Error => Self::Error,
            Level::Warn => Self::Warn,
            Level::Info => Self::Info,
            Level::Debug => Self::Debug,
            Level::Trace => Self::Trace,
        }
    }
}

impl From<CliLogLevel> for Level {
    fn from(level: CliLogLevel) -> Self {
        match level {
            CliLogLevel::Error => Self::Error,
            CliLogLevel::Warn => Self::Warn,
            CliLogLevel::Info => Self::Info,
            CliLogLevel::Debug => Self::Debug,
            CliLogLevel::Trace => Self::Trace,
        }
    }
}

#[derive(
    AsRefStr,
    EnumString,
    Debug,
    Clone,
    EnumIter,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
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
#[derive(Debug, Default, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[allow(unused)]
pub struct RequestArgs {
    pub address: Option<IpAddr>,         /* an IP address */
    pub prefix: Option<(IpAddr, u8)>,    /* an IP prefix */
    pub vrfid: Option<u32>,              /* Id of a VRF */
    pub vni: Option<u32>,                /* Vxlan vni */
    pub ifname: Option<String>,          /* name of interface */
    pub loglevel: Option<CliLogLevel>,   /* loglevel – see [`CliLogLevel`] */
    pub protocol: Option<RouteProtocol>, /* a type of route or routing protocol */
}

/// A Cli request
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
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

/// Convenience trait for serializing / deserializing CLI protocol messages
/// using [`rkyv`].
pub trait CliSerialize: Sized {
    /// Serialize `self` into a byte vector.
    fn serialize(&self) -> Result<Vec<u8>, CliSerdeError>;

    /// Deserialize an instance from a byte slice.
    fn deserialize(buf: &[u8]) -> Result<Self, CliSerdeError>;
}

/// Implement [`CliSerialize`] for one or more types that already derive the
/// required `rkyv` traits.
macro_rules! impl_cli_serialize {
    ($($t:ty),+ $(,)?) => {
        $(
            impl CliSerialize for $t {
                fn serialize(&self) -> Result<Vec<u8>, CliSerdeError> {
                    rkyv::to_bytes::<rkyv::rancor::Error>(self)
                        .map(|aligned| aligned.to_vec())
                        .map_err(|_| CliSerdeError::Serialize)
                }

                fn deserialize(buf: &[u8]) -> Result<Self, CliSerdeError> {
                    rkyv::from_bytes::<Self, rkyv::rancor::Error>(buf)
                        .map_err(|_| CliSerdeError::Deserialize)
                }
            }
        )+
    };
}

impl_cli_serialize!(CliRequest, CliResponse);

#[derive(Error, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum CliError {
    #[error("Internal error")]
    InternalError,
    #[error("Could not find: {0}")]
    NotFound(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
}

/// A Cli response
#[derive(Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
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
#[derive(Debug, Clone, EnumIter, PartialEq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum CliAction {
    Clear = 0,
    Connect,
    Disconnect,
    Help,
    Quit,

    // config
    ShowConfigSummary,

    // config: gateways & communities
    ShowGatewayGroups,
    ShowGatewayCommunities,

    // config: tracing
    ShowTracingTargets,
    ShowTracingTagGroups,

    // config: vpcs & peerings
    ShowVpc,
    ShowVpcPeerings,

    // router: Eventlog
    RouterEventLog,

    // router: cpi
    ShowCpiStats,
    CpiRequestRefresh,

    // router: frrmi
    ShowFrrmiStats,
    ShowFrrmiLastConfig,
    FrrmiApplyLastConfig,

    // router: internal state
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

    // NF: nat
    ShowPortForwarding,
    ShowStaticNat,
    ShowMasquerading,

    // NF: flow table
    ShowFlowTable,

    // NF: flow filter
    ShowFlowFilter,

    // internal config
    ShowConfigInternal,

    ShowTech,

    /* == Not supported yet == */
    // pipelines
    ShowPipeline,
    ShowPipelineStages,
    ShowPipelineStats,

    // kernel
    ShowKernelInterfaces,

    // DPDK
    ShowDpdkPort,
    ShowDpdkPortStats,

    // loglevel
    SetLoglevel,
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