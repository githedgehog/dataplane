// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds main parser for command arguments

use dataplane_cli::cliproto::{RequestArgs, RouteProtocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use strum::EnumIter;
use thiserror::Error;

// The identifier for a certain argument
#[derive(Debug, EnumIter, PartialEq)]
pub enum CliArgId {
    Path,
    BindAddr,
    Vpc,
    Vni,
    Address,
    Prefix,
    Mac,
    Ifname,
    VrfId,
    Protocol,
}
impl CliArgId {
    // N.B. strings should be different for proper parsing
    pub const ARG_PATH: &str = "path";
    pub const ARG_BIND_ADDR: &str = "bind-address";
    pub const ARG_VPC: &str = "vpc";
    pub const ARG_VNI: &str = "vni";
    pub const ARG_ADDRESS: &str = "address";
    pub const ARG_PREFIX: &str = "prefix";
    pub const ARG_MAC: &str = "mac-address";
    pub const ARG_IFNAME: &str = "interface";
    pub const ARG_VRFID: &str = "vrfid";
    pub const ARG_PROTOCOL: &str = "protocol";

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Path => Self::ARG_PATH,
            Self::BindAddr => Self::ARG_BIND_ADDR,
            Self::Vpc => Self::ARG_VPC,
            Self::Vni => Self::ARG_VNI,
            Self::Address => Self::ARG_ADDRESS,
            Self::Prefix => Self::ARG_PREFIX,
            Self::Mac => Self::ARG_MAC,
            Self::Ifname => Self::ARG_IFNAME,
            Self::VrfId => Self::ARG_VRFID,
            Self::Protocol => Self::ARG_PROTOCOL,
        }
    }
}

impl FromStr for CliArgId {
    type Err = ArgsError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            Self::ARG_PATH => Ok(Self::Path),
            Self::ARG_BIND_ADDR => Ok(Self::BindAddr),
            Self::ARG_VPC => Ok(Self::Vpc),
            Self::ARG_VNI => Ok(Self::Vni),
            Self::ARG_ADDRESS => Ok(Self::Address),
            Self::ARG_PREFIX => Ok(Self::Prefix),
            Self::ARG_MAC => Ok(Self::Mac),
            Self::ARG_IFNAME => Ok(Self::Ifname),
            Self::ARG_VRFID => Ok(Self::VrfId),
            Self::ARG_PROTOCOL => Ok(Self::Protocol),
            _ => Err(ArgsError::UnknownArgument(value.to_string())),
        }
    }
}

#[cfg(test)]
mod test {
    use super::CliArgId;
    use std::str::FromStr;
    use strum::IntoEnumIterator;

    #[test]
    // Test biject
    fn test_arg_conversion() {
        for a in CliArgId::iter() {
            assert_eq!(a, CliArgId::from_str(a.as_str()).unwrap());
        }
    }

    #[test]
    // Test uniqueness of strings. Ideally, this would be enforced at build time
    fn test_arg_string_uniqueness() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for a in CliArgId::iter() {
            assert!(set.insert(a.as_str()));
        }
    }
}

/// Errors when parsing arguments
#[derive(Error, Debug)]
pub enum ArgsError {
    #[error("Parse failure: {0}")]
    ParseFailure(String),

    #[error("Bad prefix: {0}")]
    BadPrefix(String),

    #[error("Wrong prefix length {0}")]
    BadPrefixLength(u8),

    #[error("Bad prefix format: {0}")]
    BadPrefixFormat(String),

    #[error("Unknown argument: {0}")]
    UnknownArgument(String),

    #[error("Unrecognized arguments")]
    UnrecognizedArgs(HashMap<String, String>),

    #[error("Missing value for {0}")]
    MissingValue(&'static str),

    #[error("Bad value {0}")]
    BadValue(String),

    #[error("Unknown protocol '{0}'")]
    UnknownProtocol(String),
}

#[derive(Default, Debug)]
pub struct CliArgs {
    pub connpath: Option<String>,     /* connection path; this is local */
    pub bind_address: Option<String>, /* address to bind unix sock to */
    pub remote: RequestArgs,          /* args to send to remote. These get serialized */
}

#[allow(unused)]
impl CliArgs {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn from_args_map(mut args_map: HashMap<String, String>) -> Result<CliArgs, ArgsError> {
        let mut args = CliArgs::new();
        if let Some(addr) = &args_map.remove(CliArgId::ARG_ADDRESS) {
            let address =
                IpAddr::from_str(addr).map_err(|_| ArgsError::BadPrefix(addr.to_owned()))?;
            args.remote.address = Some(address);
        }
        if let Some(mac) = &args_map.remove(CliArgId::ARG_MAC) {
            args.remote.mac = Some(mac.to_owned());
        }
        if let Some(prefix) = args_map.remove(CliArgId::ARG_PREFIX) {
            if let Some((addr, len)) = prefix.split_once('/') {
                let pfx =
                    IpAddr::from_str(addr).map_err(|_| ArgsError::BadPrefix(addr.to_owned()))?;
                let max_len = match pfx {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                let pxf_len: u8 = len
                    .parse::<u8>()
                    .map_err(|_| ArgsError::ParseFailure(len.to_owned()))?;
                if pxf_len > max_len {
                    return Err(ArgsError::BadPrefixLength(pxf_len));
                }
                args.remote.prefix = Some((pfx, pxf_len));
            } else {
                return Err(ArgsError::BadPrefixFormat(prefix.clone()));
            }
        }
        if let Some(path) = args_map.remove(CliArgId::ARG_PATH) {
            if path.is_empty() {
                return Err(ArgsError::MissingValue(CliArgId::ARG_PATH));
            }
            args.connpath = Some(path.clone());
        }
        if let Some(path) = args_map.remove(CliArgId::ARG_BIND_ADDR) {
            if path.is_empty() {
                return Err(ArgsError::MissingValue(CliArgId::ARG_BIND_ADDR));
            }
            args.bind_address = Some(path.clone());
        }
        if let Some(vrfid) = args_map.remove(CliArgId::ARG_VRFID) {
            if vrfid.is_empty() {
                return Err(ArgsError::MissingValue(CliArgId::ARG_VRFID));
            }
            args.remote.vrfid = Some(
                vrfid
                    .parse::<u32>()
                    .map_err(|_| ArgsError::BadValue(vrfid))?,
            );
        }
        if let Some(vpcname) = args_map.remove(CliArgId::ARG_VPC) {
            if vpcname.is_empty() {
                return Err(ArgsError::MissingValue(CliArgId::ARG_VPC));
            }
            args.remote.vpc = Some(vpcname);
        }
        if let Some(vni) = args_map.remove(CliArgId::ARG_VNI) {
            if vni.is_empty() {
                return Err(ArgsError::MissingValue(CliArgId::ARG_VNI));
            }
            args.remote.vni = Some(vni.parse::<u32>().map_err(|_| ArgsError::BadValue(vni))?);
        }
        if let Some(ifname) = args_map.remove(CliArgId::ARG_IFNAME) {
            if ifname.is_empty() {
                return Err(ArgsError::MissingValue(CliArgId::ARG_IFNAME));
            }
            args.remote.ifname.clone_from(&Some(ifname));
        }
        if let Some(protocol) = args_map.remove(CliArgId::ARG_PROTOCOL) {
            if protocol.is_empty() {
                return Err(ArgsError::MissingValue(CliArgId::ARG_PROTOCOL));
            }
            args.remote.protocol = Some(
                RouteProtocol::from_str(&protocol)
                    .map_err(|_| ArgsError::UnknownProtocol(protocol))?,
            );
        }
        if args_map.is_empty() {
            Ok(args)
        } else {
            Err(ArgsError::UnrecognizedArgs(args_map))
        }
    }
}
