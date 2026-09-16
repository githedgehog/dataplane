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
    PrefixLen,
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
    pub const ARG_PREFIX_LEN: &str = "prefix-len";
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
            Self::PrefixLen => Self::ARG_PREFIX_LEN,
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
            Self::ARG_PREFIX_LEN => Ok(Self::PrefixLen),
            Self::ARG_MAC => Ok(Self::Mac),
            Self::ARG_IFNAME => Ok(Self::Ifname),
            Self::ARG_VRFID => Ok(Self::VrfId),
            Self::ARG_PROTOCOL => Ok(Self::Protocol),
            _ => Err(ArgsError::UnknownArgument(value.to_owned())),
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

    #[error("Bad address: {0}")]
    BadAddress(String),

    #[error("Wrong prefix length {0}")]
    BadPrefixLength(u8),

    #[error("Invalid prefix length {0}")]
    InvalidPrefixLength(String),

    #[error("Bad prefix format: {0}")]
    BadPrefixFormat(String),

    #[error("Unknown argument: {0}")]
    UnknownArgument(String),

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

fn parse_string(value: &str) -> String {
    value.to_owned()
}
fn parse_address(value: &String) -> Result<IpAddr, ArgsError> {
    let address = IpAddr::from_str(value).map_err(|_| ArgsError::BadAddress(value.to_owned()))?;
    Ok(address)
}
fn parse_prefix(value: &str) -> Result<(IpAddr, u8), ArgsError> {
    if let Some((addr, len)) = value.split_once('/') {
        let pfx = IpAddr::from_str(addr).map_err(|_| ArgsError::BadPrefix(addr.to_owned()))?;
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
        Ok((pfx, pxf_len))
    } else {
        Err(ArgsError::BadPrefixFormat(value.to_owned()))
    }
}
fn parse_prefix_len(value: &str) -> Result<u8, ArgsError> {
    let plen = value
        .parse::<u8>()
        .map_err(|_| ArgsError::InvalidPrefixLength(value.to_owned()))?;

    // we don't know the version here (but surely this can't exceed 128)
    // Dataplane will complain if len > 32 and version is  ipv4
    if plen > 128 {
        return Err(ArgsError::InvalidPrefixLength(value.to_owned()));
    }
    Ok(plen)
}
fn parse_u32(value: &str) -> Result<u32, ArgsError> {
    value
        .parse::<u32>()
        .map_err(|_| ArgsError::BadValue(value.to_owned()))
}
fn parse_protocol(value: &str) -> Result<RouteProtocol, ArgsError> {
    RouteProtocol::from_str(value).map_err(|_| ArgsError::UnknownProtocol(value.to_owned()))
}

#[allow(unused)]
impl CliArgs {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn from_args_map(args_map: &HashMap<String, String>) -> Result<CliArgs, ArgsError> {
        let mut args = CliArgs::new();

        // parse each of the args in the input map and, on success, fill in the args for the request
        for (arg_name, value) in args_map {
            // convert arg name to code
            let argid = CliArgId::from_str(arg_name.as_str())?;

            // complain if value is empty
            if value.is_empty() {
                return Err(ArgsError::MissingValue(argid.as_str()));
            }

            // parse value and fill args
            match argid {
                CliArgId::Path => args.connpath = Some(parse_string(value)),
                CliArgId::BindAddr => args.bind_address = Some(parse_string(value)),
                CliArgId::Vpc => args.remote.vpc = Some(parse_string(value)),
                CliArgId::Ifname => args.remote.ifname = Some(parse_string(value)),
                CliArgId::Mac => args.remote.mac = Some(parse_string(value)),

                CliArgId::Address => args.remote.address = Some(parse_address(value)?),
                CliArgId::Prefix => args.remote.prefix = Some(parse_prefix(value)?),
                CliArgId::PrefixLen => args.remote.prefix_len = Some(parse_prefix_len(value)?),
                CliArgId::VrfId => args.remote.vrfid = Some(parse_u32(value)?),
                CliArgId::Vni => args.remote.vni = Some(parse_u32(value)?),
                CliArgId::Protocol => args.remote.protocol = Some(parse_protocol(value)?),
            }
        }
        Ok(args)
    }
}
