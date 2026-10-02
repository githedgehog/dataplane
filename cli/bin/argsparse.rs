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
#[derive(Debug, strum::Display, EnumIter, PartialEq, strum::EnumString, strum::IntoStaticStr)]
pub enum CliArgId {
    #[strum(serialize = "path")]
    Path,

    #[strum(serialize = "bind-address")]
    BindAddr,

    #[strum(serialize = "vpc")]
    Vpc,

    #[strum(serialize = "vni")]
    Vni,

    #[strum(serialize = "address")]
    Address,

    #[strum(serialize = "prefix")]
    Prefix,

    #[strum(serialize = "prefix-len")]
    PrefixLen,

    #[strum(serialize = "mac-address")]
    Mac,

    #[strum(serialize = "interface")]
    Ifname,

    #[strum(serialize = "vrfid")]
    VrfId,

    #[strum(serialize = "protocol")]
    Protocol,
}
impl CliArgId {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
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
            assert_eq!(a, CliArgId::from_str(&a.to_string()).unwrap());
        }
    }

    #[test]
    // Test uniqueness of strings. Ideally, this would be enforced at build time
    fn test_arg_string_uniqueness() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for a in CliArgId::iter() {
            assert!(set.insert(a.to_string()));
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

    #[error("Bad IP address: {0}")]
    BadAddress(String),

    #[error("Bad MAC address: {0}")]
    BadMac(String),

    #[error("Wrong prefix length {0}")]
    BadPrefixLength(u8),

    #[error("Invalid prefix length {0}")]
    InvalidPrefixLength(String),

    #[error("Bad prefix format: {0}")]
    BadPrefixFormat(String),

    #[error("Unknown argument: {0}")]
    UnknownArgument(String),

    #[error("Missing value for {0}")]
    MissingValue(CliArgId),

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

fn parse_mac(value: &str) -> Result<String, ArgsError> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6 {
        return Err(ArgsError::BadMac(value.to_owned()));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| ArgsError::BadMac(value.to_owned()))?;
    }
    Ok(value.to_owned())
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
fn parse_vni(value: &str) -> Result<u32, ArgsError> {
    let vni = value
        .parse::<u32>()
        .map_err(|_| ArgsError::BadValue(value.to_owned()))?;

    if vni != 0 && vni <= 0x00FF_FFFF {
        Ok(vni)
    } else {
        Err(ArgsError::BadValue(value.to_owned()))
    }
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
            let argid = CliArgId::from_str(arg_name)
                .map_err(|_| ArgsError::UnknownArgument(arg_name.to_owned()))?;

            // complain if value is empty
            if value.is_empty() {
                return Err(ArgsError::MissingValue(argid));
            }

            // parse value and fill args
            match argid {
                CliArgId::Path => args.connpath = Some(parse_string(value)),
                CliArgId::BindAddr => args.bind_address = Some(parse_string(value)),
                CliArgId::Vpc => args.remote.vpc = Some(parse_string(value)),
                CliArgId::Ifname => args.remote.ifname = Some(parse_string(value)),
                CliArgId::Mac => args.remote.mac = Some(parse_mac(value)?),
                CliArgId::Address => args.remote.address = Some(parse_address(value)?),
                CliArgId::Prefix => args.remote.prefix = Some(parse_prefix(value)?),
                CliArgId::PrefixLen => args.remote.prefix_len = Some(parse_prefix_len(value)?),
                CliArgId::VrfId => args.remote.vrfid = Some(parse_u32(value)?),
                CliArgId::Vni => args.remote.vni = Some(parse_vni(value)?),
                CliArgId::Protocol => args.remote.protocol = Some(parse_protocol(value)?),
            }
        }
        Ok(args)
    }
}

#[cfg(test)]
mod test_args_parsing {
    use super::{CliArgId, CliArgs};
    use std::collections::HashMap;
    use strum::IntoEnumIterator;

    #[test]
    fn test_parse_good_values() {
        let mut args_map = HashMap::new();
        for argid in CliArgId::iter() {
            let value = match argid {
                CliArgId::Path => "/tmp/foo/bar/baz",
                CliArgId::BindAddr => "/tmp/foo/bar/local",
                CliArgId::Vpc => "Vpc-1",
                CliArgId::Vni => "3000",
                CliArgId::Address => "192.168.1.1",
                CliArgId::Prefix => "10.0.1.1/28",
                CliArgId::PrefixLen => "24",
                CliArgId::Mac => "02:aa:bb:cc:dd:ee",
                CliArgId::Ifname => "eth0.100",
                CliArgId::VrfId => "1879",
                CliArgId::Protocol => "Bgp",
            }
            .to_string();
            args_map.insert(argid.to_string(), value);
        }
        CliArgs::from_args_map(&args_map).expect("Should succeed");
    }

    #[test]
    fn test_reject_bad_protocol() {
        let mut args_map = HashMap::new();
        args_map.insert(CliArgId::Protocol.to_string(), "PIMPAMPUM".to_string());
        let parsed = CliArgs::from_args_map(&args_map);
        assert!(parsed.is_err());
    }
    #[test]
    fn test_reject_bad_prefix() {
        let mut args_map = HashMap::new();
        args_map.insert(CliArgId::Prefix.to_string(), "300.0.0.1".to_string());
        let parsed = CliArgs::from_args_map(&args_map);
        assert!(parsed.is_err());
    }
    #[test]
    fn test_reject_bad_prefix_len() {
        let mut args_map = HashMap::new();
        args_map.insert(CliArgId::PrefixLen.to_string(), "129".to_string());
        let parsed = CliArgs::from_args_map(&args_map);
        assert!(parsed.is_err());
    }
    #[test]
    fn test_reject_bad_ip_address() {
        let mut args_map = HashMap::new();
        args_map.insert(CliArgId::Address.to_string(), "700.1.2.3".to_string());
        let parsed = CliArgs::from_args_map(&args_map);
        assert!(parsed.is_err());
    }
    #[test]
    fn test_reject_bad_mac_address() {
        let mut args_map = HashMap::new();
        args_map.insert(CliArgId::Mac.to_string(), "aa:bb:cc:dd".to_string());
        let parsed = CliArgs::from_args_map(&args_map);
        assert!(parsed.is_err());
    }
    #[test]
    fn test_reject_bad_vni() {
        let mut args_map = HashMap::new();
        args_map.insert(CliArgId::Vni.to_string(), "16777216".to_string());
        let parsed = CliArgs::from_args_map(&args_map);
        assert!(parsed.is_err());
    }
}
