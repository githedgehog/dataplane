// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds main parser for command arguments

use crate::cliproto::RequestArgs;
use log::Level;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

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
    #[error("Unrecognized arguments")]
    UnrecognizedArgs(HashMap<String, String>),
    #[error("Missing value for {0}")]
    MissingValue(&'static str),
    #[error("Unknown loglevel {0}")]
    UnknownLogLevel(String),
}

#[allow(unused)]
impl RequestArgs {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn from_args_map(mut args_map: HashMap<String, String>) -> Result<RequestArgs, ArgsError> {
        let mut args = RequestArgs::new();
        if let Some(addr) = &args_map.remove("address") {
            let address =
                IpAddr::from_str(addr).map_err(|_| ArgsError::BadPrefix(addr.to_owned()))?;
            args.address = Some(address);
        }
        if let Some(prefix) = args_map.remove("prefix") {
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
                args.prefix = Some((pfx, pxf_len));
            } else {
                return Err(ArgsError::BadPrefixFormat(prefix.to_owned()));
            }
        }
        if let Some(path) = args_map.remove("path") {
            if path.is_empty() {
                return Err(ArgsError::MissingValue("path"));
            }
            args.connpath = Some(path.clone());
        }
        if let Some(vrf) = args_map.remove("vrf") {
            if vrf.is_empty() {
                return Err(ArgsError::MissingValue("vrf"));
            }
            args.vrf = Some(vrf).clone();
        }
        if let Some(ifname) = args_map.remove("ifname") {
            if ifname.is_empty() {
                return Err(ArgsError::MissingValue("ifname"));
            }
            args.ifname = Some(ifname).clone();
        }
        if let Some(level) = args_map.remove("level") {
            if level.is_empty() {
                return Err(ArgsError::MissingValue("level"));
            } else {
                let level = level.to_uppercase();
                args.loglevel = Some(
                    Level::from_str(level.as_str())
                        .map_err(|_| ArgsError::UnknownLogLevel(level))?,
                );
            }
        }
        if !args_map.is_empty() {
            Err(ArgsError::UnrecognizedArgs(args_map))
        } else {
            Ok(args)
        }
    }
}
