// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Commonly used conversions from strings

use ipnet::{AddrParseError, IpNet, Ipv4Net};
use std::net::{IpAddr, Ipv4Addr};

/// Parse a string containing an IP address. If the string contains a mask
/// length, ignore it. On Success, returns an `IpAddr`.
///
/// # Errors
/// This function returns `AddrParseError` if the address could not be parsed.
pub fn parse_address(input: &str) -> Result<IpAddr, AddrParseError> {
    match input.parse::<IpAddr>() {
        Ok(address) => Ok(address),
        Err(_) => match input.parse::<IpNet>()? {
            IpNet::V4(a) => Ok(a.addr().into()),
            IpNet::V6(a) => Ok(a.addr().into()),
        },
    }
}

/// Parse a string containing an IPv4 address. If the string contains a mask
/// length, ignore it. On Success, returns an `Ipv4Addr`.
///
/// # Errors
/// This function returns `AddrParseError` if the address could not be parsed.
pub fn parse_address_v4(input: &str) -> Result<Ipv4Addr, AddrParseError> {
    match input.parse::<Ipv4Addr>() {
        Ok(address) => Ok(address),
        Err(_) => Ok(input.parse::<Ipv4Net>()?.addr()),
    }
}
