// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Errors which may occur when parsing a network address.

use std::net::IpAddr;
use thiserror;

/// An error which may occur when parsing a network address.
#[derive(thiserror::Error, Debug)]
pub enum AddrParseError {
    /// A multicast IP address was parsed but is not allowed
    #[error("Multicast IP address not allowed: {0}")]
    IpMulticastAddressNotAllowed(IpAddr),
    /// An error occurred in the `std::net` parser while parsing an address
    #[error(transparent)]
    StdAddrParseError(std::net::AddrParseError),
}
