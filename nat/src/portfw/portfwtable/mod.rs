// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding table and lookups

pub mod access;
mod display;
pub mod objects;
pub mod portrange;
pub mod setup;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PortFwTableError {
    #[error("Unsupported: {0}")]
    Unsupported(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(std::net::IpAddr),
    #[error("Invalid port: {0}")]
    InvalidPort(u16),
    #[error("Invalid port range: [{0}-{1}]")]
    InvalidPortRange(u16, u16),
    #[error("Invalid port mapping: the length of ranges {0} and {1} differ")]
    InvalidPortRangeMapping(String, String),
    #[error("Invalid port mapping: {0} overlaps with other ranges")]
    OverlappingRange(String),
    #[error("Invalid initial timeout: the minimum allowed is 1 second")]
    InvalidInitialTimeout,
    #[error("Invalid established timeout: the minimum allowed is 3 seconds")]
    InvalidEstablishedTimeout,
}
