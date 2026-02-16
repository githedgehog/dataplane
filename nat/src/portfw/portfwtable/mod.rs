// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding table and lookups

pub mod access;
mod display;
pub mod objects;
pub mod portrange;
pub mod setup;

use objects::PortFwKey;
use std::net::IpAddr;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PortFwTableError {
    #[error("Duplicate key: {0}")]
    DuplicateKey(PortFwKey),
    #[error("Unsupported: {0}")]
    Unsupported(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(IpAddr),
    #[error("Invalid port: {0}")]
    InvalidPort(u16),
    #[error("Invalid port range: [{0}-{1}]")]
    InvalidPortRange(u16, u16),
    #[error("Invalid initial timeout: the minimum allowed is 1 second")]
    InvalidInitialTimeout,
    #[error("Invalid established timeout: the minimum allowed is 3 seconds")]
    InvalidEstablishedTimeout,
}
