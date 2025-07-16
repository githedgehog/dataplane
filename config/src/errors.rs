// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Type for configuration / validation failures
//! Any result returned by the validation or configuration builder methods returned
//! in this crate is a `ConfigError`.

use std::net::IpAddr;

use crate::external::GenId;
use crate::external::overlay::vpc::VpcId;
use crate::external::overlay::vpcpeering::VpcExpose;

use lpm::prefix::{Prefix, PrefixSize};
use net::eth::mac::Mac;
use thiserror::Error;

/// The reasons why we may reject a configuration
#[derive(Debug, Error, PartialEq)]
pub enum ConfigError {
    #[error("A VPC with name '{0}' already exists")]
    DuplicateVpcName(String),
    #[error("A VPC with id '{0}' already exists")]
    DuplicateVpcId(VpcId),
    #[error("VNI '{0}' is already in use")]
    DuplicateVpcVni(u32),
    #[error("A VPC peering with id '{0}' already exists")]
    DuplicateVpcPeeringId(String),
    #[error("Peering '{0}' refers to a VPC for which a peering already exists")]
    DuplicateVpcPeerings(String),
    #[error("A VPC peering object refers to non-existent VPC '{0}'")]
    NoSuchVpc(String),
    #[error("'{0}' is not a valid VNI")]
    InvalidVpcVni(u32),
    #[error("Config with id {0} not found")]
    NoSuchConfig(GenId),
    #[error("A config with id {0} already exists")]
    ConfigAlreadyExists(GenId),
    #[error("Failure applying config: {0}")]
    FailureApply(String),
    #[error("Forbidden: {0}")]
    Forbidden(&'static str),
    #[error("Bad VPC Id")]
    BadVpcId(String),
    #[error("Bad VTEP local address {0}: {1}")]
    BadVtepLocalAddress(IpAddr, &'static str),
    #[error("Bad VTEP mac address {0}: {1}")]
    BadVtepMacAddress(Mac, &'static str),
    #[error("Missing identifier: {0}")]
    MissingIdentifier(&'static str),
    #[error("Missing mandatory parameter: {0}")]
    MissingParameter(&'static str),
    #[error("Multiple instances of {0} found, expected {1}")]
    TooManyInstances(&'static str, usize),
    #[error("Internal error: {0}")]
    InternalFailure(String),
    #[error("MTU out of range [68, 65535]: {0}")]
    BadMtu(u32),

    // Peering and VpcExpose validation
    #[error("All prefixes are excluded in VpcExpose: {0}")]
    ExcludedAllPrefixes(VpcExpose),
    #[error("Exclusion prefix {0} not contained within existing allowed prefix")]
    OutOfRangeExclusionPrefix(Prefix),
    #[error("VPC prefixes overlap: {0} and {1}")]
    OverlappingPrefixes(Prefix, Prefix),
    #[error("Inconsistent IP version in VpcExpose: {0}")]
    InconsistentIpVersion(VpcExpose),
    // NAT-specific
    #[error("Mismatched prefixes sizes for static NAT: {0:?} and {1:?}")]
    MismatchedPrefixSizes(PrefixSize, PrefixSize),

    // Interface addresses
    #[error("Invalid interface address format: {0}")]
    InvalidFormat(String),
    #[error("Invalid IP address interface address: {0}")]
    InvalidIpAddress(String),
    #[error("Invalid mask length in interface address: {0}")]
    InvalidMaskLength(String),
}

/// Result-like type for configurations
pub type ConfigResult = Result<(), ConfigError>;

#[must_use]
pub fn stringify(conf_result: &ConfigResult) -> String {
    match conf_result {
        Ok(()) => "Ok".to_string(),
        Err(e) => format!("FAILED: {e}"),
    }
}
