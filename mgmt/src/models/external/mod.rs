// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod gwconfig;
pub mod overlay;

use crate::models::external::gwconfig::GenId;
use crate::models::external::overlay::vpc::VpcId;
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
    #[error("Missing identifier: {0}")]
    MissingIdentifier(&'static str),
    #[error("Missing mandatory parameter: {0}")]
    MissingParameter(&'static str),
    #[error("Frr agent is unreachable")]
    FrrAgentUnreachable,
    #[error("Internal error: {0}")]
    InternalFailure(&'static str),
}

/// Result-like type for configurations
pub type ConfigResult = Result<(), ConfigError>;

pub fn stringify(conf_result: &ConfigResult) -> String {
    match conf_result {
        Ok(()) => "Ok".to_string(),
        Err(e) => format!("FAILED: {e}"),
    }
}
