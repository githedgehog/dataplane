// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod configdb;
pub mod overlay;

use thiserror::Error;

/// The reasons why we may reject a configuration
#[derive(Debug, Error, PartialEq)]
pub enum ApiError {
    #[error("A VPC with id '{0}' already exists")]
    DuplicateVpcId(String),
    #[error("A VPC peering with id '{0}' already exists")]
    DuplicateVpcPeeringId(String),
    #[error("The VPC peering '{0}' is incomplete")]
    IncompletePeeringData(String),
    #[error("A VPC peering object refers to non-existent VPC '{0}'")]
    NoSuchVpc(String),
    #[error("'{0}' is not a valid VNI")]
    InvalidVpcVni(u32),
    #[error("VNI '{0}' is already in use")]
    DuplicateVpcVni(u32),
    #[error("VPC peering name is missing")]
    MissingPeeringName,
    #[error("Config with id {0} not found")]
    NoSuchConfig(u64),
    #[error("Failure applying config")]
    FailureApply,
    #[error("Forbidden")]
    Forbidden,
    #[error("Incomplete config: missing {0} configuration")]
    IncompleteConfig(&'static str),
}
pub type ApiResult = Result<(), ApiError>;
