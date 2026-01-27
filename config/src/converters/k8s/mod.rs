// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Converter for gateway-schema k8s objects to internal config and status

pub mod config;
pub mod status;

use crate::ConfigError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FromK8sConversionError {
    /// Error that occurs when required, expected (meta)data is missing
    #[error("k8s infra: {0}")]
    K8sInfra(String),

    /// An object within the configuration lacks a value for the object to make any sense
    #[error("Missing required data: {0}")]
    MissingData(String),

    /// A value that is invalid such as a malformed IP or MAC address, an out of range integer, etc.
    #[error("Invalid {0}")]
    InvalidData(String),

    /// Something that we don't allow because the system would malfunction or because it's not supported atm
    #[error("Not allowed: {0}")]
    NotAllowed(String),

    /// An error that occurs while processing the configuration which prevents processing or validating it
    #[error("Internal failure: {0}")]
    InternalError(String),

    /// A validation error, generally.
    #[error("Configuration error: {0}")]
    ConfigError(#[from] ConfigError),
}

#[derive(Debug, Error)]
pub enum ToK8sConversionError {
    #[error("Invalid Gateway Agent object: {0}")]
    Invalid(String),
    #[error("Missing required data: {0}")]
    MissingData(String),
    #[error("Could not parse value: {0}")]
    ParseError(String),
    #[error("Source configuration cannot be converted: {0}")]
    Unsupported(String),
}
