// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Converter for gateway-schema k8s objects to internal config

#![deny(clippy::all, clippy::pedantic)]

pub mod bgp;
pub mod device;
pub mod expose;
pub mod gateway_config;
pub mod interface;
pub mod overlay;
pub mod peering;
pub mod tracecfg;
pub mod underlay;
pub mod vpc;

use std::collections::BTreeMap;

use thiserror::Error;

use lpm::prefix::Prefix;

#[derive(Debug, Error)]
pub enum FromK8sConversionError {
    #[error("Invalid Gateway Agent object: {0}")]
    Invalid(String),
    #[error("Missing required data: {0}")]
    MissingData(String),
    #[error("Could not parse value: {0}")]
    ParseError(String),
    #[error("Internal CRD object conversion error: {0}")]
    InternalError(String),
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

pub type SubnetMap = BTreeMap<String, Prefix>;
pub type VpcSubnetMap = BTreeMap<String, SubnetMap>;
