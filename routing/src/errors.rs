// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The error results used by this library.

use crate::fib::fibtype::FibKey;
use net::interface::InterfaceIndex;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum RouterError {
    #[error("No interface with ifindex {0}")]
    NoSuchInterface(InterfaceIndex),

    #[error("No such VRF")]
    NoSuchVrf,

    #[error("A VRF with id {0} already exists")]
    VrfExists(u32),

    #[error("A VRF with Vni {0} already exists")]
    VniInUse(u32),

    #[error("Invalid VNI value: {0}")]
    VniInvalid(u32),

    #[error("An interface with ifindex {0} already exists")]
    InterfaceExists(InterfaceIndex),

    #[error("Invalid socket path '{0}'")]
    InvalidPath(String),

    #[error("Internal error: {0}")]
    Internal(&'static str),

    #[error("Verify failure for {0}")]
    VerifyFailure(String),

    #[error("Permission errors")]
    PermError,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(&'static str),

    #[error("Fibtable is not accessible")]
    FibTableError,

    #[error("Fib error: {0}")]
    FibError(#[from] left_right_tlcache::ReadHandleCacheError<FibKey>),
}
