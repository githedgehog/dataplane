// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The error results used by this library.

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum RouterError {
    #[error("No interface with ifindex {0}")]
    NoSuchInterface(u32),

    #[error("No such VRF")]
    NoSuchVrf,

    #[error("A VRF with id {0} already exists")]
    VrfExists(u32),

    #[error("A VRF with Vni {0} already exists")]
    VniInUse(u32),

    #[error("Invalid VNI value: {0}")]
    VniInvalid(u32),

    #[error("An interface with ifindex {0} already exists")]
    InterfaceExists(u32),

    #[error("Invalid socket path '{0}'")]
    InvalidPath(String),

    #[error("Internal error: {0}")]
    Internal(&'static str),

    #[error("Permission errors")]
    PermError,
}
