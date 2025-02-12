// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The error results used by this library.

use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug, PartialEq)]
pub enum RouterError {
    #[error("No such interface (ifindex {0})")]
    NoSuchInterface(u32),

    #[error("No such VRF")]
    NoSuchVrf,

    #[error("A VRF with id {0} already exists")]
    VrfExists(u32),

    #[error("A VRF with Vni {0} already exists")]
    VniInUse(u32),

    #[error("Invalid VNI value {0} ")]
    VniInvalid(u32),

    #[error("The interface is already attached to a distinct VRF")]
    AlreadyAttached,

    #[error("Some internal error ocurred")]
    CpiFailure,

    #[error("Invalid socket path")]
    InvalidSockPath,

    #[error("Permission errors")]
    PermError,
}
