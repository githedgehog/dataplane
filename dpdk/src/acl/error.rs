// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Error types for ACL operations.
//!
//! Each fallible ACL operation has a dedicated error type following the project's error handling
//! guidelines.  Errors are strongly typed enums rather than strings or bare numeric codes.

use core::fmt::{Display, Formatter};

use errno::Errno;

/// Ways in which an ACL context name can be invalid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum InvalidAclName {
    /// The name is not valid ASCII.
    NotAscii,
    /// The name is too long (exceeds [`RTE_ACL_NAMESIZE`][dpdk_sys::RTE_ACL_NAMESIZE]).
    TooLong {
        /// The length of the name that was provided.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },
    /// The name is empty.
    Empty,
    /// The name contains interior null bytes.
    ContainsNullBytes,
}

impl Display for InvalidAclName {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            InvalidAclName::NotAscii => write!(f, "ACL context name must be valid ASCII"),
            InvalidAclName::TooLong { len, max } => {
                write!(
                    f,
                    "ACL context name is too long ({len} > {max} bytes)",
                )
            }
            InvalidAclName::Empty => write!(f, "ACL context name must not be empty"),
            InvalidAclName::ContainsNullBytes => {
                write!(f, "ACL context name must not contain null bytes")
            }
        }
    }
}

/// Errors that can occur when creating an ACL context via [`rte_acl_create`][dpdk_sys::rte_acl_create].
#[derive(Debug, thiserror::Error)]
pub enum AclCreateError {
    /// The context name failed validation.
    #[error("Invalid ACL context name: {0}")]
    InvalidName(InvalidAclName),
    /// DPDK returned `EINVAL` — one or more parameters are invalid.
    #[error("Invalid ACL creation parameters")]
    InvalidParams,
    /// DPDK returned `ENOMEM` — insufficient memory to allocate the context.
    #[error("Not enough memory to create ACL context")]
    OutOfMemory,
    /// DPDK set an `rte_errno` value that does not match any documented error for this call.
    #[error("Unknown error creating ACL context: {0:?}")]
    Unknown(Errno),
}

/// Errors that can occur when adding rules via [`rte_acl_add_rules`][dpdk_sys::rte_acl_add_rules].
#[derive(Debug, thiserror::Error)]
pub enum AclAddRulesError {
    /// DPDK returned `ENOMEM` — not enough space in the context for the new rules.
    #[error("No space for additional rules in ACL context")]
    OutOfMemory,
    /// DPDK returned `EINVAL` — one or more rule parameters are invalid.
    #[error("Invalid rule parameters")]
    InvalidParams,
    /// DPDK returned an undocumented error code.
    #[error("Unknown error adding rules: {0:?}")]
    Unknown(Errno),
}

/// Errors that can occur when building the ACL context via [`rte_acl_build`][dpdk_sys::rte_acl_build].
#[derive(Debug, thiserror::Error)]
pub enum AclBuildError {
    /// DPDK returned `ENOMEM` — not enough memory to build the runtime structures.
    #[error("Not enough memory to build ACL context")]
    OutOfMemory,
    /// DPDK returned `EINVAL` — the build configuration is invalid.
    #[error("Invalid ACL build configuration")]
    InvalidConfig,
    /// The build consumed the context but failed.
    ///
    /// The inner context has been reset back to [`Configuring`][super::context::Configuring] state
    /// so that it can be reconfigured or dropped.
    #[error("ACL build failed: {0:?}")]
    Unknown(Errno),
}

/// Errors that can occur during classification via
/// [`rte_acl_classify`][dpdk_sys::rte_acl_classify].
#[derive(Debug, thiserror::Error)]
pub enum AclClassifyError {
    /// DPDK returned `EINVAL` — the classify arguments are invalid.
    ///
    /// Common causes:
    /// - `categories` is zero, greater than [`RTE_ACL_MAX_CATEGORIES`][dpdk_sys::RTE_ACL_MAX_CATEGORIES],
    ///   or not a multiple of [`RTE_ACL_RESULTS_MULTIPLIER`][dpdk_sys::RTE_ACL_RESULTS_MULTIPLIER].
    /// - The `results` slice is too small for `num * categories` entries.
    #[error("Invalid classify arguments")]
    InvalidArgs,
    /// DPDK returned an undocumented error code.
    #[error("Unknown error during classification: {0:?}")]
    Unknown(Errno),
}

/// Errors that can occur when setting the classification algorithm via
/// [`rte_acl_set_ctx_classify`][dpdk_sys::rte_acl_set_ctx_classify].
#[derive(Debug, thiserror::Error)]
pub enum AclSetAlgorithmError {
    /// DPDK returned `EINVAL` — the parameters are invalid.
    #[error("Invalid algorithm or context")]
    InvalidParams,
    /// The requested algorithm is not supported on this CPU.
    #[error("Requested classification algorithm is not supported on this platform")]
    NotSupported,
    /// DPDK returned an undocumented error code.
    #[error("Unknown error setting classification algorithm: {0:?}")]
    Unknown(Errno),
}