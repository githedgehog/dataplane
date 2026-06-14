// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Errors returned by `rte_flow` validate/create/destroy.

use alloc::string::{String, ToString};
use core::ffi::CStr;
use dpdk_sys::{rte_flow_error, rte_flow_error_type as et};

/// Why an `rte_flow` operation was rejected by the PMD.
///
/// The variant identifies which structural part the PMD faulted on (from `rte_flow_error.type`);
/// the carried `String` is the PMD's human-readable detail. That message is *context only* -- it is
/// never matched on to decide handling (matching on error strings is hostile to maintenance; see the
/// error-handling guide). Note that "this NIC does not support this item/action" surfaces here at
/// runtime rather than as a compile error, because hardware capability is measured, not assumed.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    /// The rule attributes were rejected (group, priority, or ingress/egress/transfer direction).
    #[error("rte_flow rejected the rule attributes: {0}")]
    Attr(String),
    /// A pattern (match) item was rejected -- unsupported, or a bad spec/mask/last.
    #[error("rte_flow rejected a pattern item: {0}")]
    Item(String),
    /// An action was rejected -- unsupported, bad config, or an illegal action combination.
    #[error("rte_flow rejected an action: {0}")]
    Action(String),
    /// The flow rule handle was rejected (e.g. destroying a rule others depend on).
    #[error("rte_flow rejected the rule handle: {0}")]
    Handle(String),
    /// The PMD rejected the rule without attributing a specific structural cause.
    #[error("rte_flow rejected the rule: {0}")]
    Unspecified(String),
    /// Any error type not otherwise categorized; carries the raw `rte_flow_error_type`.
    #[error("rte_flow failed (error type {error_type}): {message}")]
    Other {
        /// The raw `rte_flow_error_type` value.
        error_type: u32,
        /// The PMD's detail message.
        message: String,
    },
}

impl FlowError {
    /// Build a [`FlowError`] from a PMD-populated `rte_flow_error`.
    ///
    /// Only meaningful when the originating call actually failed; on success the PMD does not
    /// populate `error`.
    pub(crate) fn from_raw(error: &rte_flow_error) -> FlowError {
        let message = if error.message.is_null() {
            "(no detail from PMD)".to_string()
        } else {
            // SAFETY: on failure the PMD sets `message` to a static, NUL-terminated C string.
            unsafe { CStr::from_ptr(error.message) }
                .to_string_lossy()
                .into_owned()
        };
        match error.type_ {
            et::RTE_FLOW_ERROR_TYPE_ATTR_GROUP
            | et::RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY
            | et::RTE_FLOW_ERROR_TYPE_ATTR_INGRESS
            | et::RTE_FLOW_ERROR_TYPE_ATTR_EGRESS
            | et::RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER
            | et::RTE_FLOW_ERROR_TYPE_ATTR => FlowError::Attr(message),
            et::RTE_FLOW_ERROR_TYPE_ITEM_NUM
            | et::RTE_FLOW_ERROR_TYPE_ITEM_SPEC
            | et::RTE_FLOW_ERROR_TYPE_ITEM_LAST
            | et::RTE_FLOW_ERROR_TYPE_ITEM_MASK
            | et::RTE_FLOW_ERROR_TYPE_ITEM => FlowError::Item(message),
            et::RTE_FLOW_ERROR_TYPE_ACTION_NUM
            | et::RTE_FLOW_ERROR_TYPE_ACTION_CONF
            | et::RTE_FLOW_ERROR_TYPE_ACTION => FlowError::Action(message),
            et::RTE_FLOW_ERROR_TYPE_HANDLE => FlowError::Handle(message),
            et::RTE_FLOW_ERROR_TYPE_UNSPECIFIED => FlowError::Unspecified(message),
            other => FlowError::Other {
                error_type: other,
                message,
            },
        }
    }
}
