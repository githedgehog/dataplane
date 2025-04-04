// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(feature = "cli")]
pub mod argsparse;

/// CLI protocol
pub mod cliproto;

#[cfg(feature = "cli")]
pub mod cmdtree;

#[cfg(feature = "cli")]
pub mod cmdtree_dp;

#[cfg(feature = "cli")]
pub mod completions;

#[cfg(feature = "cli")]
pub mod terminal;
