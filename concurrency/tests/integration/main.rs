// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The integration tests, as one binary.
//!
//! Each `tests/*.rs` file would be its own test binary, and every one of them links the whole
//! dependency graph -- under the release profile, a cross-language ThinLTO link apiece. Each module
//! here is one of those files; add new ones the same way rather than as `tests/*.rs`.

mod arc_weak;
mod quiescent_model;
mod quiescent_properties;
mod quiescent_protocol;
mod quiescent_shuttle;
mod scope_property;
mod stress_dispatch;
mod sync_channel;
mod thread_scope;
