// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Crate to control tracing dynamically at runtime

pub mod control;
pub mod display;
pub mod targets;

// re-exports
pub use control::TracingControl;
pub use control::get_trace_ctl;
