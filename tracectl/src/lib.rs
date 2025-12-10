// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Crate to control tracing dynamically at runtime

#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

pub mod control;
pub mod display;
pub mod targets;

// re-exports
pub use control::DEFAULT_DEFAULT_LOGLEVEL;
pub use control::{TraceCtlError, TracingControl};
pub use control::{get_name, get_trace_ctl, set_name};
pub use tracing_subscriber::filter::LevelFilter;
