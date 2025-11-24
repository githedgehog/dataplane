// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane management module

mod grpc;
mod processor;
mod tests;
pub mod vpc_manager;

pub use processor::launch::{MgmtParams, start_mgmt};
pub use processor::proc::ConfigProcessorParams;

use tracectl::trace_target;
trace_target!("mgmt", LevelFilter::DEBUG, &["management"]);
