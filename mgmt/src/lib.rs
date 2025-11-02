// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane management module

/* gRPC entry point */
mod grpc;

/* Configuration processor */
mod processor;

/* VPC manager */
pub mod vpc_manager;

#[cfg(test)]
mod tests;

pub use processor::launch::{MgmtParams, start_mgmt};
pub use processor::proc::ConfigProcessorParams;

use tracectl::trace_target;
trace_target!("mgmt", LevelFilter::DEBUG, &["management"]);
