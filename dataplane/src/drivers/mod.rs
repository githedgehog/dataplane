// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use thiserror::Error;

pub mod dpdk;
pub mod kernel;
pub mod status;
pub mod watchdog;

#[derive(Error, Debug)]
pub enum DriverError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// A packet port could not be brought up, or its queues could not be handed to workers.
    #[error("port setup failed: {0}")]
    PortSetup(String),
}
