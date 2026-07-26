// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use thiserror::Error;

pub mod kernel;
pub mod status;
pub mod watchdog;

#[derive(Error, Debug)]
pub enum DriverError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
