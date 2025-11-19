// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use thiserror::Error;

pub mod dpdk;
pub mod kernel;
mod tokio_util;

#[derive(Error, Debug)]
pub enum DriverError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
