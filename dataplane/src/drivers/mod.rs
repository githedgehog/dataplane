// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(missing_docs)] // TEMPORARY
#![allow(clippy::missing_errors_doc)] // TEMPORARY

pub mod dpdk;
pub mod kernel;
mod tokio_util;

#[derive(thiserror::Error, Debug)]
pub enum DriverError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
