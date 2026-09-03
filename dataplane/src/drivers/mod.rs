// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use thiserror::Error;

#[cfg(feature = "af-xdp")]
pub mod af_xdp;
pub mod kernel;
pub(crate) mod kif;
pub mod status;
pub(crate) mod supervisor;
pub mod watchdog;

#[derive(Error, Debug)]
pub enum DriverError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
