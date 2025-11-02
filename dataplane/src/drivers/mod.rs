// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(missing_docs)] // TEMPORARY
#![allow(clippy::missing_errors_doc)] // TEMPORARY

pub mod dpdk;
pub mod kernel;
mod tokio_util;

use mgmt::processor::launch::start_mgmt;
use routing::{RouterParams, RouterParamsBuilder};
use tracing::error;

use crate::{packet_processor::start_router, statistics::MetricsServer};

pub trait Start {
    fn start(&self);
}

pub trait Stop {
    fn stop(self);
}

pub trait Driver: Start + Stop {}
