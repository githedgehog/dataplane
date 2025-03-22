// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Kernel dataplane driver

use crate::CmdArgs;
use net::buffer::test_buffer::TestBuffer;
use pipeline::{self, DynPipeline, NetworkFunction};
use tracing::debug;

pub struct DriverKernel;

impl DriverKernel {
    pub fn start(
        args: impl IntoIterator<Item = impl AsRef<str>>,
        pipeline: DynPipeline<TestBuffer>,
    ) {
        debug!("Entering Kernel worker IO loop");
        loop { /* TODO */ }
    }
}
