// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(missing_docs)] // TEMPORARY
#![allow(clippy::missing_errors_doc)] // TEMPORARY

pub mod dpdk;
pub mod kernel;
mod tokio_util;

pub trait Start {
    type Started;
    fn start(self) -> Self::Started;
}

pub trait Stop {
    type Stopped;
    fn stop(self) -> Self::Stopped;
}

#[non_exhaustive]
pub struct Started;
#[non_exhaustive]
pub struct Stopped;

pub(crate) trait State {}

impl State for Started {}
impl State for Stopped {}

pub trait Cleanup {
    fn cleanup(self);
}

pub trait Driver {}
