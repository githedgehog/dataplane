// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library to pull dataplane config from k8s

#![deny(clippy::all, clippy::pedantic)]

#[cfg(any(test, feature = "bolero"))]
pub mod bolero;
pub mod client;
pub mod generated;
pub mod samplegen;
pub mod utils;

pub mod gateway_agent_crd {
    pub use crate::generated::gateway_agent_crd::*;
}

pub use client::watch_gateway_agent_crd;
