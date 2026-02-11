// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! WASM-safe CRD type definitions for the dataplane.

#![deny(clippy::all, clippy::pedantic)]

pub mod generated;

pub mod gateway_agent_crd {
    pub use crate::generated::gateway_agent_crd::*;
}
