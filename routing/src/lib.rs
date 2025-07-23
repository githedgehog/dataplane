// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library to implement routing functions.

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::similar_names)]

pub mod atable;
pub mod cli;
pub mod config;
mod cpi;
pub mod ctl;
mod display;
mod errors;
#[macro_use]
pub(crate) mod event;
pub mod evpn;
pub mod fib;
pub mod frr;
pub mod interfaces;
pub mod pretty_utils;
pub mod rib;
pub mod rio;

mod router;
pub mod routingdb;
mod rpc_adapt;
pub mod testfib;

// re-exports
pub use errors::RouterError;
pub use router::{Router, RouterParams, RouterParamsBuilder};
