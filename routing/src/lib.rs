// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library to implement routing functions.

#![deny(clippy::all)]

pub mod atable;
pub mod cli;
pub mod cpi;
mod cpi_process;
mod display;
mod encapsulation;
mod errors;
pub mod fib;
pub mod interfaces;
mod nexthop;
pub mod prefix;
mod pretty_utils;
mod rmac;
pub mod route_processor;
pub mod routingdb;
mod rpc_adapt;
pub mod testfib;
pub mod vrf;
