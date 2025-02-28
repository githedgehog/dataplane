// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library to implement routing functions.

#![deny(clippy::all)]

mod adjacency;
mod cpi;
mod cpi_process;
mod display;
mod encapsulation;
mod errors;
mod interface;
mod nexthop;
pub mod prefix;
mod pretty_utils;
mod rmac;
mod routingdb;
mod rpc_adapt;
mod vrf;
