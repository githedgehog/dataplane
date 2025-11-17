// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library to implement routing functions.

#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::collapsible_if,
    clippy::missing_errors_doc
)]

mod atable;
mod cli;
mod config;
mod cpi;
mod ctl;
mod display;
mod errors;
#[macro_use]
mod event;
mod evpn;
mod fib;
mod frr;
mod interfaces;
pub mod pretty_utils;

#[macro_use]
mod revent;
mod rib;
mod rio;

mod router;
mod routingdb;
mod rpc_adapt;

// re-exports
pub use atable::atablerw::AtableReader;
pub use config::RouterConfig;
pub use ctl::RouterCtlSender;
pub use errors::RouterError;
pub use evpn::Vtep;
pub use fib::fibobjects::{EgressObject, FibEntry, PktInstruction};
pub use fib::fibtable::FibTableReader;
pub use fib::fibtype::FibKey;
pub use frr::frrmi::FrrAppliedConfig;
pub use frr::renderer::builder::Render;
pub use interfaces::iftable::IfTable;
pub use interfaces::iftablerw::IfTableReader;
pub use interfaces::interface::{
    AttachConfig, Attachment, IfDataEthernet, IfState, IfType, Interface, RouterInterfaceConfig,
};
pub use rib::encapsulation::{Encapsulation, VxlanEncapsulation};
pub use rib::vrf::{RouterVrfConfig, VrfId};
pub use router::{Router, RouterParams, RouterParamsBuilder};

// main trace target for routing
use tracectl::trace_target;
trace_target!("routing", LevelFilter::DEBUG, &["routing-full"]);
