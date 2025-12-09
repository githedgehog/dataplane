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
mod bmp;
mod cli;
mod config;
mod errors;
#[macro_use]
mod event;
mod evpn;
mod fib;
mod frr;
mod interfaces;
mod rib;
mod router;
mod routingdb;

// re-exports
pub use atable::atablerw::AtableReader;
pub use bmp::server::{BmpServer, BmpServerConfig};
pub use config::RouterConfig;
pub use errors::RouterError;
pub use evpn::Vtep;
pub use fib::fibobjects::{EgressObject, FibEntry, PktInstruction};
pub use fib::fibtable::FibTableReader;
pub use fib::fibtype::FibKey;
pub use frr::frrmi::FrrAppliedConfig;
pub use frr::renderer::builder::Render;
pub use interfaces::iftable::IfTable;
pub use interfaces::iftablerw::IfTableReader;
pub use interfaces::interface::{AttachConfig, Attachment, RouterInterfaceConfig};
pub use interfaces::interface::{IfDataEthernet, IfState, IfType, Interface};
pub use rib::encapsulation::{Encapsulation, VxlanEncapsulation};
pub use rib::vrf::{RouterVrfConfig, VrfId};

pub use router::ctl::RouterCtlSender;
pub use router::{BmpServerParams, Router, RouterParams, RouterParamsBuilder};

pub use cli::pretty_utils::Heading;

// main trace target for routing
use tracectl::trace_target;
trace_target!("routing", LevelFilter::DEBUG, &["routing-full"]);
