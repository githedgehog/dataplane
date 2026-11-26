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
mod nfs;
mod rib;
mod router;
mod routingdb;

// re-exports: config
pub use config::RouterConfig;
pub use errors::RouterError;
pub use evpn::Vtep;
pub use rib::vrf::{RouterVrfConfig, VrfId};

pub use fib::fibobjects::{EgressObject, FibEntry, FibGroup, PktInstruction};
pub use fib::fibtable::FibTableReaderFactory;
pub use fib::fibtype::FibKey;
pub use frr::frrmi::FrrAppliedConfig;
pub use frr::renderer::builder::Render;
pub use interfaces::iftablerw::IfTableReaderFactory;
pub use interfaces::interface::{AttachConfig, RouterInterfaceConfig};
pub use interfaces::interface::{IfDataEthernet, IfState, IfType};
pub use rib::encapsulation::{Encapsulation, VxlanEncapsulation};

// re-expors: NFs for pipeline
pub use nfs::egress::Egress;
pub use nfs::ingress::Ingress;
pub use nfs::ipforward::IpForwarder;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use bmp::spawn_bmp_server;
pub use router::ctl::RouterCtlSender;
pub use router::{BmpServerParams, CliSources, Router, RouterParams, RouterParamsBuilder};

// main trace target for routing
use tracectl::trace_target;
trace_target!("routing", LevelFilter::DEBUG, &["routing-full"]);
