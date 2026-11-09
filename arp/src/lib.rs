// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Suport for ARP and Neighbor Discovery

#![deny(clippy::all)]
#![allow(clippy::collapsible_if)]

mod backlog;
mod cache;
mod daemon;
mod netlink;
mod querier;
mod setup;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

//re-exports
pub use cache::{NeighCache, NeighCacheReader, NeighCacheReaderFactory, NeighEntry};
pub use daemon::ArpNdError;
pub use setup::{ArpNfFactory, ArpSetup};

use tracectl::trace_target;
trace_target!("arp-nd", LevelFilter::INFO, &[]);
