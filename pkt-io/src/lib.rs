// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local packet I/O for gateway

#![deny(clippy::all)]
#![allow(clippy::collapsible_if)]

mod ctl;
mod io;

mod nf;
mod portmap;
mod portmapper;
mod tests;

// re-exports
pub use ctl::IoManagerCtl;
pub use io::start_io;
pub use nf::PktIo;
pub use nf::PktQueue;
pub use portmap::{PortMap, PortMapReader, PortMapReaderFactory, PortMapWriter};
pub use portmapper::{PortSpec, build_portmap, build_portmap_async};
