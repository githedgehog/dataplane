// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local packet I/O for gateway

#![deny(clippy::all)]

mod nf;
mod portmap;
mod portmapper;
mod tests;

pub use nf::PktIo;
pub use nf::PktQueue;
pub use portmap::{PortMap, PortMapReader, PortMapReaderFactory, PortMapWriter};
pub use portmapper::{PortSpec, build_portmap, build_portmap_async};
