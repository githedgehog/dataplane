// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Portmapper. The port mapper is responsible for creating tap devices for the
//! available ports reported by drivers and populate the [`PortMapTable`].

#![deny(unsafe_code, clippy::all, clippy::pedantic, clippy::unwrap_used)]
#![allow(unused)]
#![allow(clippy::panic, clippy::missing_panics_doc)]

use crate::portmap::{NetworkDeviceDescription, PortMapReaderFactory, PortMapWriter};
use interface_manager::interface::TapDevice;
use net::interface::{Interface, InterfaceName};
use net::packet::PortIndex;
use tokio::runtime::Runtime;

pub struct PortSpec {
    pdesc: NetworkDeviceDescription, // port description
    pindex: PortIndex,               // driver must guarantee uniqueness
    ifname: InterfaceName,
}
impl PortSpec {
    #[must_use]
    pub fn new(pdesc: NetworkDeviceDescription, pindex: PortIndex, ifname: InterfaceName) -> Self {
        Self {
            pdesc,
            pindex,
            ifname,
        }
    }
}

#[must_use]
pub async fn build_portmap_async(port_specs: impl Iterator<Item = PortSpec>) -> PortMapWriter {
    let mut mapt_w = PortMapWriter::new();
    for spec in port_specs {
        let Ok(tap) = TapDevice::open(&spec.ifname).await else {
            // clearly, we should not proceed further if this fails.
            panic!("Failed to build tap '{}'", spec.ifname);
        };

        // add mapping entry
        mapt_w.add_replace(spec.pdesc, spec.ifname.clone(), spec.pindex, tap.ifindex());
        // N.B. we drop the tap device here. This is fine and desired. The tap interface is persisted
        // and we don't need nor want to hold any file descriptor for it here.
    }
    mapt_w
}

#[must_use]
pub fn build_portmap(port_specs: impl Iterator<Item = PortSpec>) -> PortMapWriter {
    Runtime::new()
        .expect("Tokio runtime creation failed!")
        .block_on(build_portmap_async(port_specs))
}
