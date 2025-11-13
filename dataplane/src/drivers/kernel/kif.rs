// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use netdev::Interface;
use std::io;

use net::interface::InterfaceIndex;

use tracing::{debug, error, warn};

#[derive(Debug, Clone)]
/// Simple representation of a kernel interface.
pub struct Kif {
    /// Linux ifindex of the interface
    pub ifindex: InterfaceIndex,
    /// Name of the interface, must be a name that can bound using bind on a socket
    pub name: String,
}

impl Kif {
    /// Create a kernel interface entry.
    #[allow(clippy::unnecessary_wraps)] // Eventually we'll do work that could return an error
    fn new(ifindex: InterfaceIndex, name: &str) -> io::Result<Self> {
        let iface = Self {
            ifindex,
            name: name.to_owned(),
        };

        // TDOO(manishv) we should open a socket just to make sure the interface exists and opens correctly
        debug!("Successfully created interface '{name}'");
        Ok(iface)
    }
}

/// Get the ifindex of the interface with the given name.
pub fn get_interface_ifindex(interfaces: &[Interface], name: &str) -> Option<InterfaceIndex> {
    interfaces
        .iter()
        .position(|interface| interface.name == name)
        .and_then(|pos| InterfaceIndex::try_new(interfaces[pos].index).ok())
}

/// Build a table of kernel interfaces to receive packets from (or send to).
/// Interfaces of interest are indicated by --interface INTERFACE in the command line.
/// Argument --interface ANY|any instructs the driver to capture on all interfaces.
pub fn get_interfaces(args: impl IntoIterator<Item = impl AsRef<str>>) -> io::Result<Vec<Kif>> {
    /* learn about existing kernel network interfaces. We need these to know their ifindex  */
    let interfaces = netdev::get_interfaces();

    /* build kiftable */
    let mut kifs = Vec::new();

    /* check what interfaces we're interested in from args */
    let ifnames: Vec<String> = args.into_iter().map(|x| x.as_ref().to_owned()).collect();
    if ifnames.is_empty() {
        warn!("No interfaces have been specified. No packet will be processed!");
        warn!("Consider specifying them with --interface. ANY captures over all interfaces.");
        return Ok(kifs);
    }

    if ifnames.len() == 1 && ifnames[0].eq_ignore_ascii_case("ANY") {
        /* use all interfaces */
        for interface in &interfaces {
            let if_index = match InterfaceIndex::try_new(interface.index) {
                Ok(if_index) => if_index,
                Err(e) => match e {
                    net::interface::InterfaceIndexError::Zero => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                },
            };
            match Kif::new(if_index, &interface.name) {
                Ok(kif) => kifs.push(kif),
                Err(e) => error!("Skipping interface '{}': {e}", interface.name),
            }
        }
    } else {
        /* use only the interfaces specified in args */
        for name in &ifnames {
            if let Some(ifindex) = get_interface_ifindex(&interfaces, name) {
                match Kif::new(ifindex, name) {
                    Ok(kif) => kifs.push(kif),
                    Err(e) => error!("Skipping interface '{name}': {e}"),
                }
            } else {
                warn!("Could not find ifindex of interface '{name}'");
            }
        }
    }

    Ok(kifs)
}
