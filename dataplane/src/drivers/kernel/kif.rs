// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use futures::TryStreamExt;
use netdev::Interface;
use std::io;

use net::interface::InterfaceIndex;
use rtnetlink::packet_route::link::LinkFlags;
use rtnetlink::{Handle, LinkUnspec};

use tracing::{debug, error, info, warn};

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
        debug!("Successfully created interface '{name}'");
        Ok(iface)
    }
    /// Bring the kernel interface represented by a [`Kif`] up and double check it went up.
    async fn bring_up(&self, handle: &Handle) -> io::Result<()> {
        info!("Bringing interface {} up ...", self.name);
        handle
            .link()
            .set(
                LinkUnspec::new_with_index(self.ifindex.to_u32())
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "Failed to bring {} (ifindex {}) up: {e}",
                    self.name, self.ifindex
                ))
            })?;

        // verify this single interface
        let links = handle
            .link()
            .get()
            .match_index(self.ifindex.to_u32())
            .execute()
            .try_next()
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "Failed to verify status of {} (ifindex {}) up: {e}",
                    self.name, self.ifindex
                ))
            })?;

        match links {
            Some(msg) => {
                if msg.header.flags.contains(LinkFlags::Up) {
                    info!("Interface {} is up", self.name);
                    Ok(())
                } else {
                    error!(
                        "Interface {} is not up, flags: {:?}",
                        self.name, msg.header.flags
                    );
                    Err(io::Error::other(format!(
                        "Interface {} did not come up",
                        self.name,
                    )))
                }
            }
            None => Err(io::Error::other(format!(
                "Got no response to check status of interface {}",
                self.name
            ))),
        }
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

/// Bring all of the interfaces in the slice of `Kif`s up
pub async fn bring_kifs_up(kifs: &[Kif]) -> io::Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    let h = tokio::spawn(connection);

    for kif in kifs {
        kif.bring_up(&handle).await?;
    }
    h.abort();
    Ok(())
}
