// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use futures::TryStreamExt;
use netdev::Interface;
use std::io;

use net::interface::InterfaceIndex;
use rtnetlink::packet_route::link::LinkFlags;
use rtnetlink::{Handle, LinkUnspec};

use tracing::{debug, error, info};

#[derive(Debug, Clone)]
/// Simple representation of a kernel interface.
pub struct Kif {
    /// Linux ifindex of the interface
    pub ifindex: InterfaceIndex,
    /// The MAC the kernel reports for this interface.
    ///
    /// Carried because the control-plane bridge needs it: the tap standing in for this interface
    /// has to answer ARP with the same address, or the peer sends frames this interface will not
    /// accept. `None` when the kernel reported none, which a physical interface never does.
    pub mac: Option<net::eth::mac::Mac>,
    /// The MTU the kernel reports, which the tap is given so both ends agree.
    pub mtu: Option<u32>,
    /// Name of the interface, must be a name that can bound using bind on a socket
    pub name: String,
}

impl Kif {
    /// Create a kernel interface entry.
    #[allow(clippy::unnecessary_wraps)] // Eventually we'll do work that could return an error
    fn new(ifindex: InterfaceIndex, name: &str, interface: &Interface) -> io::Result<Self> {
        let iface = Self {
            ifindex,
            mac: interface
                .mac_addr
                .map(|mac| net::eth::mac::Mac::from(mac.octets())),
            mtu: interface.mtu,
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
pub fn get_interface_ifindex(interfaces: &[Interface], name: &str) -> io::Result<InterfaceIndex> {
    let pos = interfaces
        .iter()
        .position(|interface| interface.name == name)
        .ok_or_else(|| io::Error::other(format!("Unknown interface '{name}'")))?;

    let ifindex = InterfaceIndex::try_new(interfaces[pos].index).map_err(io::Error::other)?;

    Ok(ifindex)
}

macro_rules! INTERFACE_FMT {
    ($ifindex:expr, $name:expr, $mac:expr, $opstate:expr, $admstate:expr) => {
        format_args!(
            "{:>8} {:<16} {:<20} {:<12} {:<6}",
            $ifindex, $name, $mac, $opstate, $admstate
        )
    };
}

fn log_kernel_interfaces(interfaces: &[Interface], msg: &str) {
    info!("━━━━━━━━━━━━━━━ {} ━━━━━━━━━━━━━━━", msg);
    info!(
        "{}",
        INTERFACE_FMT!("ifindex", "name", "mac", "OpState", "AdmState"),
    );
    for interface in interfaces {
        let mac = interface
            .mac_addr
            .map_or_else(|| "none".to_string(), |genid| genid.to_string());
        info!(
            "{}",
            INTERFACE_FMT!(
                interface.index,
                interface.name,
                mac,
                interface.oper_state.to_string(),
                if interface.is_up() { "up" } else { "down" }
            )
        );
    }
}

/// Build a table of kernel interfaces to receive packets from (or send to).
/// Interfaces of interest are indicated by --interface INTERFACE in the command line.
/// Argument --interface ANY|any instructs the driver to capture on all interfaces.
pub fn get_interfaces(args: impl IntoIterator<Item = impl AsRef<str>>) -> io::Result<Vec<Kif>> {
    /* learn about existing kernel network interfaces. We need these to know their ifindex  */
    let interfaces = netdev::get_interfaces();
    log_kernel_interfaces(interfaces.as_slice(), "Available kernel interfaces");

    /* check what interfaces we're interested in from args */
    let ifnames: Vec<String> = args.into_iter().map(|x| x.as_ref().to_owned()).collect();
    if ifnames.is_empty() {
        return Err(io::Error::other("At least one interface must be specified"));
    }

    /* populate vector with a [`Kif`] if the interface exists, else fail */
    let mut kifs = Vec::new();
    for ifname in &ifnames {
        let if_index = get_interface_ifindex(&interfaces, ifname)?;
        let interface = interfaces
            .iter()
            .find(|i| &i.name == ifname)
            .ok_or_else(|| io::Error::other(format!("interface '{ifname}' vanished mid-scan")))?;
        kifs.push(Kif::new(if_index, ifname, interface)?);
    }

    /* interfaces that will be used */
    let to_use: Vec<_> = interfaces
        .iter()
        .filter_map(|i| ifnames.contains(&i.name).then_some(i.clone()))
        .collect();
    log_kernel_interfaces(to_use.as_slice(), "Will use the following interfaces");

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
