// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Where DPDK ports come from.
//!
//! Ports differ in how their device comes to exist -- probed off the PCI bus, or made in-process
//! by a test -- and in nothing after that. Once claimed, every port is configured, queued and run
//! by the same code, so a [`PortSource`] is the only thing a new kind of port has to provide.

use std::collections::BTreeSet;

use dpdk::dev::DevIndex;
use dpdk::eal::Eal;
use hardware::pci::address::PciAddress;
use net::eth::mac::Mac;
use net::interface::InterfaceName;
use tracing::{info, warn};

use super::port::{Port, report_links};
use crate::drivers::DriverError;

/// What a port is called and how it is to be set up, whatever device it turns out to be.
#[derive(Debug, Clone)]
pub(crate) struct PortSettings {
    /// The configured interface name, which is also the name of the port's tap.
    pub(crate) name: InterfaceName,
    /// The MTU asked for; the device's default if `None`.
    pub(crate) mtu: Option<u16>,
    /// Receive descriptors per queue asked for; the driver's default if `None`.
    pub(crate) rx_descriptors: Option<u16>,
    /// The address to use if the device has none of its own, as a ring port does not. A device's
    /// own address always wins.
    pub(crate) fallback_mac: Option<Mac>,
}

/// A port's device, and how to find it once it exists.
///
/// Every source is attached ([`attach_ports`]) before any port is claimed ([`bring_up_ports`]):
/// attaching needs the EAL to itself, and a claimed port borrows it for as long as the port lives.
pub(crate) trait PortSource {
    /// What the port is called and how it is to be set up.
    fn settings(&self) -> &PortSettings;

    /// Make the device exist.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::PortSetup`] if the device cannot be made to appear.
    fn attach(&mut self, eal: &mut Eal) -> Result<(), DriverError>;

    /// The Ethernet device [`PortSource::attach`] made.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::PortSetup`] if no such device exists.
    fn find(&self, eal: &Eal) -> Result<DevIndex, DriverError>;
}

/// A device on the PCI bus, which DPDK names by its address.
///
/// Init must have prepared its kernel binding before it is attached.
#[derive(Debug, Clone)]
pub(crate) struct PciPort {
    pub(crate) settings: PortSettings,
    pub(crate) address: PciAddress,
}

impl PortSource for PciPort {
    fn settings(&self) -> &PortSettings {
        &self.settings
    }

    fn attach(&mut self, eal: &mut Eal) -> Result<(), DriverError> {
        eal.probe_pci(self.address)
            .map_err(|e| DriverError::PortSetup(format!("interface '{}': {e}", self.settings.name)))
    }

    fn find(&self, eal: &Eal) -> Result<DevIndex, DriverError> {
        let name = &self.settings.name;
        let wanted = self.address;
        for info in eal.dev.iter() {
            let index = info.index();
            let device = info.name().map_err(|e| {
                DriverError::PortSetup(format!("could not read the name of DPDK port {index}: {e}"))
            })?;
            // TODO: Resolve suffixed PMD port names when init supports eswitch configuration.
            if PciAddress::try_from(device.as_str()).is_ok_and(|address| address == wanted) {
                return Ok(index);
            }
        }
        Err(DriverError::PortSetup(format!(
            "interface '{name}': probing PCI device {wanted} produced no Ethernet port with that name"
        )))
    }
}

/// One end of a ring cable (see [`dpdk::dev::ring`]), whose other end the caller drives.
///
/// The cable exists before the port is brought up -- whoever made it needs the other end -- so
/// there is nothing to attach.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct RingPort {
    pub(crate) settings: PortSettings,
    pub(crate) dev: DevIndex,
}

#[cfg(test)]
impl PortSource for RingPort {
    fn settings(&self) -> &PortSettings {
        &self.settings
    }

    fn attach(&mut self, _eal: &mut Eal) -> Result<(), DriverError> {
        Ok(())
    }

    fn find(&self, _eal: &Eal) -> Result<DevIndex, DriverError> {
        Ok(self.dev)
    }
}

/// Sources whose devices exist, ready for [`bring_up_ports`].
pub(crate) struct Attached<S>(Vec<S>);

/// Make every source's device exist.
///
/// Separate from [`bring_up_ports`] because attaching needs the EAL to itself, while the ports
/// brought up afterwards borrow it shared, alongside anything else that does.
///
/// # Errors
///
/// Returns [`DriverError::PortSetup`] for the first device that cannot be attached.
pub(crate) fn attach_ports<S: PortSource>(
    eal: &mut Eal,
    mut sources: Vec<S>,
) -> Result<Attached<S>, DriverError> {
    for source in &mut sources {
        source.attach(eal)?;
    }
    Ok(Attached(sources))
}

/// Configure, queue and start every attached source's port, in order.
///
/// # Errors
///
/// Returns [`DriverError::PortSetup`] for the first port that cannot be brought up.
pub(crate) fn bring_up_ports<'eal, S: PortSource>(
    eal: &'eal Eal,
    sources: &Attached<S>,
    num_workers: u16,
) -> Result<Vec<Port<'eal>>, DriverError> {
    let Attached(sources) = sources;
    // Every port's pool backs its packets in every port's transmit rings.
    let num_ports = u32::try_from(sources.len()).unwrap_or(u32::MAX);

    let mut ports = Vec::with_capacity(sources.len());
    let mut claimed = BTreeSet::new();
    for source in sources {
        let index = source.find(eal)?;
        // Claim before any setup, so a port something else owns is refused up front.
        let port = eal
            .claim(index)
            .map_err(|e| DriverError::PortSetup(format!("cannot use port {index}: {e}")))?;
        claimed.insert(index);

        // Configure, queue and start the device; this is where the port actually comes up.
        let started = Port::bring_up(eal, port, source.settings().clone(), num_workers, num_ports)?;
        ports.push(started);
    }
    info!(
        "Brought up {} DPDK port(s): {}",
        ports.len(),
        ports
            .iter()
            .map(|port| port.name.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    report_links(&ports, num_workers);

    let unclaimed: Vec<String> = eal
        .dev
        .iter()
        .filter(|info| !claimed.contains(&info.index()))
        .map(|info| {
            info.name()
                .unwrap_or_else(|e| format!("port {} ({e})", info.index()))
        })
        .collect();
    if !unclaimed.is_empty() {
        warn!(
            "{} DPDK port(s) were not named by any interface and will carry no traffic: {}",
            unclaimed.len(),
            unclaimed.join(", ")
        );
    }

    Ok(ports)
}
