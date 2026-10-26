// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Give each kernel-driver interface its configured name.
//!
//! The kernel driver, management, and the router all find an interface by its configured name, so
//! that has to be the kernel's name for it. An interface given as `pci@ADDR` or `kernel@IFNAME` is
//! renamed to its configured name. A PCI device that a DPDK run left on vfio-pci has no interface
//! at all, so it is first handed back to its kernel driver: by its address for `pci@`, and for an
//! interface given by name, every device a DPDK run could have left there, since nothing says which
//! one the name belongs to.

use std::path::Path;
use std::time::Duration;

use args::{InterfaceArg, KernelDriverConfigSection, PortArg};
use hardware::nic::{PciNic, ReleaseFromVfioPci, netdevs_of};
use hardware::pci::address::PciAddress;
use hardware::pci::device::DeviceId;
use hardware::pci::vendor::VendorId;
use hardware::support::{DpdkDriverType, SupportedDevice};
use rtnetlink::LinkUnspec;
use sysfs::sysfs_root;
use tracing::{debug, info};

/// How long a device handed back to its kernel driver has to register its interface.
const NETDEV_TIMEOUT: Duration = Duration::from_secs(5);

/// `IFF_UP` in `/sys/class/net/<name>/flags`.
const IFF_UP: u32 = 0x1;

/// Find every configured interface and give it its configured name.
pub(crate) fn prepare(kernel: &KernelDriverConfigSection) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not build a runtime to talk to netlink: {e}"))?;
    runtime.block_on(async {
        let (connection, handle, _) = rtnetlink::new_connection()
            .map_err(|e| format!("could not open a netlink socket: {e}"))?;
        let connection = tokio::spawn(connection);

        let mut problems = Vec::new();
        let mut released = false;
        for interface in &kernel.interfaces {
            if let Err(e) = prepare_one(&handle, interface, &mut released).await {
                problems.push(format!("interface '{}': {e}", interface.interface));
            }
        }

        connection.abort();
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("\n  "))
        }
    })
}

/// `released` is whether the devices a DPDK run left on vfio-pci have been handed back already.
async fn prepare_one(
    handle: &rtnetlink::Handle,
    interface: &InterfaceArg,
    released: &mut bool,
) -> Result<(), String> {
    let wanted = interface.interface.to_string();
    let current = match &interface.port {
        None => named(&wanted, &wanted, released).await?,
        Some(PortArg::KERNEL(name)) => named(name.as_ref(), &wanted, released).await?,
        Some(PortArg::PCI(ebdf)) => {
            let address = PciAddress::try_from(ebdf.to_string().as_str())
                .map_err(|e| format!("invalid PCI address {ebdf}: {e}"))?;
            netdev_of(address, &wanted).await?
        }
    };
    if current == wanted {
        info!("interface '{wanted}' is already named");
        return Ok(());
    }
    rename(handle, &current, &wanted).await
}

/// The kernel interface of the PCI device at `address`, handing the device back from vfio-pci
/// if it has none.
async fn netdev_of(address: PciAddress, wanted: &str) -> Result<String, String> {
    let list =
        || netdevs_of(address).map_err(|e| format!("cannot list the interfaces of {address}: {e}"));
    let mut names = list()?;
    if names.is_empty() {
        info!("{address} has no kernel interface; returning it to its kernel driver");
        PciNic::new(address)
            .map_err(|e| e.to_string())?
            .release_from_vfio_pci()
            .map_err(|e| e.to_string())?;
        let deadline = clock::deadline(NETDEV_TIMEOUT);
        loop {
            names = list()?;
            if !names.is_empty() || clock::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    match names.as_slice() {
        [] => Err(format!(
            "PCI device {address} has no network interface in this network namespace; it may \
             have been left in another one"
        )),
        [name] => {
            info!("{address} is interface '{name}'");
            Ok(name.clone())
        }
        many if many.iter().any(|name| name == wanted) => Ok(wanted.to_string()),
        many => Err(format!(
            "PCI device {address} has several network interfaces ({}); cannot tell which one is \
             '{wanted}'",
            many.join(", ")
        )),
    }
}

/// Whether this network namespace has an interface called `name`.
fn exists(name: &str) -> bool {
    sysfs_root().inner().join("class/net").join(name).exists()
}

/// The interface the kernel calls `name`, or `wanted` if an earlier start already renamed it.
///
/// Neither is there when a DPDK run left the device on vfio-pci, so the devices it could have left
/// are handed back to their kernel drivers, once for all interfaces (see [`left_on_vfio_pci`]),
/// and the names get [`NETDEV_TIMEOUT`] to appear: udev may rename the interface after the driver
/// registers it.
async fn named(name: &str, wanted: &str, released: &mut bool) -> Result<String, String> {
    let found = || [name, wanted].into_iter().find(|n| exists(n));
    if let Some(found) = found() {
        return Ok(found.to_string());
    }
    if !*released {
        *released = true;
        let left = left_on_vfio_pci(sysfs_root().inner());
        if !left.is_empty() {
            info!(
                "there is no interface '{name}'; returning the devices a DPDK run left on vfio-pci \
                 to their kernel drivers"
            );
        }
        for address in left {
            PciNic::new(address)
                .map_err(|e| e.to_string())?
                .release_from_vfio_pci()
                .map_err(|e| format!("cannot return {address} to its kernel driver: {e}"))?;
        }
    }
    let deadline = clock::deadline(NETDEV_TIMEOUT);
    while clock::now() < deadline {
        if let Some(found) = found() {
            return Ok(found.to_string());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    found()
        .map(str::to_string)
        .ok_or_else(|| format!("there is no network interface '{name}' in this network namespace"))
}

/// The devices under `sys` that a DPDK run could have left on vfio-pci: ones the DPDK driver binds
/// to vfio-pci, still overridden to it, and bound to it or (after an interrupted bind) to nothing.
///
/// The override is what `BindToVfioPci` sets, and what tells these from a device someone handed
/// to vfio-pci some other way, which is left alone.
fn left_on_vfio_pci(sys: &Path) -> Vec<PciAddress> {
    let Ok(devices) = std::fs::read_dir(sys.join("bus/pci/devices")) else {
        return Vec::new();
    };
    let mut left: Vec<PciAddress> = devices
        .flatten()
        .filter_map(|entry| {
            let address = PciAddress::try_from(entry.file_name().to_str()?).ok()?;
            let path = entry.path();
            let id = |attribute: &str| {
                let text = std::fs::read_to_string(path.join(attribute)).ok()?;
                u16::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok()
            };
            let vendor = VendorId::new(id("vendor")?).ok()?;
            let device = SupportedDevice::try_from((vendor, DeviceId::new(id("device")?))).ok()?;
            if DpdkDriverType::from(device) != DpdkDriverType::VfioPci {
                return None;
            }
            let overridden = std::fs::read_to_string(path.join("driver_override"))
                .is_ok_and(|o| o.trim() == "vfio-pci");
            let driver = std::fs::read_link(path.join("driver")).ok();
            let on_vfio_or_nothing = driver
                .as_deref()
                .and_then(Path::file_name)
                .is_none_or(|d| d == "vfio-pci");
            (overridden && on_vfio_or_nothing).then_some(address)
        })
        .collect();
    left.sort();
    left
}

/// Rename `current` to `wanted`, leaving it up if it was up.
async fn rename(handle: &rtnetlink::Handle, current: &str, wanted: &str) -> Result<(), String> {
    let net = sysfs_root().inner().join("class/net");
    if net.join(wanted).exists() {
        return Err(format!(
            "cannot rename '{current}' to '{wanted}': another interface already has that name"
        ));
    }
    let read = |attribute: &str| {
        std::fs::read_to_string(net.join(current).join(attribute))
            .map_err(|e| format!("cannot read {attribute} of interface '{current}': {e}"))
    };
    let index: u32 = read("ifindex")?
        .trim()
        .parse()
        .map_err(|e| format!("bad ifindex for interface '{current}': {e}"))?;
    let flags = read("flags")?;
    let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
        .map_err(|e| format!("bad flags for interface '{current}': {e}"))?;

    info!("renaming interface '{current}' (index {index}) to '{wanted}'");
    // The kernel refuses to rename an interface that is up.
    handle
        .link()
        .set(
            LinkUnspec::new_with_index(index)
                .down()
                .name(wanted.to_string())
                .build(),
        )
        .execute()
        .await
        .map_err(|e| format!("cannot rename '{current}' to '{wanted}': {e}"))?;
    if flags & IFF_UP != 0 {
        debug!("bringing '{wanted}' back up");
        handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .map_err(|e| {
                format!("renamed '{current}' to '{wanted}' but cannot bring it up: {e}")
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;
    use std::str::FromStr;

    use args::{InterfaceArg, KernelDriverConfigSection};
    use hardware::nic::{BindToVfioPci, PciNic, ReleaseFromVfioPci, netdevs_of};
    use hardware::pci::address::PciAddress;
    use hardware::support::DpdkDriverType;
    use rtnetlink::LinkUnspec;

    use super::{left_on_vfio_pci, prepare};

    /// A NIC that can be bound to vfio-pci and currently has a kernel interface.
    fn vfio_capable_nic() -> PciAddress {
        std::fs::read_dir("/sys/bus/pci/devices")
            .unwrap()
            .flatten()
            .filter_map(|entry| PciAddress::try_from(entry.file_name().to_str()?).ok())
            .find(|&address| {
                PciNic::new(address)
                    .is_ok_and(|nic| DpdkDriverType::from(nic.device()) == DpdkDriverType::VfioPci)
                    && netdevs_of(address).is_ok_and(|names| !names.is_empty())
            })
            .expect("the guest has a NIC that can be bound to vfio-pci")
    }

    fn prepare_interfaces(spec: &str) -> Result<(), String> {
        prepare(&KernelDriverConfigSection {
            interfaces: vec![InterfaceArg::from_str(spec).unwrap()],
            num_workers: NonZero::<u16>::MIN,
        })
    }

    fn is_up(name: &str) -> bool {
        let flags = std::fs::read_to_string(format!("/sys/class/net/{name}/flags")).unwrap();
        u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap() & 0x1 != 0
    }

    fn bring_up(name: &str) {
        let index: u32 = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (connection, handle, _) = rtnetlink::new_connection().unwrap();
            let connection = tokio::spawn(connection);
            handle
                .link()
                .set(LinkUnspec::new_with_index(index).up().build())
                .execute()
                .await
                .unwrap();
            connection.abort();
        });
    }

    /// A device a DPDK run left on vfio-pci comes back under its configured name, and an
    /// interface named by `kernel@` is renamed and stays up.
    #[n_vm::test]
    fn interfaces_are_found_restored_and_renamed() {
        let address = vfio_capable_nic();
        PciNic::new(address).unwrap().bind_to_vfio_pci().unwrap();
        assert_eq!(netdevs_of(address).unwrap(), Vec::<String>::new());

        prepare_interfaces(&format!("wan0=pci@{address}")).unwrap();
        assert_eq!(netdevs_of(address).unwrap(), ["wan0"]);
        let driver_override =
            std::fs::read_to_string(format!("/sys/bus/pci/devices/{address}/driver_override"))
                .unwrap();
        assert_eq!(driver_override.trim(), "(null)");

        // A restart finds the interface already named.
        prepare_interfaces(&format!("wan0=pci@{address}")).unwrap();
        assert_eq!(netdevs_of(address).unwrap(), ["wan0"]);

        bring_up("wan0");
        prepare_interfaces("lan0=kernel@wan0").unwrap();
        assert_eq!(netdevs_of(address).unwrap(), ["lan0"]);
        assert!(is_up("lan0"), "renaming must leave an up interface up");

        let err = prepare_interfaces("lo=kernel@lan0").unwrap_err();
        assert!(err.contains("already has that name"), "{err}");
        assert!(prepare_interfaces("lan1=kernel@missing0").is_err());
    }

    /// A NIC in a fake sysfs under `sys`.
    fn device(
        sys: &std::path::Path,
        address: &str,
        ids: (&str, &str),
        driver: Option<&str>,
        over: &str,
    ) {
        let dir = sys.join("bus/pci/devices").join(address);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vendor"), format!("{}\n", ids.0)).unwrap();
        std::fs::write(dir.join("device"), format!("{}\n", ids.1)).unwrap();
        std::fs::write(dir.join("driver_override"), format!("{over}\n")).unwrap();
        if let Some(driver) = driver {
            let target = sys.join("bus/pci/drivers").join(driver);
            std::fs::create_dir_all(&target).unwrap();
            std::os::unix::fs::symlink(target, dir.join("driver")).unwrap();
        }
    }

    const E1000E: (&str, &str) = ("0x8086", "0x10d3");
    const BLUEFIELD3: (&str, &str) = ("0x15b3", "0xa2dc");
    const UNSUPPORTED: (&str, &str) = ("0x8086", "0x1234");

    #[test]
    fn only_devices_our_bind_left_on_vfio_pci_are_returned() {
        let sys = std::env::temp_dir().join(format!(
            "init-kif-{}",
            id::Id::<KernelDriverConfigSection>::new()
        ));
        device(&sys, "0000:05:00.0", E1000E, Some("vfio-pci"), "vfio-pci");
        // An interrupted bind: overridden, bound to nothing.
        device(&sys, "0000:06:00.0", E1000E, None, "vfio-pci");
        // Already back with its kernel driver.
        device(&sys, "0000:07:00.0", E1000E, Some("e1000e"), "(null)");
        // On vfio-pci, but not by our bind.
        device(&sys, "0000:08:00.0", E1000E, Some("vfio-pci"), "(null)");
        // Bifurcated: DPDK never binds it to vfio-pci.
        device(
            &sys,
            "0000:09:00.0",
            BLUEFIELD3,
            Some("vfio-pci"),
            "vfio-pci",
        );
        // Not a NIC the dataplane drives.
        device(
            &sys,
            "0000:0a:00.0",
            UNSUPPORTED,
            Some("vfio-pci"),
            "vfio-pci",
        );
        let left: Vec<String> = left_on_vfio_pci(&sys)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(left, ["0000:05:00.0", "0000:06:00.0"]);
        std::fs::remove_dir_all(&sys).unwrap();
    }

    #[test]
    fn no_pci_devices_means_nothing_to_return() {
        assert_eq!(left_on_vfio_pci(std::path::Path::new("/nonexistent")), []);
    }

    /// Switching from DPDK to the kernel driver: the configuration names the interface, not the
    /// device, and the device is still on vfio-pci from the DPDK run.
    #[n_vm::test]
    fn an_interface_given_by_name_comes_back_from_vfio_pci() {
        let address = vfio_capable_nic();
        let name = netdevs_of(address).unwrap().remove(0);
        PciNic::new(address).unwrap().bind_to_vfio_pci().unwrap();
        assert_eq!(netdevs_of(address).unwrap(), Vec::<String>::new());

        prepare_interfaces(&format!("port1=kernel@{name}")).unwrap();
        assert_eq!(netdevs_of(address).unwrap(), ["port1"]);

        // A restart finds it under the name the first start gave it.
        prepare_interfaces(&format!("port1=kernel@{name}")).unwrap();
        assert_eq!(netdevs_of(address).unwrap(), ["port1"]);

        // Given by its own name, with no `kernel@`.
        PciNic::new(address).unwrap().bind_to_vfio_pci().unwrap();
        let name = {
            // The kernel names it afresh when it comes back.
            PciNic::new(address)
                .unwrap()
                .release_from_vfio_pci()
                .unwrap();
            let name = netdevs_of(address).unwrap().remove(0);
            PciNic::new(address).unwrap().bind_to_vfio_pci().unwrap();
            name
        };
        prepare_interfaces(&name).unwrap();
        assert_eq!(netdevs_of(address).unwrap(), [name]);
    }
}
