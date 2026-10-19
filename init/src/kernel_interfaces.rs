// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Give each kernel-driver interface its configured name.
//!
//! The kernel driver, management, and the router all find an interface by its configured name, so
//! that has to be the kernel's name for it. An interface given as `pci@ADDR` or `kernel@IFNAME` is
//! renamed to its configured name. A PCI device that a DPDK run left on vfio-pci has no interface
//! at all, so it is first handed back to its kernel driver.

use std::time::Duration;

use args::{InterfaceArg, KernelDriverConfigSection, PortArg};
use hardware::nic::{PciNic, ReleaseFromVfioPci, netdevs_of};
use hardware::pci::address::PciAddress;
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
        for interface in &kernel.interfaces {
            if let Err(e) = prepare_one(&handle, interface).await {
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

async fn prepare_one(handle: &rtnetlink::Handle, interface: &InterfaceArg) -> Result<(), String> {
    let wanted = interface.interface.to_string();
    let current = match &interface.port {
        None => return Ok(()),
        Some(PortArg::KERNEL(name)) => name.to_string(),
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
    use hardware::nic::{BindToVfioPci, PciNic, netdevs_of};
    use hardware::pci::address::PciAddress;
    use hardware::support::DpdkDriverType;
    use rtnetlink::LinkUnspec;

    use super::prepare;

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
}
