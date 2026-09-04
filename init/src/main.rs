// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
#![deny(clippy::pedantic, missing_docs)]

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;

use args::{
    AsFinalizedMemFile, CmdArgs, DpdkDriverConfigSection, DriverConfigSection, LaunchConfiguration,
    Parser, PortArg,
};
use command_fds::{CommandFdExt, FdMapping};
use hardware::NodeAttributes;
use hardware::nic::{BindToVfioPci, PciNic};
use hardware::pci::address::PciAddress;
use hardware::support::{DpdkDriverType, SupportedDevice};
use nix::mount::MsFlags;
use tracing::{Level, debug, error, info, span, warn};

/// Where the dataplane is installed. `exec`'d, not spawned: this process has nothing left to do
/// once it has prepared the hardware, and staying alive as a parent would only add a layer between
/// the supervisor and the process that matters.
const DATAPLANE_BINARY: &str = "/bin/dataplane";

/// Hugetlbfs mount points, and how much to back each with.
///
/// Mounting these is best-effort. The dataplane asks the EAL for `--in-memory`, which backs its
/// hugepages with memfd rather than files under a mount, so it starts without them; a mount is
/// what a multi-process DPDK setup would need, and what makes the pages visible to an operator
/// looking at the filesystem.
const HUGETLBFS_MOUNTS: &[(&str, &str)] = &[
    ("/dev/hugepages/1G", "pagesize=1G,size=20G,rw"),
    ("/dev/hugepages/2M", "pagesize=2M,size=128M,rw"),
];

/// A device named in the configuration, resolved against the hardware actually present.
struct ResolvedDevice {
    address: PciAddress,
    supported: SupportedDevice,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_file(true)
        .with_level(true)
        .with_line_number(true)
        .init();
}

/// Mount hugetlbfs where DPDK expects to find it.
///
/// Best-effort and deliberately not fatal. A mount that is already there is success, and a mount
/// this process is not privileged enough to make is a warning rather than a failure, because
/// `--in-memory` means the dataplane can still get its pages. Failing here would turn a
/// nice-to-have into a startup blocker.
fn mount_hugepages() {
    for (path, options) in HUGETLBFS_MOUNTS {
        if let Err(e) = std::fs::DirBuilder::new().recursive(true).create(path) {
            warn!("could not create {path}: {e}; skipping this hugetlbfs mount");
            continue;
        }
        match nix::mount::mount(
            Some("hugetlbfs"),
            *path,
            Some("hugetlbfs"),
            MsFlags::empty(),
            Some(*options),
        ) {
            Ok(()) => info!("mounted hugetlbfs at {path} ({options})"),
            Err(nix::errno::Errno::EBUSY) => {
                debug!("hugetlbfs already mounted at {path}");
            }
            Err(e) => warn!(
                "could not mount hugetlbfs at {path}: {e}. The dataplane uses --in-memory and \
                 should still start, but hugepages will not be visible under {path}."
            ),
        }
    }
}

/// Resolve every PCI device the configuration names against a scan of the machine.
///
/// Reports what it found rather than failing on the first surprise: an operator debugging a NIC
/// that will not come up wants the whole picture, not the first line of it. A device that is
/// missing or unrecognised is an error, but every device is examined before any error is returned.
fn resolve_devices(dpdk: &DpdkDriverConfigSection) -> Result<Vec<ResolvedDevice>, String> {
    info!("scanning hardware");
    let scan = hardware::Node::scan_all();

    // Every PCI device on the machine, by address.
    let present: BTreeMap<PciAddress, &hardware::pci::PciDeviceAttributes> = scan
        .iter()
        .filter_map(|node| match node.attributes() {
            Some(NodeAttributes::Pci(pci)) => Some((pci.address(), pci)),
            _ => None,
        })
        .collect();
    debug!("hardware scan found {} PCI device(s)", present.len());

    let mut resolved = Vec::new();
    let mut problems = Vec::new();

    for interface in &dpdk.interfaces {
        let name = &interface.interface;
        let Some(PortArg::PCI(ebdf)) = &interface.port else {
            problems.push(format!(
                "interface '{name}' does not name a PCI device; the DPDK driver requires one"
            ));
            continue;
        };
        let address = match PciAddress::try_from(ebdf.to_string().as_str()) {
            Ok(address) => address,
            Err(e) => {
                problems.push(format!(
                    "interface '{name}' names an invalid PCI address: {e}"
                ));
                continue;
            }
        };
        let Some(attributes) = present.get(&address) else {
            problems.push(format!(
                "interface '{name}' names PCI device {address}, which is not present on this machine"
            ));
            continue;
        };
        match SupportedDevice::try_from((attributes.vendor_id(), attributes.device_id())) {
            Ok(supported) => {
                info!(
                    "interface '{name}' is {address}: {supported} ({driver})",
                    driver = DpdkDriverType::from(supported)
                );
                resolved.push(ResolvedDevice { address, supported });
            }
            Err(_) => problems.push(format!(
                "interface '{name}' names PCI device {address}, which is not a supported network \
                 device (vendor {vendor:?}, device {device:?})",
                vendor = attributes.vendor_id(),
                device = attributes.device_id(),
            )),
        }
    }

    if problems.is_empty() {
        Ok(resolved)
    } else {
        Err(problems.join("\n  "))
    }
}

/// Put each device into the state DPDK needs to attach to it.
///
/// The two cases are opposites, and getting them the wrong way round breaks the device rather than
/// merely failing:
///
/// - **`vfio-pci`**: unbind from the kernel driver and bind to `vfio-pci`, which is what gives a
///   userspace process direct access to the device. The NIC disappears from `ip link` and
///   `ethtool` as a result.
/// - **bifurcated** (mlx5): leave the kernel driver exactly where it is. DPDK attaches alongside it
///   through the RDMA verbs interface, and unbinding would take away the very thing it attaches
///   through.
fn prepare_devices(devices: &[ResolvedDevice]) -> Result<(), String> {
    for device in devices {
        let driver = DpdkDriverType::from(device.supported);
        match driver {
            DpdkDriverType::Bifurcated => {
                info!(
                    "{} ({}) uses a bifurcated driver; leaving it bound to the kernel",
                    device.supported, device.address
                );
            }
            DpdkDriverType::VfioPci => {
                info!(
                    "binding {} ({}) to vfio-pci",
                    device.supported, device.address
                );
                let mut nic = PciNic::new(device.address)
                    .map_err(|e| format!("cannot open PCI device {}: {e}", device.address))?;
                nic.bind_to_vfio_pci()
                    .map_err(|e| format!("failed to bind {} to vfio-pci: {e}", device.address))?;
            }
        }
    }
    Ok(())
}

/// Hand the configuration to the dataplane and become it.
///
/// The configuration travels as a sealed memfd rather than as arguments: it is passed once,
/// immutably, alongside a hash of itself, so the dataplane can verify it received what was sent and
/// then read it in place. `exec` replaces this process, so the descriptors below are the only thing
/// that outlives it.
fn exec_dataplane(config: LaunchConfiguration) -> ! {
    let mut config_file = config.finalize();
    let integrity_check = config_file.integrity_check().finalize().to_owned_fd();
    let config_fd = config_file.to_owned_fd();

    info!("handing configuration to {DATAPLANE_BINARY} and exec'ing it");

    let error = std::process::Command::new(DATAPLANE_BINARY)
        .fd_mappings(vec![
            FdMapping {
                parent_fd: integrity_check,
                child_fd: LaunchConfiguration::STANDARD_INTEGRITY_CHECK_FD,
            },
            FdMapping {
                parent_fd: config_fd,
                child_fd: LaunchConfiguration::STANDARD_CONFIG_FD,
            },
        ])
        .unwrap_or_else(|e| {
            error!("failed to map configuration descriptors for the dataplane: {e}");
            std::process::exit(1);
        })
        .env_clear()
        .env("RUST_BACKTRACE", "full")
        .exec();

    // `exec` only returns on failure.
    error!("failed to exec {DATAPLANE_BINARY}: {error}");
    std::process::exit(1);
}

/// Give up, having said why.
///
/// This program either succeeds or requires outside intervention, so there is nothing to do with an
/// error but report it clearly and stop.
fn fail(context: &str, detail: &str) -> ! {
    error!("{context}:\n  {detail}");
    error!("dataplane initialization failed");
    std::process::exit(1);
}

fn main() {
    init_tracing();
    let main = span!(Level::INFO, "init");
    let _main = main.enter();

    let config = match LaunchConfiguration::try_from(CmdArgs::parse()) {
        Ok(config) => config,
        Err(e) => fail("invalid command line arguments", &e.to_string()),
    };

    match &config.driver {
        DriverConfigSection::Dpdk(dpdk) => {
            mount_hugepages();
            let devices = match resolve_devices(dpdk) {
                Ok(devices) => devices,
                Err(problems) => fail("cannot use the requested network devices", &problems),
            };
            if devices.is_empty() {
                fail(
                    "no network devices to drive",
                    "the DPDK driver was selected but no interfaces were configured",
                );
            }
            if let Err(e) = prepare_devices(&devices) {
                fail("failed to prepare a network device for DPDK", &e);
            }
            info!("{} network device(s) ready for DPDK", devices.len());
        }
        DriverConfigSection::Kernel(_) => {
            // The kernel driver uses interfaces exactly as the kernel presents them, so there is no
            // hardware to prepare and nothing here to do but hand over.
            info!("kernel driver selected; no device preparation required");
        }
    }

    exec_dataplane(config);
}
