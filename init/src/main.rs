// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
#![deny(clippy::pedantic, missing_docs)]

use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;

use args::{
    AsFinalizedMemFile, CmdArgs, DpdkDriverConfigSection, DriverConfigSection, LaunchConfiguration,
    Parser, PortArg,
};
use command_fds::{CommandFdExt, FdMapping};
use devlink::{DevlinkHandle, Netns, ReloadAction};
use hardware::NodeAttributes;
use hardware::netns::NetworkNamespace;
use hardware::nic::{BindToVfioPci, PciNic};
use hardware::pci::address::PciAddress;
use hardware::support::{DpdkDriverType, SupportedDevice};
use nix::mount::MsFlags;
use tracing::{Level, debug, error, info, span, warn};

/// Installed dataplane executable. Init replaces itself with this process.
const DATAPLANE_BINARY: &str = "/bin/dataplane";

/// Optional hugetlbfs mounts. EAL uses memfd-backed hugepages with `--in-memory`.
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

/// Mount hugetlbfs on a best-effort basis.
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

/// Resolve and validate all configured PCI devices before changing any driver bindings.
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

/// Bind non-bifurcated devices to vfio-pci, removing their kernel netdevs.
/// Leave mlx5 bound to its kernel driver, which DPDK needs for RDMA verbs access.
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

/// Move bifurcated devices with devlink driver reinitialization; vfio-pci devices need no move.
///
/// Unlike moving only the netdev, devlink reload also moves the RDMA device when the host uses
/// exclusive RDMA namespace mode (`ib_core.netns_mode=0`). Reload retrains links and changes
/// ifindices. The descriptor names the destination without a `/run/netns` mount.
async fn move_devices_to_netns(
    devices: &[ResolvedDevice],
    netns: &NetworkNamespace,
) -> Result<(), String> {
    let bifurcated: Vec<&ResolvedDevice> = devices
        .iter()
        .filter(|d| {
            matches!(
                DpdkDriverType::from(d.supported),
                DpdkDriverType::Bifurcated
            )
        })
        .collect();

    for device in devices {
        if matches!(
            DpdkDriverType::from(device.supported),
            DpdkDriverType::VfioPci
        ) {
            debug!(
                "{} is bound to vfio-pci and has no network namespace to move between",
                device.address
            );
        }
    }

    if bifurcated.is_empty() {
        return Ok(());
    }

    let (connection, handle) =
        devlink::new_connection().map_err(|e| format!("could not open a devlink socket: {e}"))?;
    // Poll the connection to service requests made through the handle.
    let connection = tokio::spawn(connection);

    let mut problems = Vec::new();
    for device in bifurcated {
        let target = DevlinkHandle::new("pci", device.address.to_string());
        info!(
            "moving {} into the datapath network namespace",
            device.address
        );

        let as_fd = u32::try_from(netns.as_raw().as_raw_fd()).unwrap_or(u32::MAX);
        match handle
            .reload_into(
                &target,
                ReloadAction::DriverReinit,
                None,
                Some(Netns::Fd(as_fd)),
            )
            .await
        {
            Ok(_) => info!("{} is now in the datapath network namespace", device.address),
            Err(e) => problems.push(format!(
                "could not move {} into the namespace: {e}. If the devlink instance moved but DPDK                  later finds no device, the RDMA subsystem is in shared mode and the host needs to                  boot with ib_core.netns_mode=0.",
                device.address
            )),
        }
    }

    connection.abort();

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n  "))
    }
}

/// Create a descriptor-owned namespace and move the datapath devices into it.
fn isolate_devices(devices: &[ResolvedDevice]) -> Result<NetworkNamespace, String> {
    let netns = NetworkNamespace::create()
        .map_err(|e| format!("could not create a network namespace for the datapath: {e}"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not build a runtime to talk to devlink: {e}"))?;

    runtime.block_on(move_devices_to_netns(devices, &netns))?;
    Ok(netns)
}

/// Exec the dataplane with sealed configuration, its checksum, and an optional namespace FD.
fn exec_dataplane(config: LaunchConfiguration, netns: Option<NetworkNamespace>) -> ! {
    let mut config_file = config.finalize();
    let integrity_check = config_file.integrity_check().finalize().to_owned_fd();
    let config_fd = config_file.to_owned_fd();

    info!("handing configuration to {DATAPLANE_BINARY} and exec'ing it");

    let mut mappings = vec![
        FdMapping {
            parent_fd: integrity_check,
            child_fd: LaunchConfiguration::STANDARD_INTEGRITY_CHECK_FD,
        },
        FdMapping {
            parent_fd: config_fd,
            child_fd: LaunchConfiguration::STANDARD_CONFIG_FD,
        },
    ];

    // The inherited descriptor keeps the namespace alive across exec.
    if let Some(netns) = netns {
        mappings.push(FdMapping {
            parent_fd: netns.into_fd(),
            child_fd: LaunchConfiguration::STANDARD_NETNS_FD,
        });
    }

    let mut command = std::process::Command::new(DATAPLANE_BINARY);
    command.fd_mappings(mappings).unwrap_or_else(|e| {
        error!("failed to map configuration descriptors for the dataplane: {e}");
        std::process::exit(1);
    });

    // Preserve Kubernetes configuration and any backtrace setting supplied by the launcher.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        command.env("RUST_BACKTRACE", "full");
    }
    let error = command.exec();

    // `exec` only returns on failure.
    error!("failed to exec {DATAPLANE_BINARY}: {error}");
    std::process::exit(1);
}

/// Report an initialization failure and exit.
fn fail(context: &str, detail: &str) -> ! {
    error!("{context}:\n  {detail}");
    error!("dataplane initialization failed");
    std::process::exit(1);
}

fn main() {
    init_tracing();
    let main = span!(Level::INFO, "init");
    let _main = main.enter();

    let args = CmdArgs::parse();
    if args.is_informational() {
        // Only the dataplane binary contains the complete tracing target registry.
        let error = std::process::Command::new(DATAPLANE_BINARY)
            .args(std::env::args_os().skip(1))
            .exec();
        fail("failed to execute dataplane", &error.to_string());
    }

    let config = match LaunchConfiguration::try_from(args) {
        Ok(config) => config,
        Err(e) => fail("invalid command line arguments", &e.to_string()),
    };

    let netns = match &config.driver {
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

            if dpdk.netns {
                match isolate_devices(&devices) {
                    Ok(netns) => {
                        info!("datapath network namespace ready");
                        Some(netns)
                    }
                    Err(e) => fail("failed to isolate the network devices", &e),
                }
            } else {
                None
            }
        }
        DriverConfigSection::Kernel(_) => {
            info!("kernel driver selected; no device preparation required");
            None
        }
    };

    exec_dataplane(config, netns);
}
