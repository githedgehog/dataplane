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

/// Move every device that needs it into `netns`, so the dataplane can drive them from there.
///
/// Only bifurcated devices need this. A device bound to `vfio-pci` is a character device under
/// `/dev/vfio` that the networking stack knows nothing about, so it has no namespace to be in and
/// nothing to move -- the dataplane reaches it from wherever it likes.
///
/// mlx5 is the case that matters, and it moves with a **devlink reload**, which is not
/// interchangeable with the obvious alternative: `ip link set netns` moves the netdev and leaves
/// the RDMA device behind, and the RDMA device is the half DPDK attaches through. Only
/// [`ReloadAction::DriverReinit`] may change namespace, and the kernel enforces that.
///
/// The namespace is named by **descriptor**. That is the whole reason it can stay nameless: the
/// process is already holding the only reference that keeps it alive, and `DEVLINK_ATTR_NETNS_FD`
/// accepts exactly that, so nothing has to be registered under `/run/netns` for the kernel to know
/// which namespace is meant.
///
/// # What it costs the device
///
/// The device is torn down and re-probed, not merely moved: measured at about seven seconds for two
/// BlueField-3 ports, with a link retrain and a new ifindex on the far side. The same happens in
/// reverse when the namespace is destroyed, which is why nothing may cache an ifindex across it.
///
/// # A precondition that is not ours to set
///
/// This only works with the RDMA subsystem in exclusive mode. In shared mode `_ib_alloc_device`
/// discards the requested net, so the devlink instance moves but the RDMA device stays behind in
/// `init_net` -- and DPDK would then find nothing from inside the namespace. That is a boot-time
/// setting, `ib_core.netns_mode=0`, and it is checked here so the failure is reported where it can
/// be understood rather than as an empty device list much later.
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
    // The connection is the half that talks to the kernel; the handle only queues requests, so
    // nothing below completes unless this is being polled.
    let connection = tokio::spawn(connection);

    let mut problems = Vec::new();
    for device in bifurcated {
        let target = DevlinkHandle::new("pci", device.address.to_string());
        info!(
            "moving {} into the datapath network namespace",
            device.address
        );

        // The descriptor is borrowed for the duration of the call and stays owned by `netns`: the
        // kernel resolves it during the request and keeps its own reference to the namespace.
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

/// Create the datapath's network namespace and move the devices into it.
///
/// Returns the namespace, which the descriptor alone keeps alive. Nothing is registered under
/// `/run/netns`, so there is no name for anything to collide with and nothing to clean up: when the
/// dataplane exits, however it exits, the kernel closes the descriptor and the namespace goes.
fn isolate_devices(devices: &[ResolvedDevice]) -> Result<NetworkNamespace, String> {
    let netns = NetworkNamespace::create()
        .map_err(|e| format!("could not create a network namespace for the datapath: {e}"))?;

    // A current-thread runtime, because this is the only asynchronous thing this program does and
    // it is done before anything else exists to share a runtime with.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not build a runtime to talk to devlink: {e}"))?;

    runtime.block_on(move_devices_to_netns(devices, &netns))?;
    Ok(netns)
}

/// Hand the configuration to the dataplane and become it.
///
/// The configuration travels as a sealed memfd rather than as arguments: it is passed once,
/// immutably, alongside a hash of itself, so the dataplane can verify it received what was sent and
/// then read it in place. `exec` replaces this process, so the descriptors below are the only thing
/// that outlives it.
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

    // The namespace travels as a descriptor, and that descriptor is also what keeps it alive: this
    // process is about to be replaced, so once `exec` happens the dataplane holds the only
    // reference. Nothing is registered under `/run/netns`, so there is no name to collide with and
    // nothing to clean up -- when the dataplane exits, however it exits, the kernel closes the
    // descriptor and the namespace goes with it.
    if let Some(netns) = netns {
        mappings.push(FdMapping {
            parent_fd: netns.into_fd(),
            child_fd: LaunchConfiguration::STANDARD_NETNS_FD,
        });
    }

    let error = std::process::Command::new(DATAPLANE_BINARY)
        .fd_mappings(mappings)
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

            // Binding first, then isolation: a device is moved in the state it will be driven in,
            // and a vfio-pci device has no namespace to be moved between at all.
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
            // The kernel driver uses interfaces exactly as the kernel presents them, so there is no
            // hardware to prepare and nothing here to do but hand over.
            info!("kernel driver selected; no device preparation required");
            None
        }
    };

    exec_dataplane(config, netns);
}
