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
use futures::TryStreamExt;
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
/// exclusive RDMA namespace mode (`ib_core.netns_mode=0`). In the default shared mode the RDMA
/// device stays visible from every namespace. Reload retrains links and changes ifindices.
/// The descriptor names the destination without a `/run/netns` mount.
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
            Ok(_) => info!(
                "{} is now in the datapath network namespace",
                device.address
            ),
            Err(e) => problems.push(format!(
                "could not move {} into the datapath network namespace: {e}",
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

/// Put this process into the network namespace the control plane will run in.
///
/// # Why the control plane needs one at all
///
/// The dataplane's control path to the wire is a **tap** per configured interface, named exactly
/// the configured name -- that is the name FRR's configuration, the routing tables and the ACLs all
/// use. The physical device wants that name too. In the host's namespace those two collide: a tap
/// sitting on `dp0` makes udev's rename of the returning physical device fail, which strands the
/// real device under a name nothing is looking for.
///
/// A private namespace removes the collision entirely, because the physical device is never in it.
/// It also gives FRR somewhere to live where the only interfaces it can see are the ones the
/// dataplane means it to see.
///
/// # Why this happens after the devlink reload and not before
///
/// The devices are moved with a devlink reload, and a PCI device's devlink instance belongs to the
/// namespace the device is in -- which, at that point, is the host's. Entering the control
/// namespace first would put this process somewhere the devlink instance is not.
///
/// # Why `lo` has to come up
///
/// FRR binds its vty to `127.0.0.1` and the dataplane's `frr-agent` connects to it there. A fresh
/// namespace's loopback is down, so without this the two cannot talk at all -- and the failure
/// looks like an agent that will not connect rather than an interface that is down.
///
/// # Why nothing has to hold the namespace afterwards
///
/// `setns` on the main thread is inherited across `exec`, and this process has no other threads by
/// then, so the dataplane *is* in the namespace. A namespace with a process in it does not go away,
/// so there is no descriptor to keep and nothing to clean up. A namespace opened by path (the
/// `--control-netns` case) was somebody else's to begin with and stays theirs.
fn enter_control_netns(path: Option<&String>) -> Result<(), String> {
    let netns = if let Some(path) = path {
        info!("entering the control network namespace at {path}");
        NetworkNamespace::open(path)
            .map_err(|e| format!("could not open the control network namespace {path}: {e}"))?
    } else {
        info!("creating a network namespace for the control plane");
        NetworkNamespace::create()
            .map_err(|e| format!("could not create a control network namespace: {e}"))?
    };

    // `enter_with_sysfs`, not `enter`. The second half is the one that is easy to miss and it is
    // not optional here: **sysfs is tagged with the network namespace it was mounted in**, and
    // `setns` does not retag an existing mount, so a thread which merely joined the namespace still
    // reads the *old* one's `/sys`.
    //
    // The control plane depends on that in a way that is invisible until it fails. `netdev`
    // reads an interface's type from `/sys/class/net/<name>/type` and reports `Unknown` when it
    // cannot -- and `mgmt::processor::confbuild::router` rejects an interface whose type is not
    // Ethernet or Loopback. So with an inherited `/sys` every configured interface is `Unknown`,
    // every config apply fails with "Unsupported type of interface", the routing table never
    // learns the interface, and the datapath then drops every frame that arrives on it as
    // `InterfaceUnknown`. Measured: a tap reads `type = 1` under a fresh sysfs and does not exist
    // at all under an inherited one.
    //
    // The mount namespace is unshared here, on the main thread, so the dataplane inherits it across
    // `exec` and every one of its threads gets the right view. The datapath thread unshares again
    // for its own namespace, which is unaffected by this.
    netns
        .enter_with_sysfs()
        .map_err(|e| format!("could not enter the control network namespace: {e}"))?;
    info!(
        "control plane is in network namespace {}",
        hardware::netns::current()
    );

    // A current-thread runtime, so the netlink socket below is opened on *this* thread -- the one
    // that just entered the namespace. A multi-threaded runtime would open it on a worker thread
    // which is still in the namespace this process started in.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            format!("could not build a runtime to configure the control namespace: {e}")
        })?;
    runtime.block_on(bring_up_loopback())?;

    // Dropped rather than kept: this process is in the namespace, which is what holds it open.
    drop(netns);
    Ok(())
}

/// Bring `lo` up in the calling thread's network namespace.
async fn bring_up_loopback() -> Result<(), String> {
    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| format!("could not open a netlink socket in the control namespace: {e}"))?;
    let connection = tokio::spawn(connection);

    let result = async {
        let link = handle
            .link()
            .get()
            .match_name("lo".to_string())
            .execute()
            .try_next()
            .await
            .map_err(|e| format!("could not look up lo: {e}"))?
            .ok_or_else(|| "the control namespace has no loopback interface".to_string())?;
        handle
            .link()
            .set(
                rtnetlink::LinkUnspec::new_with_index(link.header.index)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(|e| format!("could not bring lo up: {e}"))
    }
    .await;

    connection.abort();
    result?;
    debug!("lo is up in the control namespace");
    Ok(())
}

/// Exec the dataplane with sealed configuration, its checksum, and the datapath namespace.
fn exec_dataplane(config: LaunchConfiguration, netns: NetworkNamespace) -> ! {
    let mut config_file = config.finalize();
    let integrity_check = config_file.integrity_check().finalize().to_owned_fd();
    let config_fd = config_file.to_owned_fd();

    info!("handing configuration to {DATAPLANE_BINARY} and exec'ing it");

    let mappings = vec![
        FdMapping {
            parent_fd: integrity_check,
            child_fd: LaunchConfiguration::STANDARD_INTEGRITY_CHECK_FD,
        },
        FdMapping {
            parent_fd: config_fd,
            child_fd: LaunchConfiguration::STANDARD_CONFIG_FD,
        },
        // The inherited descriptor keeps the namespace alive across exec.
        FdMapping {
            parent_fd: netns.into_fd(),
            child_fd: LaunchConfiguration::STANDARD_NETNS_FD,
        },
    ];

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
    let control_netns = args.control_netns().cloned();

    let config = match LaunchConfiguration::try_from(args) {
        Ok(config) => config,
        Err(e) => fail("invalid command line arguments", &e.to_string()),
    };

    // Rejected rather than ignored. The kernel driver's interfaces stay in this namespace, so a
    // control namespace would hold taps named after devices that are still here -- which is the
    // name collision the split exists to avoid.
    if control_netns.is_some() && matches!(config.driver, DriverConfigSection::Kernel(_)) {
        fail(
            "--control-netns requires the DPDK driver",
            "the control plane's taps are named after the configured interfaces, so they can only \
             exist in a namespace the physical devices are not in",
        );
    }

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

            let netns = match isolate_devices(&devices) {
                Ok(netns) => {
                    info!("datapath network namespace ready");
                    netns
                }
                Err(e) => fail("failed to isolate the network devices", &e),
            };

            // Last, because it is one-way: after this the process is somewhere the devlink
            // instances above are not, and there is no going back.
            if let Err(e) = enter_control_netns(control_netns.as_ref()) {
                fail("failed to enter the control network namespace", &e);
            }

            // Named rather than left to be discovered. The k8s client and the metrics endpoint
            // reach *out* of this process, and a fresh control namespace has no route to
            // anywhere; they have not been split onto a runtime that stays in the host's
            // namespace yet. Without `--config-dir` the dataplane will retry k8s init ten times
            // and give up, which says nothing about why.
            //
            // A warning rather than an error, because `--control-netns` names a namespace the
            // operator built, and they may well have given it a path out.
            if config
                .config_server
                .as_ref()
                .and_then(|c| c.config_dir.as_ref())
                .is_none()
            {
                warn!(
                    "the control plane is in a network namespace of its own and no \
                     --config-dir was given, so the dataplane will try to reach Kubernetes \
                     from in there. Until the host-namespace split lands, this configuration \
                     is --config-dir only."
                );
            }

            netns
        }
        DriverConfigSection::Kernel(_) => {
            // The router's adjacency resolver and FRR use the host stack on these interfaces,
            // so for now they stay in this namespace and the datapath joins it.
            info!("kernel driver selected; the datapath shares this network namespace");
            match NetworkNamespace::current() {
                Ok(netns) => netns,
                Err(e) => fail("failed to open this network namespace", &e.to_string()),
            }
        }
    };

    exec_dataplane(config, netns);
}
