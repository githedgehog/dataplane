// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
#![deny(clippy::pedantic, missing_docs)]

mod frr;
mod hugepages;
mod netns_names;
mod socket;
mod supervisor;

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
use supervisor::{Outcome, Process, Supervisor, SupervisorError};
use tracing::{Level, debug, error, info, span, warn};

/// Where the dataplane is installed.
const DATAPLANE_BINARY: &str = "/bin/dataplane";

/// Wrap the dataplane in `perf record`, for development.
///
/// An environment variable rather than a flag for the same reason `DATAPLANE_PYROSCOPE_URL` is
/// one: a controller owns the dataplane's argv in a fabric, so a flag is a thing nobody can set.
/// Its value is passed to `perf` verbatim, e.g.
/// `DATAPLANE_DEV_PERF="record -F 99 --call-graph fp -o /var/log/dataplane/perf.data"`.
///
/// Unset in every shipped image, and `perf` is not in one -- this does nothing unless someone has
/// deliberately built an image that carries it.
const DEV_PERF_ENV: &str = "DATAPLANE_DEV_PERF";

/// Where `perf` is expected to be, when [`DEV_PERF_ENV`] asks for it.
const DEV_PERF_BINARY: &str = "/bin/perf";

/// Where a profile is written when [`DEV_PERF_ENV`] does not say.
///
/// This survives the container being restarted and the rest of its filesystem does not, which is
/// the whole point: the restart that ends a run is often the thing you wanted the profile of.
const DEV_PERF_DIR: &str = "/var/run/dataplane";

/// Optional hugetlbfs mounts. EAL uses memfd-backed hugepages with `--in-memory`.
/// Omit mount size caps; the hugepage pool limits available memory.
const HUGETLBFS_MOUNTS: &[(&str, &str)] = &[
    ("/dev/hugepages/1G", "pagesize=1G,rw"),
    ("/dev/hugepages/2M", "pagesize=2M,rw"),
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
fn resolve_devices(
    dpdk: &DpdkDriverConfigSection,
    scan: &hardware::Node,
) -> Result<Vec<ResolvedDevice>, String> {
    if dpdk.interfaces.is_empty() {
        return Err("the DPDK driver was selected but no interfaces were configured".into());
    }
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

/// Whether the RDMA subsystem will let a network namespace own a device.
///
/// `ib_core.netns_mode=0` selects exclusive mode at boot. Runtime changes require
/// that no network namespaces other than the initial one exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RdmaNetnsMode {
    /// A device belongs to one namespace.
    Exclusive,
    /// Devices remain in the initial namespace and are visible across namespaces.
    Shared,
    /// `ib_core` is not loaded, or the parameter is not where it is expected.
    Unknown,
}

/// Where the kernel exposes the RDMA namespace mode.
const IB_CORE_NETNS_MODE: &str = "/sys/module/ib_core/parameters/netns_mode";

/// Interpret the contents of [`IB_CORE_NETNS_MODE`].
fn parse_netns_mode(raw: &str) -> RdmaNetnsMode {
    match raw.trim() {
        "N" | "0" => RdmaNetnsMode::Exclusive,
        "Y" | "1" => RdmaNetnsMode::Shared,
        other => {
            warn!("{IB_CORE_NETNS_MODE} contained {other:?}, which is neither Y nor N");
            RdmaNetnsMode::Unknown
        }
    }
}

/// Read the RDMA namespace mode from the `ib_core` module parameter.
fn rdma_netns_mode() -> RdmaNetnsMode {
    match std::fs::read_to_string(IB_CORE_NETNS_MODE) {
        Ok(raw) => parse_netns_mode(&raw),
        Err(e) => {
            debug!("could not read {IB_CORE_NETNS_MODE}: {e}");
            RdmaNetnsMode::Unknown
        }
    }
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

    // Shared visibility may still let the PMD reach the device, so this is diagnostic only.
    if !bifurcated.is_empty() {
        match rdma_netns_mode() {
            RdmaNetnsMode::Exclusive => {}
            RdmaNetnsMode::Shared => warn!(
                "RDMA shared mode keeps devices {} in init_net after devlink moves. If the PMD \
                 cannot find them, boot with ib_core.netns_mode=0 or omit --datapath-netns. \
                 Switching to exclusive mode at runtime requires no other network namespaces.",
                bifurcated
                    .iter()
                    .map(|d| d.address.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            RdmaNetnsMode::Unknown => warn!(
                "could not determine the RDMA namespace mode; if the datapath finds no device, \
                 check `rdma system show` for `netns exclusive`"
            ),
        }
    }

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

/// Raise every interface in the init-owned datapath namespace, including loopback.
/// Namespace moves clear `IFF_UP`, and bifurcated devices need the kernel netdev up for carrier.
/// Enumerate by ifindex because devlink reload may change interface names.
async fn bring_up_interfaces_in_netns() -> Result<(), String> {
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|e| format!("could not open a netlink socket: {e}"))?;
    let connection = tokio::spawn(connection);

    let result = async {
        let mut links = handle.link().get().execute();
        let mut problems = Vec::new();
        let mut brought_up = 0usize;
        loop {
            match links.try_next().await {
                Ok(Some(link)) => {
                    let index = link.header.index;
                    let name = link
                        .attributes
                        .iter()
                        .find_map(|a| match a {
                            rtnetlink::packet_route::link::LinkAttribute::IfName(n) => {
                                Some(n.clone())
                            }
                            _ => None,
                        })
                        .unwrap_or_else(|| format!("index {index}"));
                    match handle
                        .link()
                        .set(rtnetlink::LinkUnspec::new_with_index(index).up().build())
                        .execute()
                        .await
                    {
                        Ok(()) => {
                            info!("brought {name} up in the datapath network namespace");
                            if name != "lo" {
                                brought_up += 1;
                            }
                        }
                        Err(e) => problems.push(format!("could not bring '{name}' up: {e}")),
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    problems.push(format!("could not list interfaces: {e}"));
                    break;
                }
            }
        }
        // Counted excluding `lo`, which is always there and says nothing about whether the move
        // landed. Not an error either way: a vfio-pci device has no netdev to bring up at all.
        if brought_up == 0 && problems.is_empty() {
            warn!(
                "the datapath namespace holds no interface but loopback; expected for a vfio-pci \
                 device, and a sign the move did not land for a bifurcated one"
            );
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }
    .await;

    connection.abort();
    result
}

/// Raise datapath interfaces on a temporary thread, preserving the caller's namespace.
fn bring_up_datapath_interfaces(netns: &NetworkNamespace) -> Result<(), String> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                netns
                    .enter()
                    .map_err(|e| format!("could not enter the datapath namespace: {e}"))?;
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("could not build a runtime for netlink: {e}"))?
                    .block_on(bring_up_interfaces_in_netns())
            })
            .join()
            .map_err(|_| "the thread bringing datapath interfaces up panicked".to_string())?
    })
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
    // The move left them down; a bifurcated device's port follows its netdev, so without this the
    // datapath starts cleanly and carries nothing.
    bring_up_datapath_interfaces(&netns)?;
    Ok(netns)
}

/// Move kernel-driver netdevs into the datapath namespace with `IFLA_NET_NS_FD`.
/// Moving clears their addresses/routes and leaves them administratively down.
/// The driver uses `AF_PACKET`; control-plane addresses belong on the matching taps.
async fn move_interfaces_to_netns(
    interfaces: &[String],
    netns: &NetworkNamespace,
) -> Result<(), String> {
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|e| format!("could not open a netlink socket: {e}"))?;
    let connection = tokio::spawn(connection);

    let result = async {
        let mut problems = Vec::new();
        for name in interfaces {
            // Looked up by name and moved by index. The name is what the configuration gives, but
            // it is also what a tap is about to take in the control namespace, so resolving to an
            // index first means the move cannot be redirected by a later name collision.
            let link = match handle
                .link()
                .get()
                .match_name(name.clone())
                .execute()
                .try_next()
                .await
            {
                Ok(Some(link)) => link,
                Ok(None) => {
                    problems.push(format!("interface '{name}' does not exist"));
                    continue;
                }
                Err(e) => {
                    problems.push(format!("could not look up interface '{name}': {e}"));
                    continue;
                }
            };

            info!("moving {name} into the datapath network namespace");
            // The descriptor is borrowed for this call only; the kernel resolves it during the
            // request and takes its own reference to the namespace.
            if let Err(e) = handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(link.header.index)
                        .setns_by_fd(netns.as_raw().as_raw_fd())
                        .build(),
                )
                .execute()
                .await
            {
                problems.push(format!("could not move '{name}' into the namespace: {e}"));
                continue;
            }
            info!("{name} is now in the datapath network namespace");
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("\n  "))
        }
    }
    .await;

    connection.abort();
    result
}

/// Create the datapath's network namespace and move the kernel driver's interfaces into it.
///
/// The kernel-driver twin of [`isolate_devices`], with the same ownership rule: the descriptor
/// alone keeps the namespace alive, nothing is registered under `/run/netns`, and when this process
/// exits the kernel returns the interfaces to where they came from.
fn isolate_interfaces(interfaces: &[String]) -> Result<NetworkNamespace, String> {
    let netns = NetworkNamespace::create()
        .map_err(|e| format!("could not create a network namespace for the datapath: {e}"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not build a runtime to talk to netlink: {e}"))?;

    runtime.block_on(move_interfaces_to_netns(interfaces, &netns))?;
    // Same reason as the DPDK path. This one was covered by an init container running
    // `ip l set dev <iface> up` in shell, which is why only DPDK ever showed the hole.
    bring_up_datapath_interfaces(&netns)?;
    Ok(netns)
}

/// Choose the control namespace and return a descriptor for the original namespace.
/// Create a private namespace only when init also starts FRR. External FRR must
/// share the caller's namespace unless `--control-netns` explicitly selects another.
/// When the control plane stays put, the original namespace is the current one.
fn place_control_plane(
    path: Option<&String>,
    supervise_frr: bool,
) -> Result<NetworkNamespace, String> {
    if path.is_none() && !supervise_frr {
        info!(
            "the control plane stays in the namespace this process started in: FRR is not ours to \
             start, so it is somewhere we cannot follow, and it has to see the taps"
        );
        return NetworkNamespace::current()
            .map_err(|e| format!("could not open the current network namespace: {e}"));
    }
    enter_control_netns(path)
}

/// Enter the selected control namespace and bring up loopback.
/// Do this after moving the NICs, while their devlink instances are still reachable,
/// and before spawning children so they inherit the control namespace.
///
/// The process holds the control namespace alive. Return a descriptor for the
/// original namespace so the dataplane can create its host-facing runtime there.
fn enter_control_netns(path: Option<&String>) -> Result<NetworkNamespace, String> {
    // Opened *before* the move, because afterwards there is no way to name it. `/proc/self/ns/net`
    // always means "the namespace this thread is in now", so asking after `setns` returns the
    // control namespace and the way back is lost. The dataplane needs it: its Kubernetes client,
    // its metrics endpoint and its Pyroscope pushes all reach outside the fabric, and the control
    // namespace is a place with no route anywhere.
    let host = NetworkNamespace::open("/proc/self/ns/net")
        .map_err(|e| format!("could not open the current network namespace: {e}"))?;

    let netns = if let Some(path) = path {
        info!("entering the control network namespace at {path}");
        NetworkNamespace::open(path)
            .map_err(|e| format!("could not open the control network namespace {path}: {e}"))?
    } else {
        info!("creating a network namespace for the control plane");
        NetworkNamespace::create()
            .map_err(|e| format!("could not create a control network namespace: {e}"))?
    };

    // Mount a fresh sysfs after entering the control namespace. `setns` alone leaves
    // /sys showing the old namespace, so netdev cannot identify the taps correctly.
    // Children inherit this private mount namespace; datapath threads make their own.
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
    Ok(host)
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

/// Anything that can go wrong between "the hardware is ready" and "the gateway is running".
#[derive(Debug, thiserror::Error)]
enum HandoffError {
    /// The datapath namespace descriptor could not be duplicated for the dataplane.
    #[error("could not duplicate the datapath network namespace descriptor: {0}")]
    DuplicateNetns(#[source] std::io::Error),

    /// Two descriptors wanted the same number in the child.
    #[error("could not place the dataplane's descriptors: {0}")]
    PlaceDescriptors(#[source] command_fds::FdMappingCollision),

    /// A runtime for the supervisor could not be built.
    #[error("could not build a runtime to supervise the gateway: {0}")]
    Runtime(#[source] std::io::Error),

    /// A gateway socket could not be cleared before startup.
    #[error("could not clear stale socket {path}: {source}")]
    Socket {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// FRR could not be worked out well enough to start it.
    #[error(transparent)]
    Frr(#[from] frr::FrrError),

    /// Supervision itself failed.
    #[error(transparent)]
    Supervisor(#[from] SupervisorError),
}

/// Pass sealed configuration, its integrity hash, and duplicated namespace descriptors.
/// Init retains its namespace descriptors until the gateway shuts down.
fn dataplane_process(
    config: LaunchConfiguration,
    netns: &NetworkNamespace,
    host_netns: &NetworkNamespace,
) -> Result<Process, HandoffError> {
    let mut config_file = config.finalize();
    let integrity_check = config_file.integrity_check().finalize().to_owned_fd();
    let config_fd = config_file.to_owned_fd();

    let mappings = vec![
        FdMapping {
            parent_fd: integrity_check,
            child_fd: LaunchConfiguration::STANDARD_INTEGRITY_CHECK_FD,
        },
        FdMapping {
            parent_fd: config_fd,
            child_fd: LaunchConfiguration::STANDARD_CONFIG_FD,
        },
        FdMapping {
            parent_fd: netns
                .as_raw()
                .try_clone_to_owned()
                .map_err(HandoffError::DuplicateNetns)?,
            child_fd: LaunchConfiguration::STANDARD_NETNS_FD,
        },
        // The namespace this process started in: the dataplane's way out to Kubernetes, its
        // metrics scraper and Pyroscope. Also duplicated rather than handed over: once the control
        // plane has moved, this process's copy is the only thing on our side still referring to
        // it, and a supervisor that outlives one dataplane has to hand the next one the same way
        // back.
        FdMapping {
            parent_fd: host_netns
                .as_raw()
                .try_clone_to_owned()
                .map_err(HandoffError::DuplicateNetns)?,
            child_fd: LaunchConfiguration::STANDARD_HOST_NETNS_FD,
        },
    ];

    let mut command = match std::env::var(DEV_PERF_ENV) {
        Ok(args) if !args.trim().is_empty() => {
            // Development only. `perf record -- dataplane ...` rather than attaching from a
            // sidecar: the dataplane's pid is not knowable from outside without `hostPID` and a
            // search, and being its parent is the one way to have it from the start. It also
            // means the very first packets are sampled, which attaching never manages.
            //
            // The descriptors below survive this. They are placed at 30/40/50, well clear of
            // anything perf allocates for itself, and `perf record` execs the target rather than
            // closing what it inherited -- which matters, because the dataplane decides it was
            // launched by an init at all by checking that they are present.
            //
            // Split on whitespace: these are perf's own arguments, written by whoever set the
            // variable, and perf's flags do not contain spaces. A shell would be the alternative
            // and is a worse one in a pid-1 supervisor.
            let mut perf = std::process::Command::new(DEV_PERF_BINARY);
            let given: Vec<&str> = args.split_whitespace().collect();
            perf.args(&given);

            // Defaulted, not forced: an explicit `-o` in the variable wins. Absent one, the
            // profile goes somewhere that outlives the container. Everything else a container
            // writes is on its own filesystem and goes away with it, which for a profile means
            // the restart that ended the run also destroys the evidence about it.
            if !given.iter().any(|a| *a == "-o" || *a == "--output") {
                if let Err(e) = std::fs::create_dir_all(DEV_PERF_DIR) {
                    warn!("could not create {DEV_PERF_DIR} for a perf profile: {e}");
                }
                perf.arg("-o").arg(format!("{DEV_PERF_DIR}/perf.data"));
            }
            // perf appends `.<YYYYMMDDHHMMSSmm>` itself, so successive runs do not overwrite one
            // another in a directory that persists across restarts. Left to perf rather than
            // composed here because perf also renames on `--switch-output`, and two things
            // naming the same file differently is how you lose one of them.
            if !given.iter().any(|a| *a == "--timestamp-filename") {
                perf.arg("--timestamp-filename");
            }

            perf.arg("--").arg(DATAPLANE_BINARY);
            warn!(
                "{DEV_PERF_ENV} is set: running the dataplane under `{DEV_PERF_BINARY} {args}`. \
                 This is a development aid, it costs performance, and the profile is only written \
                 if the process is allowed to shut down cleanly."
            );
            perf
        }
        _ => std::process::Command::new(DATAPLANE_BINARY),
    };
    command
        .fd_mappings(mappings)
        .map_err(HandoffError::PlaceDescriptors)?;

    // Preserve the launch environment and any caller-supplied backtrace setting.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        command.env("RUST_BACKTRACE", "full");
    }

    Ok(Process::new("dataplane", command))
}

/// Prepare and supervise the gateway.
/// When init owns FRR, start dataplane, watchfrr, and agent in that order, waiting
/// for each socket before starting its consumer.
async fn run_gateway(
    config: LaunchConfiguration,
    netns: NetworkNamespace,
    host_netns: NetworkNamespace,
    supervise_frr: bool,
) -> Result<Outcome, HandoffError> {
    // Taken before the configuration is consumed below.
    let control_plane_socket = config.routing.control_plane_socket.clone();
    let agent_socket = config.routing.frr_agent_socket.clone();

    let supervisor = Supervisor::new()?;

    // Prepare FRR's directories before the dataplane binds its control-plane socket there.
    let daemons = if supervise_frr {
        let (config_dir, daemon_dir) = frr::install();
        let daemons = frr::enabled_daemons(&config_dir, &daemon_dir)?;
        frr::prepare_state_dir(&frr::state_dir())?;
        Some(daemons)
    } else {
        None
    };

    // Clear owned endpoints before any child starts, including configured paths outside /run/frr.
    for path in [
        Some(control_plane_socket.as_str()),
        supervise_frr.then_some(agent_socket.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        socket::remove_stale(std::path::Path::new(path)).map_err(|source| {
            HandoffError::Socket {
                path: path.into(),
                source,
            }
        })?;
    }

    let dataplane = dataplane_process(config, &netns, &host_netns)?;
    let dataplane = if supervise_frr {
        dataplane.ready_when_socket_exists(control_plane_socket)
    } else {
        // Nothing here is waiting on it, so there is nothing to gain by waiting: FRR is in a
        // container of its own and already has to tolerate starting in any order.
        dataplane
    };
    let mut processes = vec![dataplane];

    if let Some(daemons) = daemons {
        processes.push(frr::watchfrr(&daemons));
        processes.push(frr::agent(&agent_socket));
    }

    Ok(supervisor.run(processes).await?)
}

/// Start the gateway and stay as its supervisor, returning the status this process should exit
/// with.
///
/// A **current-thread** runtime, and this matters more than it looks. Children inherit the network
/// and mount namespaces of the thread that forks them, and the namespace work above was done on
/// this thread. A multi-threaded runtime would spawn from a worker that is still where this process
/// started, and the dataplane would come up unable to see its own hardware.
fn supervise_gateway(
    config: LaunchConfiguration,
    netns: NetworkNamespace,
    host_netns: NetworkNamespace,
    supervise_frr: bool,
) -> i32 {
    // Retain the control descriptor alongside the datapath and host descriptors until shutdown.
    let _control_namespace = netns_names::publish(Some(&netns), Some(&host_netns))
        .unwrap_or_else(|e| fail("could not publish network namespace names", &e.to_string()));

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(HandoffError::Runtime)
    {
        Ok(runtime) => runtime,
        Err(e) => fail("could not start the gateway", &e.to_string()),
    };

    match runtime.block_on(run_gateway(config, netns, host_netns, supervise_frr)) {
        Ok(Outcome::Exited { name, report }) => {
            error!("{name} {report}");
            report.as_exit_code()
        }
        // A requested stop is a successful one. The orchestrator asked, and everything came down.
        Ok(Outcome::Signalled { signal }) => {
            info!("stopped on {signal}");
            0
        }
        Err(e) => fail("the gateway failed", &e.to_string()),
    }
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
    let supervise_frr = args.supervise_frr();

    let mut config = match LaunchConfiguration::try_from(args) {
        Ok(config) => config,
        Err(e) => fail("invalid command line arguments", &e.to_string()),
    };

    // Record the plan after the driver borrow ends and before sealing the configuration.
    let mut hugepage_plan = None;
    let (netns, host_netns) = match &config.driver {
        DriverConfigSection::Dpdk(dpdk) => {
            mount_hugepages();
            info!("scanning hardware");
            let scan = hardware::Node::scan_all();
            let devices = match resolve_devices(dpdk, &scan) {
                Ok(devices) => devices,
                Err(problems) => fail("cannot use the requested network devices", &problems),
            };
            // Check hugepage capacity on the NICs' nodes before changing device bindings.
            hugepage_plan = Some(
                hugepages::reserve_for(
                    &devices.iter().map(|d| d.address).collect::<Vec<_>>(),
                    &scan,
                )
                .unwrap_or_else(|e| fail("hugepage configuration is unusable", &e)),
            );
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
            // instances above are not, and there is no going back. It hands back the namespace
            // we are leaving, which is the dataplane's way out to Kubernetes, its metrics
            // scraper and Pyroscope.
            let host_netns = match place_control_plane(control_netns.as_ref(), supervise_frr) {
                Ok(host_netns) => host_netns,
                Err(e) => fail("failed to enter the control network namespace", &e),
            };

            (netns, host_netns)
        }
        DriverConfigSection::Kernel(kernel) => {
            // No hardware to prepare -- these are interfaces the kernel already drives -- but the
            // namespace work is the same as DPDK's, and for the same reasons: an interface the host
            // stack still owns is one it will route, ARP for and terminate connections on with no
            // dataplane involvement. See `move_interfaces_to_netns` for what moving them costs.
            info!("kernel driver selected; no device preparation required");
            let names: Vec<String> = kernel
                .interfaces
                .iter()
                .map(|i| i.interface.to_string())
                .collect();
            let netns = match isolate_interfaces(&names) {
                Ok(netns) => {
                    info!("datapath network namespace ready");
                    netns
                }
                Err(e) => fail("failed to isolate the network interfaces", &e),
            };

            let host_netns = match place_control_plane(control_netns.as_ref(), supervise_frr) {
                Ok(host_netns) => host_netns,
                Err(e) => fail("failed to enter the control network namespace", &e),
            };

            (netns, host_netns)
        }
    };

    // Pass the checked per-node requirement to EAL before sealing the configuration.
    if let DriverConfigSection::Dpdk(dpdk) = &mut config.driver {
        dpdk.hugepages = hugepage_plan;
    }

    std::process::exit(supervise_gateway(config, netns, host_netns, supervise_frr));
}

#[cfg(test)]
mod rdma_netns_mode_test {
    use super::{IB_CORE_NETNS_MODE, RdmaNetnsMode, parse_netns_mode, rdma_netns_mode};

    #[test]
    fn shared_and_exclusive_are_both_recognised() {
        assert_eq!(parse_netns_mode("Y"), RdmaNetnsMode::Shared);
        assert_eq!(parse_netns_mode("1"), RdmaNetnsMode::Shared);
        assert_eq!(parse_netns_mode("Y\n"), RdmaNetnsMode::Shared);
        assert_eq!(parse_netns_mode("N"), RdmaNetnsMode::Exclusive);
        assert_eq!(parse_netns_mode("0"), RdmaNetnsMode::Exclusive);
        assert_eq!(parse_netns_mode("N\n"), RdmaNetnsMode::Exclusive);
        assert_eq!(parse_netns_mode("maybe"), RdmaNetnsMode::Unknown);
        assert_eq!(parse_netns_mode(""), RdmaNetnsMode::Unknown);
    }

    #[test]
    fn a_readable_parameter_is_never_reported_unknown() {
        let Ok(raw) = std::fs::read_to_string(IB_CORE_NETNS_MODE) else {
            assert_eq!(rdma_netns_mode(), RdmaNetnsMode::Unknown);
            return;
        };
        assert_eq!(rdma_netns_mode(), parse_netns_mode(&raw));
        assert_ne!(
            rdma_netns_mode(),
            RdmaNetnsMode::Unknown,
            "{IB_CORE_NETNS_MODE} is readable ({raw:?}), so the mode must be decided, not guessed"
        );
    }
}
