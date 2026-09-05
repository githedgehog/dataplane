// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
#![deny(clippy::pedantic, missing_docs)]

mod frr;
mod supervisor;

use std::collections::BTreeMap;
use std::os::fd::AsRawFd;

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
/// This process stays in the namespace for as long as it supervises anything, and a namespace with
/// a process in it does not go away, so there is no descriptor to keep and nothing to clean up.
/// Every process started from here inherits it, because namespaces are inherited at `fork` -- which
/// is also why this has to happen before anything is started rather than after. A namespace opened
/// by path (the `--control-netns` case) was somebody else's to begin with and stays theirs.
///
/// # Returns
///
/// The namespace this process was in **before** the move, so the dataplane can be handed a way
/// back. This one does have to be held: nothing else in this process refers to it any more.
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
    // The mount namespace is unshared here, on the main thread, so every process started from here
    // inherits it and every one of the dataplane's threads gets the right view. The datapath thread
    // unshares again for its own namespace, which is unaffected by this.
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

    /// FRR could not be worked out well enough to start it.
    #[error(transparent)]
    Frr(#[from] frr::FrrError),

    /// Supervision itself failed.
    #[error(transparent)]
    Supervisor(#[from] SupervisorError),
}

/// Describe how to start the dataplane.
///
/// The configuration travels as a sealed memfd rather than as arguments: it is passed once,
/// immutably, alongside a hash of itself, so the dataplane can verify it received what was sent and
/// then read it in place.
///
/// The namespace travels the same way, as a descriptor at an agreed number. It is **duplicated**
/// rather than handed over, because this process stays alive and a namespace is kept alive by
/// anything holding a descriptor to it. Keeping ours means the namespace -- and so the NICs inside
/// it, with the ifindices and MAC addresses they already have -- survives a dataplane that dies.
/// Recreating it would mean another devlink reload, another link flap, and several seconds during
/// which the hardware is somewhere else.
fn dataplane_process(
    config: LaunchConfiguration,
    netns: Option<&NetworkNamespace>,
    host_netns: Option<&NetworkNamespace>,
) -> Result<Process, HandoffError> {
    let mut config_file = config.finalize();
    let integrity_check = config_file.integrity_check().finalize().to_owned_fd();
    let config_fd = config_file.to_owned_fd();

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

    if let Some(netns) = netns {
        let duplicate = netns
            .as_raw()
            .try_clone_to_owned()
            .map_err(HandoffError::DuplicateNetns)?;
        mappings.push(FdMapping {
            parent_fd: duplicate,
            child_fd: LaunchConfiguration::STANDARD_NETNS_FD,
        });
    }

    // The namespace this process started in, when the control plane was moved out of it. Also
    // duplicated rather than handed over, and for a different reason than the datapath's: this
    // process keeps its own copy because it is the only thing still referring to that namespace on
    // our side, and a supervisor that outlives one dataplane has to be able to hand the next one
    // the same way back.
    if let Some(host_netns) = host_netns {
        let duplicate = host_netns
            .as_raw()
            .try_clone_to_owned()
            .map_err(HandoffError::DuplicateNetns)?;
        mappings.push(FdMapping {
            parent_fd: duplicate,
            child_fd: LaunchConfiguration::STANDARD_HOST_NETNS_FD,
        });
    }

    let mut command = std::process::Command::new(DATAPLANE_BINARY);
    command
        .fd_mappings(mappings)
        .map_err(HandoffError::PlaceDescriptors)?;

    // The environment is inherited, not cleared. Sealing the *configuration* into a memfd is what
    // stops the dataplane being reconfigured behind our back; it says nothing about the ambient
    // environment, and the dataplane needs that environment to do its job.
    //
    // Clearing it broke three things at once, all silently. `KUBERNETES_SERVICE_HOST` and
    // `KUBERNETES_SERVICE_PORT` are how an in-cluster client finds the API server, so the k8s
    // client failed to infer any configuration at all and the gateway never reported its status.
    // `HOME` is how it finds a kubeconfig to fall back on, so the error named `/var/empty/.kube/
    // config`, a path belonging to nobody. And `DATAPLANE_PYROSCOPE_URL` exists precisely because
    // a controller owns argv here -- a flag with no environment fallback is a flag nobody can set
    // -- so clearing the environment took away the only way to turn profiling on.
    //
    // Set only if the launcher did not, so an operator who chose a backtrace level keeps it.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        command.env("RUST_BACKTRACE", "full");
    }

    Ok(Process::new("dataplane", command))
}

/// Run the gateway until something stops it.
///
/// # Order
///
/// The dataplane first, and when FRR is ours to run, not merely started first but *waited for*.
/// Zebra's `hh_dplane` module connects to the dataplane's control-plane socket as it loads; a zebra
/// that starts first finds nothing there, and the gateway comes up with a routing daemon that
/// cannot tell the datapath anything. Waiting for the socket to exist is what removes the race, and
/// it is cheap: the socket is bound while the router starts, long before the packet path does.
///
/// `frr-agent` last, because it is the one thing here that depends on FRR rather than the other way
/// round: it applies configuration through `vtysh`.
async fn run_gateway(
    config: LaunchConfiguration,
    netns: Option<NetworkNamespace>,
    host_netns: Option<NetworkNamespace>,
    supervise_frr: bool,
) -> Result<Outcome, HandoffError> {
    // Taken before the configuration is consumed below.
    let control_plane_socket = config.routing.control_plane_socket.clone();
    let agent_socket = config.routing.frr_agent_socket.clone();

    let mut supervisor = Supervisor::new();

    let dataplane = dataplane_process(config, netns.as_ref(), host_netns.as_ref())?;
    let dataplane = if supervise_frr {
        dataplane.ready_when_path_exists(control_plane_socket)
    } else {
        // Nothing here is waiting on it, so there is nothing to gain by waiting: FRR is in a
        // container of its own and already has to tolerate starting in any order.
        dataplane
    };
    supervisor.start(dataplane).await?;

    if supervise_frr {
        let (config_dir, daemon_dir) = frr::install();
        let daemons = frr::enabled_daemons(&config_dir, &daemon_dir)?;
        supervisor.start(frr::watchfrr(&daemons)).await?;
        supervisor.start(frr::agent(&agent_socket)).await?;
    }

    Ok(supervisor.supervise().await?)
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
    netns: Option<NetworkNamespace>,
    host_netns: Option<NetworkNamespace>,
    supervise_frr: bool,
) -> i32 {
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
        Err(e) => fail("the gateway could not be started", &e.to_string()),
    }
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

    // The arguments are kept, not just converted. `--control-netns` and `--supervise-frr` are this
    // program's alone: they say where to put the control plane and what to start in it, and the
    // dataplane has no opinion to form about either afterwards, so both are deliberately absent
    // from the sealed configuration.
    let args = CmdArgs::parse();
    let control_netns = args.control_netns().cloned();
    let wants_datapath_netns = args.datapath_netns();
    let supervise_frr = args.supervise_frr();

    let config = match LaunchConfiguration::try_from(args) {
        Ok(config) => config,
        Err(e) => fail("invalid command line arguments", &e.to_string()),
    };

    // Rejected rather than ignored. A control namespace without a datapath namespace puts the
    // dataplane's taps somewhere the physical devices still are, under the very names those
    // devices carry -- which is the name collision the split exists to avoid. Silently doing it
    // anyway would produce a dataplane that comes up and cannot see its own hardware.
    if control_netns.is_some() && !wants_datapath_netns {
        fail(
            "--control-netns requires --datapath-netns",
            "the control plane's taps are named after the configured interfaces, so they can only \
             exist in a namespace the physical devices are not in",
        );
    }

    let (netns, host_netns) = match &config.driver {
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
                let host_netns = match enter_control_netns(control_netns.as_ref()) {
                    Ok(host_netns) => host_netns,
                    Err(e) => fail("failed to enter the control network namespace", &e),
                };

                (Some(netns), Some(host_netns))
            } else {
                // Without a datapath namespace the physical devices are still here, so there is
                // nowhere for the taps to go that is not on top of them. The dataplane runs where
                // it always did.
                info!(
                    "the packet path was not asked for a namespace of its own; the control plane \
                     stays where this process started"
                );
                (None, None)
            }
        }
        DriverConfigSection::Kernel(_) => {
            // The kernel driver uses interfaces exactly as the kernel presents them, so there is no
            // hardware to prepare and nothing here to do but hand over. It must *not* get a control
            // namespace: its `AF_PACKET` sockets are opened on the real interfaces, which are here.
            info!("kernel driver selected; no device preparation required");
            (None, None)
        }
    };

    std::process::exit(supervise_gateway(config, netns, host_netns, supervise_frr));
}
