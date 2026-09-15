// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
#![deny(clippy::pedantic, missing_docs)]

mod frr;
mod hugepages;
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

/// Hugetlbfs mount points.
///
/// Mounting these is best-effort. The dataplane asks the EAL for `--in-memory`, which backs its
/// hugepages with memfd rather than files under a mount, so it starts without them; a mount is
/// what a multi-process DPDK setup would need, and what makes the pages visible to an operator
/// looking at the filesystem.
///
/// **Deliberately no `size=`.** hugetlbfs treats that option as a hard ceiling on the mount, not
/// as a reservation, so a figure here silently caps what DPDK can take however many pages the
/// kernel actually has. The 2 MiB mount carried `size=128M`, which is far below what a datapath
/// asks for -- and the symptom is an allocation failure blamed on the host being short of pages,
/// on a host with thousands of them free. Left off, the mount is bounded by the pool, which is the
/// only limit that should apply.
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
/// Whether the RDMA subsystem will let a network namespace own a device.
///
/// `ib_core`'s `netns_mode` is a bool parameter: `Y` is *shared* (the kernel default) and `N` is
/// *exclusive*. It is settable at boot as `ib_core.netns_mode=0`, and effectively only at boot --
/// `rdma system set netns exclusive` is permitted only while no network namespace other than the
/// initial one exists, which on a node running containers is never.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RdmaNetnsMode {
    /// A device can be moved into a namespace and is invisible outside it. What the design needs.
    Exclusive,
    /// Devices are visible everywhere and a namespace cannot own one.
    Shared,
    /// `ib_core` is not loaded, or the parameter is not where it is expected.
    Unknown,
}

/// Where the kernel exposes the RDMA namespace mode.
const IB_CORE_NETNS_MODE: &str = "/sys/module/ib_core/parameters/netns_mode";

/// Interpret the contents of [`IB_CORE_NETNS_MODE`].
///
/// Split from the read so both answers can be tested on a machine that can only be in one of them.
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

    // Say so here rather than let this surface only as an empty device list.
    //
    // This warns; it used to refuse, and refusing was wrong. In shared mode `_ib_alloc_device`
    // discards the requested net, so the devlink instance moves while the RDMA device -- the half
    // the mlx5 PMD attaches through -- stays in `init_net`. That says where the device *lives*,
    // not whether it can be reached: shared mode also means every RDMA device is visible from
    // every namespace, and if the kernel does not namespace-tag them in that mode, the datapath
    // finds it exactly as it would have in `init_net` and the arrangement works.
    //
    // What could be measured was: on an *exclusive*-mode host, a fresh network namespace with a
    // fresh sysfs lists no infiniband devices, so the class is tagged and visibility follows the
    // device's net. Whether that tagging still applies under shared mode is the part that decides
    // this, and it cannot be answered on a machine that is not in shared mode.
    //
    // A refusal would stop the only kind of host that could settle it from starting at all, to
    // prevent a failure that is now understood and reported when it happens.
    // `hardware/tests/dpdk_in_netns.rs` is the probe that answers it properly.
    if !bifurcated.is_empty() {
        match rdma_netns_mode() {
            RdmaNetnsMode::Exclusive => {}
            RdmaNetnsMode::Shared => warn!(
                "the RDMA subsystem is in shared mode, so {} cannot be given to a namespace: the \
                 devlink instance moves while the RDMA device stays in init_net. Whether the \
                 datapath can still reach it there is what this run will find out. If it reports \
                 no devices, that is the answer, and the fix is to boot with \
                 `ib_core.netns_mode=0` (`rdma system show` should then say `netns exclusive`) or \
                 to run without --datapath-netns -- it cannot be changed at runtime, because \
                 `rdma system set netns exclusive` is permitted only while no network namespace \
                 but the initial one exists.",
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

/// Move the kernel driver's interfaces into a network namespace of their own.
///
/// The counterpart of [`move_devices_to_netns`], and much the simpler of the two. A netdev the
/// kernel drives moves with one `RTM_NEWLINK` carrying `IFLA_NET_NS_FD`; there is no driver to
/// reinitialize, no devlink instance to find, and no RDMA subsystem to have an opinion about it.
///
/// # What moving them buys
///
/// Not merely symmetry with DPDK. An interface the kernel still owns is an interface the kernel
/// will route through, answer ARP on and terminate connections on, all without the dataplane
/// knowing -- which is what the netfilter rules that kept VXLAN traffic away from the host stack
/// were defending against. With the device somewhere the host stack is not, there is nothing to
/// defend.
///
/// # What it costs
///
/// The interface **loses its addresses and routes**, as any interface does when it changes
/// namespace, and it comes back administratively down. Nothing here restores them, and nothing
/// should: the dataplane drives these interfaces with `AF_PACKET` and does not want the kernel
/// configuring them, and the addresses the control plane cares about belong on the taps that take
/// their names.
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
    Ok(netns)
}

/// Decide where the control plane runs, and put this process there.
///
/// Returns the namespace this process was in beforehand when it moved, and `None` when it stayed.
/// `None` is not a failure: it says the control plane is already where it belongs, so nothing needs
/// a way back and the dataplane needs no second runtime.
///
/// # The rule
///
/// **A private control namespace is only correct when FRR is ours to place.** FRR has to see the
/// taps -- it is configured by looking each interface up in the kernel, and it peers through them
/// -- so it must share this namespace. When `--supervise-frr` says we start it, that is
/// automatic, because it inherits ours. When FRR is a container of its own, it is somewhere we do
/// not control, and moving out of that namespace would leave it looking at an empty one: config
/// applies fail with "Unable to find kernel interface", and no session ever comes up.
///
/// `--control-netns` overrides both: it names a namespace an operator arranged for the two to
/// share, and taking it at face value is the point of having the flag.
///
/// # Why staying put is still worth having a datapath namespace for
///
/// The two namespaces answer different questions. The datapath's takes the interfaces away from
/// the host stack, which is what stops the kernel routing and answering ARP behind the dataplane's
/// back. The control plane's separates FRR from everything else in the host, which only matters
/// once FRR is ours. The first is useful on its own; the taps take the names the real interfaces
/// just vacated.
fn place_control_plane(
    path: Option<&String>,
    supervise_frr: bool,
) -> Result<Option<NetworkNamespace>, String> {
    if path.is_none() && !supervise_frr {
        info!(
            "the control plane stays in the namespace this process started in: FRR is not ours to \
             start, so it is somewhere we cannot follow, and it has to see the taps"
        );
        return Ok(None);
    }
    enter_control_netns(path).map(Some)
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

    // Everything FRR needs decided *before* anything starts, because the dataplane is first out of
    // the gate and it already depends on one of these answers.
    //
    // The state directory is the reason this is not merely tidy. `/run/frr` is a volume that
    // outlives the pod and arrives empty on a fresh install, and the dataplane binds its
    // control-plane socket *inside* it, at `<state>/hh`. Prepare it afterwards and the dataplane
    // dies on startup with a bind failure -- which is what happened, and which only a lab built
    // from scratch could show: a machine that has run the old two-container gateway already has
    // the directory, left behind by the `init-frr` container this replaces.
    //
    // Reading the daemon list early is worth having for its own sake: an FRR install missing zebra
    // should be a refusal to start, not a discovery made after the datapath is already up.
    let daemons = if supervise_frr {
        let (config_dir, daemon_dir) = frr::install();
        let daemons = frr::enabled_daemons(&config_dir, &daemon_dir)?;
        frr::prepare_state_dir(&frr::state_dir())?;
        Some(daemons)
    } else {
        None
    };

    let dataplane = dataplane_process(config, netns.as_ref(), host_netns.as_ref())?;
    let dataplane = if supervise_frr {
        dataplane.ready_when_path_exists(control_plane_socket)
    } else {
        // Nothing here is waiting on it, so there is nothing to gain by waiting: FRR is in a
        // container of its own and already has to tolerate starting in any order.
        dataplane
    };
    supervisor.start(dataplane).await?;

    if let Some(daemons) = daemons {
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

    let mut config = match LaunchConfiguration::try_from(args) {
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

    // Declared out here because the match borrows `config.driver`, and the plan has to be written
    // back into it afterwards -- before `dataplane_process` seals it into the memfd.
    let mut hugepage_plan = None;
    let (netns, host_netns) = match &config.driver {
        DriverConfigSection::Dpdk(dpdk) => {
            mount_hugepages();
            let devices = match resolve_devices(dpdk) {
                Ok(devices) => devices,
                Err(problems) => fail("cannot use the requested network devices", &problems),
            };
            // Reserved here, after the devices are resolved, because the whole point is to put the
            // pages on the node the NIC is attached to -- which is not knowable until we have the
            // PCI addresses in hand. The result rides to the dataplane in the launch
            // configuration; see `hugepages` for why the EAL cannot be left to do this itself.
            hugepage_plan =
                hugepages::reserve_for(&devices.iter().map(|d| d.address).collect::<Vec<_>>());
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
                let host_netns = match place_control_plane(control_netns.as_ref(), supervise_frr) {
                    Ok(host_netns) => host_netns,
                    Err(e) => fail("failed to enter the control network namespace", &e),
                };

                (Some(netns), host_netns)
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
        DriverConfigSection::Kernel(kernel) => {
            // No hardware to prepare -- these are interfaces the kernel already drives -- but the
            // namespace work is the same as DPDK's, and for the same reasons. See
            // `move_interfaces_to_netns` for what moving them buys and what it costs.
            info!("kernel driver selected; no device preparation required");
            if kernel.netns {
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

                (Some(netns), host_netns)
            } else {
                // The interfaces stay where they are, and so does the control plane. The taps the
                // bridge would create are named after those interfaces, so there is nowhere to put
                // them that is not on top of the real ones.
                info!(
                    "the packet path was not asked for a namespace of its own; the control plane \
                     stays where this process started"
                );
                (None, None)
            }
        }
    };

    // Recorded before the configuration is sealed. The dataplane turns this into `--numa-mem`,
    // which makes the EAL fail loudly if the memory is not where we said it would be, instead of
    // falling back to another node without a word.
    if let DriverConfigSection::Dpdk(dpdk) = &mut config.driver {
        dpdk.hugepages = hugepage_plan;
    }

    std::process::exit(supervise_gateway(config, netns, host_netns, supervise_frr));
}

#[cfg(test)]
mod rdma_netns_mode_test {
    use super::{IB_CORE_NETNS_MODE, RdmaNetnsMode, parse_netns_mode, rdma_netns_mode};

    /// Both answers, on a machine that can only be in one of them.
    ///
    /// The host-reading test below can only exercise whichever mode this machine happens to be in,
    /// so a mistake in the other arm would go unnoticed -- and the arm that matters is `Y`, the
    /// kernel default, which is what a misconfigured lab host reports.
    #[test]
    fn shared_and_exclusive_are_both_recognised() {
        assert_eq!(parse_netns_mode("Y"), RdmaNetnsMode::Shared);
        assert_eq!(parse_netns_mode("1"), RdmaNetnsMode::Shared);
        assert_eq!(parse_netns_mode("Y\n"), RdmaNetnsMode::Shared);
        assert_eq!(parse_netns_mode("N"), RdmaNetnsMode::Exclusive);
        assert_eq!(parse_netns_mode("0"), RdmaNetnsMode::Exclusive);
        assert_eq!(parse_netns_mode("N\n"), RdmaNetnsMode::Exclusive);
        // Anything else is not guessed at: an unrecognised value warns and only warns, which is
        // the right way round -- refusing to start over a parameter we cannot read would be worse.
        assert_eq!(parse_netns_mode("maybe"), RdmaNetnsMode::Unknown);
        assert_eq!(parse_netns_mode(""), RdmaNetnsMode::Unknown);
    }

    /// And the reader must agree with what this machine actually reports.
    #[test]
    fn a_readable_parameter_is_never_reported_unknown() {
        let Ok(raw) = std::fs::read_to_string(IB_CORE_NETNS_MODE) else {
            // No ib_core here; Unknown is the honest answer and the guard only warns.
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
