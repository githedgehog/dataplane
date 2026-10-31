// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use futures::TryStreamExt;
use hardware::pci::address::PciAddress;
use netdev::Interface;
use std::io;

use net::interface::InterfaceIndex;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags};
use rtnetlink::{Handle, LinkUnspec};

use lldp::Link;
use nix::errno::Errno;
use nix::sched::{CpuSet, sched_getaffinity};
use nix::unistd::Pid;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

use super::offload;

#[derive(Debug, Clone)]
/// Simple representation of a kernel interface.
pub struct Kif {
    /// Linux ifindex of the interface
    pub ifindex: InterfaceIndex,
    /// The MAC the kernel reports for this interface.
    ///
    /// Carried because the control-plane bridge needs it: the tap standing in for this interface
    /// has to answer ARP with the same address, or the peer sends frames this interface will not
    /// accept. `None` when the kernel reported none, which a physical interface never does.
    pub mac: Option<net::eth::mac::Mac>,
    /// The MTU the kernel reports, which the tap is given so both ends agree.
    pub mtu: Option<u32>,
    /// Name of the interface, must be a name that can bound using bind on a socket
    pub name: String,
}

impl Kif {
    /// Where sysfs describes this interface.
    ///
    /// Only meaningful on a thread in the interface's namespace with a sysfs mounted for it, which the
    /// kernel driver's threads are.
    fn sysfs(&self) -> PathBuf {
        PathBuf::from("/sys/class/net").join(&self.name)
    }

    /// The device behind the interface, `<bus address> (<driver>)`, or `None` for a virtual one.
    #[must_use]
    pub fn hardware(&self) -> Option<String> {
        let bus = std::fs::read_link(self.sysfs().join("device")).ok()?;
        let bus = bus.file_name()?.to_string_lossy().into_owned();
        Some(match self.driver() {
            Some(driver) => format!("{bus} ({driver})"),
            None => bus,
        })
    }

    /// The PCI function behind the interface, if it is a PCI device.
    #[must_use]
    pub fn pci_address(&self) -> Option<PciAddress> {
        let device = std::fs::read_link(self.sysfs().join("device")).ok()?;
        PciAddress::try_from(device.file_name()?.to_str()?).ok()
    }

    /// The bound kernel driver, if available.
    fn driver(&self) -> Option<String> {
        let driver = std::fs::read_link(self.sysfs().join("device/driver")).ok()?;
        Some(driver.file_name()?.to_string_lossy().into_owned())
    }

    /// Disable GRO and flow control; enable RPS on e1000 ports. Failures are nonfatal.
    ///
    /// Requires the interface's network namespace and a matching sysfs mount.
    fn tune(&self) {
        match offload::disable_gro(&self.name) {
            Ok(()) => debug!("GRO is off on {}", self.name),
            Err(e) => warn!(
                "could not turn GRO off on {} ({e}); frames merged beyond its MTU will be \
                 dropped",
                self.name
            ),
        }
        match offload::disable_pause(&self.name) {
            Ok(()) => debug!("flow control (pause) is off on {}", self.name),
            Err(Errno::EOPNOTSUPP) => debug!("{} has no flow control to turn off", self.name),
            Err(e) => warn!(
                "could not turn flow control off on {} ({e}); a congested queue may pause the \
                 whole link",
                self.name
            ),
        }
        if self.driver().as_deref() == Some("e1000") {
            self.spread_receive();
        }
    }

    /// Spread e1000 receive processing across the calling thread's allowed CPUs.
    ///
    /// RPS distributes kernel processing. With `PACKET_FANOUT_QM`, a single receive queue's
    /// traffic still goes to one worker socket.
    fn spread_receive(&self) {
        // Setup runs on the unpinned datapath thread, whose affinity the workers inherit.
        let cpus = match sched_getaffinity(Pid::from_raw(0)) {
            Ok(cpus) => cpus,
            Err(e) => {
                warn!(
                    "could not read the CPUs this process may use ({e}); {} keeps its receive \
                     processing where it is",
                    self.name
                );
                return;
            }
        };
        let mask = cpu_mask((0..CpuSet::count()).filter(|&cpu| cpus.is_set(cpu).unwrap_or(false)));
        let queues = match std::fs::read_dir(self.sysfs().join("queues")) {
            Ok(queues) => queues,
            Err(e) => {
                warn!("could not list the queues of {} ({e})", self.name);
                return;
            }
        };
        for queue in queues.flatten() {
            if !queue.file_name().to_string_lossy().starts_with("rx-") {
                continue;
            }
            let path = queue.path().join("rps_cpus");
            match std::fs::write(&path, &mask) {
                Ok(()) => info!("{} steers received packets to CPUs {mask}", path.display()),
                Err(e) => warn!(
                    "could not steer received packets with {} ({e})",
                    path.display()
                ),
            }
        }
    }

    /// Whether the interface has carrier.
    ///
    /// An interface whose carrier cannot be read (the kernel refuses while it is administratively
    /// down) is treated as down: nothing should be sent on it.
    #[must_use]
    pub fn link(&self) -> Link {
        match std::fs::read_to_string(self.sysfs().join("carrier")) {
            Ok(carrier) if carrier.trim() == "1" => Link::Up,
            _ => Link::Down,
        }
    }

    /// Create a kernel interface entry.
    #[allow(clippy::unnecessary_wraps)] // Eventually we'll do work that could return an error
    fn new(ifindex: InterfaceIndex, name: &str, interface: &Interface) -> io::Result<Self> {
        let iface = Self {
            ifindex,
            mac: interface
                .mac_addr
                .map(|mac| net::eth::mac::Mac::from(mac.octets())),
            mtu: interface.mtu,
            name: name.to_owned(),
        };
        debug!("Successfully created interface '{name}'");
        Ok(iface)
    }
    /// Turn off the kernel's IPv6 stack on this interface.
    ///
    /// For an interface a tap stands in for. Left on, bringing the interface up gives it a
    /// link-local address derived from its MAC, which is the tap's MAC as well, so the kernel in
    /// the datapath namespace claims the control plane's address and answers connections meant for
    /// FRR, such as BGP, with resets.
    ///
    /// Must run on a thread in the interface's namespace: `/proc/sys/net` is the caller's.
    pub fn disable_ipv6(&self) -> io::Result<()> {
        let path = format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", self.name);
        match std::fs::write(&path, "1") {
            Ok(()) => {
                debug!("IPv6 is disabled on {}", self.name);
                Ok(())
            }
            // A kernel without IPv6 has nothing to turn off.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io::Error::other(format!(
                "could not disable IPv6 on {}: {e}",
                self.name
            ))),
        }
    }

    /// Apply the requested MTU, bring the interface up, and read back its state.
    async fn bring_up(&mut self, handle: &Handle, mtu: Option<u16>) -> io::Result<()> {
        info!("Bringing interface {} up ...", self.name);
        let mut request = LinkUnspec::new_with_index(self.ifindex.to_u32()).up();
        if let Some(mtu) = mtu {
            request = request.mtu(u32::from(mtu));
        }
        handle
            .link()
            .set(request.build())
            .execute()
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "Failed to configure {} (ifindex {}, requested MTU {mtu:?}): {e}",
                    self.name, self.ifindex,
                ))
            })?;

        // verify this single interface
        let links = handle
            .link()
            .get()
            .match_index(self.ifindex.to_u32())
            .execute()
            .try_next()
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "Failed to verify status of {} (ifindex {}) up: {e}",
                    self.name, self.ifindex
                ))
            })?;

        match links {
            Some(msg) => {
                self.mtu = msg.attributes.iter().find_map(|attribute| match attribute {
                    LinkAttribute::Mtu(value) => Some(*value),
                    _ => None,
                });
                if let Some(requested) = mtu
                    && self.mtu != Some(u32::from(requested))
                {
                    return Err(io::Error::other(format!(
                        "Interface {} reports MTU {:?}, requested {requested}",
                        self.name, self.mtu,
                    )));
                }
                if msg.header.flags.contains(LinkFlags::Up) {
                    info!("Interface {} is up", self.name);
                    Ok(())
                } else {
                    error!(
                        "Interface {} is not up, flags: {:?}",
                        self.name, msg.header.flags
                    );
                    Err(io::Error::other(format!(
                        "Interface {} did not come up",
                        self.name,
                    )))
                }
            }
            None => Err(io::Error::other(format!(
                "Got no response to check status of interface {}",
                self.name
            ))),
        }
    }
}

/// Format a sysfs CPU bitmap: comma-separated 32-bit hex groups, most significant first.
fn cpu_mask(cpus: impl IntoIterator<Item = usize>) -> String {
    let mut groups: Vec<u32> = Vec::new();
    for cpu in cpus {
        if groups.len() <= cpu / 32 {
            groups.resize(cpu / 32 + 1, 0);
        }
        groups[cpu / 32] |= 1 << (cpu % 32);
    }
    if groups.is_empty() {
        return "0".to_owned();
    }
    groups
        .iter()
        .rev()
        .map(|group| format!("{group:08x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Get the ifindex of the interface with the given name.
pub fn get_interface_ifindex(interfaces: &[Interface], name: &str) -> io::Result<InterfaceIndex> {
    let pos = interfaces
        .iter()
        .position(|interface| interface.name == name)
        .ok_or_else(|| io::Error::other(format!("Unknown interface '{name}'")))?;

    let ifindex = InterfaceIndex::try_new(interfaces[pos].index).map_err(io::Error::other)?;

    Ok(ifindex)
}

macro_rules! INTERFACE_FMT {
    ($ifindex:expr, $name:expr, $mac:expr, $opstate:expr, $admstate:expr) => {
        format_args!(
            "{:>8} {:<16} {:<20} {:<12} {:<6}",
            $ifindex, $name, $mac, $opstate, $admstate
        )
    };
}

fn log_kernel_interfaces(interfaces: &[Interface], msg: &str) {
    info!("━━━━━━━━━━━━━━━ {} ━━━━━━━━━━━━━━━", msg);
    info!(
        "{}",
        INTERFACE_FMT!("ifindex", "name", "mac", "OpState", "AdmState"),
    );
    for interface in interfaces {
        let mac = interface
            .mac_addr
            .map_or_else(|| "none".to_string(), |genid| genid.to_string());
        info!(
            "{}",
            INTERFACE_FMT!(
                interface.index,
                interface.name,
                mac,
                interface.oper_state.to_string(),
                if interface.is_up() { "up" } else { "down" }
            )
        );
    }
}

/// Build a table of kernel interfaces to receive packets from (or send to).
/// Interfaces of interest are indicated by --interface INTERFACE in the command line.
/// Argument --interface ANY|any instructs the driver to capture on all interfaces.
pub fn get_interfaces(args: impl IntoIterator<Item = impl AsRef<str>>) -> io::Result<Vec<Kif>> {
    /* learn about existing kernel network interfaces. We need these to know their ifindex  */
    let interfaces = netdev::get_interfaces();
    log_kernel_interfaces(interfaces.as_slice(), "Available kernel interfaces");

    /* check what interfaces we're interested in from args */
    let ifnames: Vec<String> = args.into_iter().map(|x| x.as_ref().to_owned()).collect();
    if ifnames.is_empty() {
        return Err(io::Error::other("At least one interface must be specified"));
    }

    /* populate vector with a [`Kif`] if the interface exists, else fail */
    let mut kifs = Vec::new();
    for ifname in &ifnames {
        let if_index = get_interface_ifindex(&interfaces, ifname)?;
        let interface = interfaces
            .iter()
            .find(|i| &i.name == ifname)
            .ok_or_else(|| io::Error::other(format!("interface '{ifname}' vanished mid-scan")))?;
        kifs.push(Kif::new(if_index, ifname, interface)?);
    }

    /* interfaces that will be used */
    let to_use: Vec<_> = interfaces
        .iter()
        .filter_map(|i| ifnames.contains(&i.name).then_some(i.clone()))
        .collect();
    log_kernel_interfaces(to_use.as_slice(), "Will use the following interfaces");

    Ok(kifs)
}

/// Configure interfaces before workers start and report their observed identity to the bridge.
///
/// With `disable_ipv6`, IPv6 is turned off on each interface before it comes up: see
/// [`Kif::disable_ipv6`].
pub(super) async fn configure_interfaces(
    config: &[args::InterfaceArg],
    disable_ipv6: bool,
) -> io::Result<Vec<Kif>> {
    let mut kifs = get_interfaces(config.iter().map(|interface| interface.interface.as_ref()))?;
    let (connection, handle, _) = rtnetlink::new_connection()?;
    let h = tokio::spawn(connection);

    let result = async {
        for kif in &mut kifs {
            // By name: pairing by position would hand MTUs to the wrong interface if
            // `get_interfaces` ever filtered or reordered.
            let mtu = config
                .iter()
                .find(|interface| interface.interface.as_ref() == kif.name.as_str())
                .and_then(|interface| interface.mtu);
            if disable_ipv6 {
                kif.disable_ipv6()?;
            }
            kif.tune();
            kif.bring_up(&handle, mtu).await?;
        }
        Ok(kifs)
    }
    .await;
    h.abort();
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use args::{CmdArgs, LaunchConfiguration, Parser};
    use caps::Capability;
    use fixin::wrap;
    use hardware::netns::NetworkNamespace;
    use rtnetlink::LinkVeth;
    use std::str::FromStr;
    use test_utils::with_caps;

    /// Parse a sysfs CPU bitmap into CPU IDs.
    fn cpus_in(mask: &str) -> Vec<usize> {
        let mut cpus = Vec::new();
        for (index, group) in mask.trim().rsplit(',').enumerate() {
            let group = u32::from_str_radix(group, 16).unwrap();
            cpus.extend(
                (0..32)
                    .filter(|bit| group & (1 << bit) != 0)
                    .map(|bit| index * 32 + bit),
            );
        }
        cpus
    }

    #[test]
    fn a_cpu_mask_names_exactly_its_cpus() {
        bolero::check!().with_type::<Vec<u16>>().for_each(|cpus| {
            let mut cpus: Vec<usize> = cpus.iter().map(|&cpu| usize::from(cpu % 1024)).collect();
            let mask = cpu_mask(cpus.iter().copied());
            cpus.sort_unstable();
            cpus.dedup();
            assert_eq!(cpus_in(&mask), cpus, "{mask}");
        });
    }

    /// Interfaces using `driver` in the current namespace.
    fn interfaces_driven_by(driver: &str) -> Vec<String> {
        std::fs::read_dir("/sys/class/net")
            .unwrap()
            .flatten()
            .filter(|entry| {
                std::fs::read_link(entry.path().join("device/driver"))
                    .is_ok_and(|link| link.file_name().is_some_and(|name| name == driver))
            })
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect()
    }

    const E1000_QEMU: n_vm::VmConfig = n_vm::VmConfig::DEFAULT
        .to_builder()
        .kernel_profile(n_vm::kernel_profiles::QEMU)
        .nic_model(n_vm::NicModel::E1000)
        .build();

    #[n_vm::test(config = E1000_QEMU)]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn an_e1000_comes_up_without_gro_and_with_receive_spread_over_our_cpus() {
        let name = interfaces_driven_by("e1000")
            .pop()
            .expect("the guest has an e1000 interface");
        let rps_cpus = format!("/sys/class/net/{name}/queues/rx-0/rps_cpus");
        // Verify that setup must change both settings.
        assert!(offload::gro(&name).unwrap(), "e1000 starts with GRO on");
        assert_eq!(
            cpus_in(&std::fs::read_to_string(&rps_cpus).unwrap()),
            Vec::<usize>::new()
        );

        let config = vec![args::InterfaceArg::from_str(&format!("{name}=kernel@{name}")).unwrap()];
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(configure_interfaces(&config, false))
            .unwrap();

        assert!(!offload::gro(&name).unwrap(), "GRO is off after setup");
        // e1000 has flow control, and setup turns all of it off.
        let pause = offload::pause(&name).unwrap();
        assert_eq!(
            (pause.autoneg, pause.rx_pause, pause.tx_pause),
            (0, 0, 0),
            "flow control is off after setup"
        );
        let allowed = sched_getaffinity(Pid::from_raw(0)).unwrap();
        let allowed: Vec<usize> = (0..CpuSet::count())
            .filter(|&cpu| allowed.is_set(cpu).unwrap())
            .collect();
        assert!(
            allowed.len() > 1,
            "a single CPU would leave nothing to spread over"
        );
        assert_eq!(
            cpus_in(&std::fs::read_to_string(&rps_cpus).unwrap()),
            allowed
        );
    }

    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn configured_mtu_reaches_the_kernel_and_reported_identity() {
        std::thread::spawn(|| {
            let netns = NetworkNamespace::create().unwrap();
            netns.enter_with_sysfs().unwrap();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
                    let connection = tokio::spawn(connection);
                    handle
                        .link()
                        .add(LinkVeth::new("mtu0", "mtu1").build())
                        .execute()
                        .await
                        .unwrap();
                    let launch = LaunchConfiguration::try_from(
                        CmdArgs::try_parse_from([
                            "dataplane",
                            "--driver",
                            "kernel",
                            "--interface",
                            "mtu0=kernel@mtu0/mtu=9000,mtu1=kernel@mtu1",
                        ])
                        .unwrap(),
                    )
                    .unwrap();
                    let mut config: Vec<_> = launch.driver.interfaces().cloned().collect();
                    let kifs = configure_interfaces(&config, false).await.unwrap();
                    for (kif, expected) in kifs.iter().zip([9000, 1500]) {
                        let actual = handle
                            .link()
                            .get()
                            .match_index(kif.ifindex.to_u32())
                            .execute()
                            .try_next()
                            .await
                            .unwrap()
                            .unwrap();
                        assert!(actual.header.flags.contains(LinkFlags::Up));
                        assert!(actual.attributes.contains(&LinkAttribute::Mtu(expected)));
                        assert_eq!(
                            kif.mtu,
                            Some(expected),
                            "MTU reported to the control bridge"
                        );
                    }

                    // An omitted value preserves the configured MTU on repeated setup.
                    config[0].mtu = None;
                    assert_eq!(
                        configure_interfaces(&config, false).await.unwrap()[0].mtu,
                        Some(9000)
                    );

                    // A kernel rejection must stop startup, not report the requested value.
                    config[0].mtu = Some(67);
                    let error = configure_interfaces(&config, false).await.unwrap_err();
                    assert!(
                        error.to_string().contains("Failed to configure mtu0"),
                        "{error}"
                    );
                    connection.abort();
                });
        })
        .join()
        .unwrap();
    }
}
