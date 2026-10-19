// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Connects isolated datapath ports to the kernel through per-interface taps.
//!
//! Both drivers use taps named after the configured interfaces so FRR, routing, and
//! ACLs resolve the same names. Interface indices above the driver are tap indices
//! in the control namespace, not physical-port indices in the datapath namespace.
//!
//! Bounded channels carry owned frames in each direction: workers punt selected
//! pipeline verdicts to the kernel and inject kernel frames directly onto the wire.
//! Frames are copied because DPDK mbufs cannot cross threads. This currently allocates
//! per frame; reusable buffers are a possible later optimization.
//!
//! Create taps on a thread in the control namespace. A tap stays in the namespace
//! where it was created, even if the thread later calls `setns`.

use std::collections::HashMap;
use std::time::Duration;

use concurrency::sync::Arc;
use interface_manager::interface::{TapDevice, TapRegistry};
use lifecycle::{CancellationToken, Subsystem};
use lldp::Link;
use net::eth::mac::Mac;
use net::interface::{InterfaceIndex, InterfaceName};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

/// One control-plane frame, copied out of (or destined for) a driver's own buffer.
pub(crate) type Frame = Vec<u8>;

/// How many frames one direction of one port's bridge will hold before it starts dropping.
///
/// Deep enough to absorb a burst of ARP or a BGP update while a worker is busy elsewhere, and
/// shallow enough that a wedged datapath is bounded memory rather than unbounded. Overflow is
/// counted and logged rather than blocking: a control plane that stalls the packet path waiting for
/// a queue would be a far worse failure than a dropped frame that BGP will retransmit.
const QUEUE_DEPTH: usize = 1024;

/// How many tap reads in a row may fail before the port's control plane is declared lost.
///
/// Spaced [`READ_RETRY`] apart, so about a second of nothing but errors. A read error on a tap is
/// not expected at all; one that persists means the port can no longer reach the control plane,
/// and a gateway that cannot peer on a port must not keep reporting itself healthy.
const READ_ERRORS_BEFORE_FATAL: u32 = 100;

/// How long to wait before retrying a failed tap read.
const READ_RETRY: Duration = Duration::from_millis(10);

/// How many received LLDP frames may wait for the LLDP agent, across all ports.
///
/// A neighbour sends one every thirty seconds or so, so this is generous; past it frames are dropped
/// and counted, and the neighbour's next frame makes up for them.
const HEARD_QUEUE_DEPTH: usize = 64;

/// An LLDP frame received on a port, on its way to the LLDP agent.
pub(crate) struct HeardFrame {
    /// The port it arrived on.
    pub(crate) port: InterfaceName,
    /// The whole frame, Ethernet header included.
    pub(crate) frame: Frame,
}

/// What a port turns out to be once it is up.
///
/// The datapath learns this and the control plane needs it: a tap whose MAC does not match its
/// port's answers ARP with the wrong address, and the peer then sends frames the port drops as
/// `MacNotForUs`. Nothing about that failure points at the MAC.
#[derive(Debug, Clone)]
pub(crate) struct PortIdentity {
    /// The configured interface name, which is also the tap's name.
    pub(crate) name: String,
    /// The MAC the PMD reports for the port.
    pub(crate) mac: Mac,
    /// The MTU the port settled on, which may not be the one that was asked for. `None` if the
    /// driver could not learn it, in which case the tap keeps its own.
    pub(crate) mtu: Option<u16>,
    /// The device behind the port, for people reading what neighbours hear about it: its bus address
    /// and driver, as far as the driver can tell.
    pub(crate) hardware: Option<String>,
    /// The index of the port's own kernel netdev in the datapath namespace, where ethtool can read
    /// its pluggable module. Not the tap's index, which belongs to the control namespace.
    pub(crate) datapath_index: Option<InterfaceIndex>,
}

/// The datapath's end of one port's bridge.
pub(crate) struct PortCpQueues {
    /// The tap's index in the control namespace.
    /// Configuration, ingress lookup, and routing use this index. The physical port's
    /// index belongs to a different namespace and may only match by coincidence.
    pub(crate) index: InterfaceIndex,
    /// Frames the datapath is handing to the kernel.
    pub(crate) punt: mpsc::Sender<Frame>,
    /// Frames the kernel wants transmitted, present on exactly one worker.
    ///
    /// Only one worker may drain a given queue, and that is not merely an ownership convenience:
    /// draining from two workers would interleave a peering session's frames across two transmit
    /// queues and reorder them. `None` on every worker but the drainer.
    pub(crate) inject: Option<mpsc::Receiver<Frame>>,
}

/// Everything the datapath thread needs from the bridge.
///
/// Deliberately a separate value from [`CpBridge`]: this half is `Send` and crosses to the datapath
/// thread, while the half that owns the tap descriptors and their tasks stays on the management
/// runtime.
pub(crate) struct DatapathEnds {
    ports: HashMap<String, PortCpQueues>,
    identities: mpsc::Sender<PortIdentity>,
    links: HashMap<String, watch::Sender<Link>>,
}

impl DatapathEnds {
    /// Take the bridge ends for the port named `name`, if the bridge made any.
    ///
    /// Taken rather than borrowed, so a port claimed twice gets `None` the second time instead of
    /// two workers quietly sharing one injection queue.
    pub(crate) fn take(&mut self, name: &str) -> Option<PortCpQueues> {
        self.ports.remove(name)
    }

    /// Take where the driver reports the link state of the port named `name`.
    ///
    /// Taken for the same reason as [`DatapathEnds::take`]: one reporter per port.
    pub(crate) fn take_link(&mut self, name: &str) -> Option<watch::Sender<Link>> {
        self.links.remove(name)
    }

    /// Tell the control plane what a port turned out to be.
    ///
    /// Best effort by construction: if the bridge is gone there is nobody to tell, and the packet
    /// path is not the thing that should stop because of it.
    pub(crate) fn report(&self, identity: PortIdentity) {
        let name = identity.name.clone();
        if self.identities.try_send(identity).is_err() {
            warn!(
                "could not report the identity of port {name} to the control plane; its tap will \
                 keep the MAC the kernel gave it, and ARP for this port will not resolve"
            );
        }
    }

    /// Warn about any port the bridge prepared for which no DPDK port appeared.
    pub(crate) fn report_unclaimed(&self) {
        for name in self.ports.keys() {
            warn!(
                "the control-plane bridge holds a tap named {name} but no DPDK port claimed it; \
                 traffic will not flow between them"
            );
        }
    }
}

/// Anything that can go wrong building the bridge.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BridgeError {
    /// A netlink socket could not be opened in the control namespace.
    #[error("could not open a netlink socket for the control-plane bridge: {0}")]
    Netlink(String),
    /// A tap device could not be created, or the kernel would not say what index it got.
    ///
    /// Fatal rather than skipped: without the index the datapath has no name for this interface
    /// that the rest of the dataplane would recognise.
    #[error("could not create the tap device for interface {name}: {source}")]
    Tap {
        /// The interface whose tap could not be made.
        name: InterfaceName,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

/// The control plane's end of the bridge: the taps, and the tasks which pump them.
pub(crate) struct CpBridge {
    /// The descriptors that keep the taps alive. Dropping this removes every one of them.
    taps: Arc<TapRegistry>,
    /// Stops the pump tasks so that they let go of their share of the descriptors.
    cancel: CancellationToken,
    /// What the control plane, other than the taps, may know and do about each port.
    ports: Vec<BridgePort>,
    /// LLDP frames received on any port, until the LLDP agent takes them.
    heard: Option<mpsc::Receiver<HeardFrame>>,
}

/// The control plane's view of one port, for things other than the tap that want to use it.
#[derive(Clone)]
pub(crate) struct BridgePort {
    /// The configured interface name.
    pub(crate) name: InterfaceName,
    /// Frames to transmit out of the port, sharing the tap's injection queue.
    pub(crate) inject: mpsc::Sender<Frame>,
    /// The port's link state, as the driver last saw it.
    pub(crate) link: watch::Receiver<Link>,
    /// What the port turned out to be, once the driver has reported it.
    pub(crate) identity: watch::Receiver<Option<PortIdentity>>,
}

impl CpBridge {
    /// Create a tap for every configured interface and start pumping frames across.
    ///
    /// Must be called from the control namespace, before the datapath thread jumps into the
    /// datapath namespace: see the module documentation for why the calling thread matters.
    ///
    /// The taps are created **down** and without a MAC. Both are set later, from
    /// [`DatapathEnds::report`], because both come from the port and the ports are not up yet.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] if netlink is unreachable or a tap cannot be created. Neither is
    /// recoverable: without the taps there is no control plane.
    pub(crate) fn create(
        handle: &tokio::runtime::Handle,
        mgmt: &Subsystem,
        interfaces: impl IntoIterator<Item = InterfaceName>,
    ) -> Result<(Self, DatapathEnds), BridgeError> {
        let names: Vec<InterfaceName> = interfaces.into_iter().collect();
        // A child, so that dropping the bridge stops its own tasks and nothing else on mgmt.
        let cancel = mgmt.cancel_token().child_token();
        let taps = Arc::new(TapRegistry::default());

        let _guard = handle.enter();

        // The bridge's own netlink socket, opened here so that it belongs to the control namespace
        // like everything else on this runtime. It is only ever used to dress the taps.
        let (connection, netlink, _) =
            rtnetlink::new_connection().map_err(|e| BridgeError::Netlink(e.to_string()))?;
        handle.spawn(connection);
        let netlink = Arc::new(netlink);

        let mut ports = HashMap::with_capacity(names.len());
        let mut links = HashMap::with_capacity(names.len());
        let mut identities = HashMap::with_capacity(names.len());
        let mut bridge_ports = Vec::with_capacity(names.len());
        let (heard_tx, heard_rx) = mpsc::channel(HEARD_QUEUE_DEPTH);
        for name in &names {
            // Created here, on this runtime, in this namespace. Everything downstream is just
            // descriptors, which travel anywhere.
            let tap = taps.open(name).map_err(|source| BridgeError::Tap {
                name: name.clone(),
                source,
            })?;

            // Learned when the tap was created, in the namespace it lives in. This index is what
            // the whole dataplane above the driver will call this interface -- see
            // `PortCpQueues::index`.
            let index = tap.index();

            let (punt_tx, punt_rx) = mpsc::channel(QUEUE_DEPTH);
            let (inject_tx, inject_rx) = mpsc::channel(QUEUE_DEPTH);
            // Down until the driver says otherwise: nothing should be sent on a port nobody has
            // seen come up.
            let (link_tx, link_rx) = watch::channel(Link::Down);
            let (identity_tx, identity_rx) = watch::channel(None);
            links.insert(name.to_string(), link_tx);
            identities.insert(name.to_string(), identity_tx);
            bridge_ports.push(BridgePort {
                name: name.clone(),
                inject: inject_tx.clone(),
                link: link_rx,
                identity: identity_rx,
            });

            handle.spawn(pump(
                tap,
                punt_rx,
                inject_tx,
                heard_tx.clone(),
                cancel.clone(),
                mgmt.clone(),
            ));

            debug!("tap {name} is interface index {index}");
            ports.insert(
                name.to_string(),
                PortCpQueues {
                    index,
                    punt: punt_tx,
                    inject: Some(inject_rx),
                },
            );
        }

        let (identity_tx, identity_rx) = mpsc::channel(names.len().max(1));
        handle.spawn(dress_taps(netlink, identity_rx, identities, cancel.clone()));

        info!(
            "control-plane bridge holding {} tap(s): {}",
            names.len(),
            names
                .iter()
                .map(InterfaceName::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok((
            CpBridge {
                taps,
                cancel,
                ports: bridge_ports,
                heard: Some(heard_rx),
            },
            DatapathEnds {
                ports,
                identities: identity_tx,
                links,
            },
        ))
    }

    /// Every port the bridge holds, for control-plane services that transmit on them.
    pub(crate) fn ports(&self) -> &[BridgePort] {
        &self.ports
    }

    /// Take the LLDP frames received on the bridge's ports. There is one taker.
    pub(crate) fn take_heard(&mut self) -> Option<mpsc::Receiver<HeardFrame>> {
        self.heard.take()
    }

    /// The taps this bridge is holding open.
    #[cfg(test)]
    pub(crate) fn taps(&self) -> &TapRegistry {
        &self.taps
    }
}

impl Drop for CpBridge {
    fn drop(&mut self) {
        // Stop the pump tasks first: each holds a share of a tap's descriptor, and the device only
        // goes when the last share does. This does not wait for them, so a task that is mid-write
        // may outlive this by a poll; the descriptors it holds are closed by the kernel at exit
        // regardless, which is the guarantee that actually matters.
        self.cancel.cancel();
        for name in self.taps.names() {
            if !self.taps.close(&name) {
                warn!("the control-plane bridge did not hold tap {name} it thought it held");
            }
        }
        debug!("control-plane bridge shut down");
    }
}

/// Carry frames between one tap and its port, in both directions, until cancelled.
///
/// One task rather than two because [`TapDevice`] reads and writes through `&self`: the descriptor
/// is registered with the reactor, so both directions can be awaited from the same place without
/// splitting it. Neither direction can starve the other -- `select!` polls both.
///
/// Read errors are retried. If they persist, `mgmt` is told the gateway is broken.
async fn pump(
    tap: Arc<TapDevice>,
    mut punt: mpsc::Receiver<Frame>,
    inject: mpsc::Sender<Frame>,
    heard: mpsc::Sender<HeardFrame>,
    cancel: CancellationToken,
    mgmt: Subsystem,
) {
    let name = tap.name().clone();
    let mut buf = vec![0u8; TapDevice::MAX_FRAME];
    let mut punt_write_errors: u64 = 0;
    let mut inject_drops: u64 = 0;
    let mut read_errors: u32 = 0;
    let mut heard_drops: u64 = 0;

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,

            // The kernel has a frame for the wire.
            read = tap.read(&mut buf) => match read {
                Ok(0) => {
                    warn!("tap {name} returned a zero-length frame; ignoring");
                }
                Ok(len) => {
                    read_errors = 0;
                    // `try_send` rather than `send`: a full injection queue means the datapath is
                    // not draining, and blocking here would stop the punt direction as well --
                    // turning a slow datapath into a dead control plane.
                    if inject.try_send(buf[..len].to_vec()).is_err() {
                        inject_drops += 1;
                        if inject_drops.is_power_of_two() {
                            warn!(
                                "dropped {inject_drops} frame(s) the kernel sent on {name}: the \
                                 datapath is not draining its injection queue"
                            );
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    read_errors += 1;
                    if read_errors >= READ_ERRORS_BEFORE_FATAL {
                        mgmt.report_fatal(&format!(
                            "tap {name} failed {read_errors} reads in a row, the last with {e}; \
                             the control plane on this port is deaf"
                        ));
                        break;
                    }
                    if read_errors.is_power_of_two() {
                        warn!("tap {name} could not be read ({read_errors} in a row): {e}");
                    }
                    tokio::time::sleep(READ_RETRY).await;
                }
            },

            // The datapath has a frame for the kernel.
            frame = punt.recv() => {
                // `None` means every worker holding a punt sender is gone, so nothing will ever
                // punt to this tap again.
                let Some(frame) = frame else {
                    debug!("nothing is punting to {name} any more; stopping its pump");
                    break;
                };
                // LLDP is the dataplane's own business; the kernel gets a copy as well, which costs
                // nothing and keeps a capture on the tap honest.
                if is_lldp(&frame) {
                    let copy = HeardFrame { port: name.clone(), frame: frame.clone() };
                    if heard.try_send(copy).is_err() {
                        heard_drops += 1;
                        if heard_drops.is_power_of_two() {
                            warn!("dropped {heard_drops} LLDP frame(s) received on {name}: the LLDP agent is not keeping up");
                        }
                    }
                }
                if let Err(e) = tap.write(&frame).await {
                    punt_write_errors += 1;
                    if punt_write_errors.is_power_of_two() {
                        warn!("could not hand a frame to the kernel on {name} ({punt_write_errors} so far): {e}");
                    }
                }
            },
        }
    }

    debug!("control-plane pump for {name} stopped");
}

/// Whether `frame` is an untagged LLDP frame.
fn is_lldp(frame: &[u8]) -> bool {
    frame.get(12..14) == Some(&net::lldp::ETHTYPE.as_u16().to_be_bytes()[..])
}

/// Give each tap the MAC and MTU of the port it stands for, and bring it up.
///
/// This cannot happen when the tap is created: the ports are not up then, and a port's MAC and MTU
/// are things the PMD reports rather than things the configuration states. So the datapath reports
/// each port as it comes up and this applies it.
async fn dress_taps(
    netlink: Arc<rtnetlink::Handle>,
    mut identities: mpsc::Receiver<PortIdentity>,
    published: HashMap<String, watch::Sender<Option<PortIdentity>>>,
    cancel: CancellationToken,
) {
    loop {
        let next = tokio::select! {
            () = cancel.cancelled() => None,
            identity = identities.recv() => identity,
        };
        let Some(identity) = next else {
            break;
        };
        if let Some(port) = published.get(&identity.name) {
            port.send_replace(Some(identity.clone()));
        } else {
            warn!(
                "the datapath reported an identity for {}, a port the bridge does not hold",
                identity.name
            );
        }

        dress_one(&netlink, &identity).await;
    }
    // The kernel driver reports each port once and then drops its end, but what it reported stays
    // true. LLDP watches these identities and stops advertising when one closes, so they are held
    // until shutdown rather than until the datapath stops talking.
    cancel.cancelled().await;
    drop(published);
    debug!("tap identity applier stopped");
}

/// Apply one port's identity to its tap, logging what could not be applied.
///
/// The MAC and the MTU are separate requests. A tap that would not take the MTU still needs the MAC
/// and to be up: without those, ARP for the port fails, and a mismatched MTU only limits frame size.
async fn dress_one(netlink: &rtnetlink::Handle, identity: &PortIdentity) {
    use futures::TryStreamExt;
    use rtnetlink::LinkUnspec;

    let name = &identity.name;

    // Resolved to an index rather than addressed by name, so that a tap which vanished is a clear
    // error here rather than a `RTM_SETLINK` the kernel quietly applies to nothing.
    let index = match netlink
        .link()
        .get()
        .match_name(name.clone())
        .execute()
        .try_next()
        .await
    {
        Ok(Some(link)) => link.header.index,
        Ok(None) => {
            error!("tap {name} is gone, so it cannot take its port's identity");
            return;
        }
        Err(e) => {
            error!("could not look up tap {name} to give it its port's identity: {e}");
            return;
        }
    };

    if let Err(e) = netlink
        .link()
        .set(
            LinkUnspec::new_with_index(index)
                .address(identity.mac.0.to_vec())
                .up()
                .build(),
        )
        .execute()
        .await
    {
        error!(
            "could not give tap {name} its port's MAC {} and bring it up: {e}. ARP for this port \
             will not resolve and no adjacency will form.",
            identity.mac
        );
        return;
    }
    info!("tap {name} is up with its port's MAC {}", identity.mac);

    let Some(mtu) = identity.mtu else {
        warn!("the MTU of the port behind tap {name} is unknown; the tap keeps its own");
        return;
    };
    match netlink
        .link()
        .set(
            LinkUnspec::new_with_index(index)
                .mtu(u32::from(mtu))
                .build(),
        )
        .execute()
        .await
    {
        Ok(()) => info!("tap {name} has its port's MTU {mtu}"),
        Err(e) => error!(
            "could not give tap {name} its port's MTU {mtu}: {e}. Frames the kernel sends larger \
             than the port allows will be dropped."
        ),
    }
}

#[cfg(test)]
mod test {
    // The bridge itself, against a real kernel.

    use super::{CpBridge, PortIdentity};
    use caps::Capability;
    use fixin::wrap;
    use futures::TryStreamExt;
    use lifecycle::Shutdown;
    use net::eth::mac::Mac;
    use net::interface::InterfaceName;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use test_utils::with_caps;

    /// Run `exec` on a thread of its own, in a network namespace of its own.
    ///
    /// The bridge creates tap devices named after configured interfaces, so it has no business
    /// doing that in a namespace shared with anything real. A private one also means the addresses
    /// and the ARP below cannot reach or be answered by anything outside the test.
    fn in_private_netns<Exec, Fut, Out>(exec: Exec) -> Out
    where
        Exec: (FnOnce() -> Fut) + Send + 'static,
        Fut: Future<Output = Out>,
        Out: Send + 'static,
    {
        std::thread::Builder::new()
            .name("private-netns".to_string())
            .spawn(move || {
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap_or_else(|err| {
                    panic!("failed to create a private network namespace: {err}")
                });
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap_or_else(|err| panic!("failed to build tokio runtime: {err}"))
                    .block_on(exec())
            })
            .unwrap_or_else(|err| panic!("failed to spawn netns thread: {err}"))
            .join()
            .unwrap_or_else(|err| std::panic::resume_unwind(err))
    }

    /// An ARP request asking who has `target`, from `sender` at `sender_mac`.
    ///
    /// Hand-built rather than produced by the packet builders, because the point of the test is
    /// what a foreign station puts on the wire: nothing in this crate should get a say in it.
    fn arp_request(sender_mac: Mac, sender: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
        let mut frame = Vec::with_capacity(42);
        frame.extend_from_slice(&[0xff; 6]); // destination: broadcast
        frame.extend_from_slice(&sender_mac.0);
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // ethertype: ARP
        frame.extend_from_slice(&1u16.to_be_bytes()); // hardware type: ethernet
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol type: IPv4
        frame.push(6); // hardware address length
        frame.push(4); // protocol address length
        frame.extend_from_slice(&1u16.to_be_bytes()); // operation: request
        frame.extend_from_slice(&sender_mac.0);
        frame.extend_from_slice(&sender.octets());
        frame.extend_from_slice(&[0u8; 6]); // target hardware address: unknown
        frame.extend_from_slice(&target.octets());
        frame
    }

    /// The ARP reply this test is waiting for, if `frame` is one.
    ///
    /// Filtered rather than asserted on the first frame that arrives, because bringing a link up
    /// makes the kernel emit IPv6 multicast listener reports and router solicitations of its own,
    /// and which of those land first is not something a test may depend on.
    fn arp_reply_from(frame: &[u8], sender: Ipv4Addr) -> Option<Mac> {
        if frame.len() < 42 {
            return None;
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != 0x0806 {
            return None;
        }
        if u16::from_be_bytes([frame[20], frame[21]]) != 2 {
            return None; // not a reply
        }
        if Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]) != sender {
            return None;
        }
        Some(Mac([
            frame[22], frame[23], frame[24], frame[25], frame[26], frame[27],
        ]))
    }

    /// Verify both bridge directions using the kernel's ARP responder.
    /// Create a tap in a private namespace, report its MAC/MTU, assign an address,
    /// and punt an ARP request. Its reply must arrive on the injection queue.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn a_punted_frame_reaches_the_kernel_and_its_answer_comes_back() {
        const PORT_NAME: &str = "dp0";
        /// The MAC the datapath will report for the port. Locally administered, so it cannot
        /// collide with a real device.
        const PORT_MAC: Mac = Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        const PEER_MAC: Mac = Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        const OURS: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
        const PEER: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
        const MTU: u16 = 1500;

        in_private_netns(|| async {
            let handle = tokio::runtime::Handle::current();
            let shutdown = Shutdown::new();
            let name = InterfaceName::try_from(PORT_NAME).unwrap();

            let (bridge, mut ends) =
                CpBridge::create(&handle, &shutdown.mgmt, std::iter::once(name.clone()))
                    .unwrap_or_else(|e| panic!("could not build the control-plane bridge: {e}"));

            assert_eq!(
                bridge.taps().len(),
                1,
                "the bridge should be holding exactly the one tap it was asked for"
            );

            let mut queues = ends
                .take(PORT_NAME)
                .unwrap_or_else(|| panic!("the bridge made no queues for {PORT_NAME}"));
            let mut inject = queues
                .inject
                .take()
                .unwrap_or_else(|| panic!("the bridge made no injection queue for {PORT_NAME}"));

            // What the datapath reports once its ports are up. Applying it is asynchronous, so the
            // address below is what waits for it: `addr add` needs the link to exist, and the ARP
            // needs it to be up with the right MAC.
            ends.report(PortIdentity {
                name: PORT_NAME.to_string(),
                mac: PORT_MAC,
                mtu: Some(MTU),
                hardware: None,
                datapath_index: None,
            });

            let (connection, netlink, _) = rtnetlink::new_connection().unwrap();
            tokio::spawn(connection);

            // Retried, because dressing the tap runs on a task of its own and the address cannot be
            // added until it has finished bringing the link up.
            let mut added = None;
            for _ in 0..50 {
                let index = netlink
                    .link()
                    .get()
                    .match_name(PORT_NAME.to_string())
                    .execute()
                    .try_next()
                    .await
                    .ok()
                    .flatten()
                    .map(|link| link.header.index);
                if let Some(index) = index
                    && netlink
                        .address()
                        .add(index, IpAddr::V4(OURS), 24)
                        .execute()
                        .await
                        .is_ok()
                {
                    added = Some(index);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(
                added.is_some(),
                "could not give {PORT_NAME} an address; the bridge never brought its tap up"
            );

            // A worker punting a frame it received on this port.
            queues
                .punt
                .send(arp_request(PEER_MAC, PEER, OURS))
                .await
                .unwrap_or_else(|e| panic!("nothing is reading the punt queue: {e}"));

            // The kernel's answer, on its way to the wire.
            let reply_mac = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let frame = inject
                        .recv()
                        .await
                        .unwrap_or_else(|| panic!("the injection queue closed"));
                    if let Some(mac) = arp_reply_from(&frame, OURS) {
                        return mac;
                    }
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "no ARP reply for {OURS} arrived on the injection queue. Either the punted \
                     request never reached the kernel or its answer never came back, and either \
                     way no peer would ever resolve this port."
                )
            });

            assert_eq!(
                reply_mac, PORT_MAC,
                "the kernel answered ARP with the tap's own MAC rather than the port's, so the \
                 peer would send to an address this port does not answer to"
            );

            // The taps go with the bridge, which is what keeps a dead dataplane from stranding a
            // device on a name the real interface will want back.
            drop(bridge);
        });
    }

    /// A tap that gets its port's identity neither loses any of its addresses nor changes its
    /// admin or operational state, even when it is already up and addressed, as zebra leaves it
    /// when FRR is configured before the port is reported.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn taking_a_port_identity_keeps_the_tap_addresses_and_state() {
        use rtnetlink::LinkUnspec;
        use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage, State};
        use std::net::Ipv6Addr;

        const PORT_NAME: &str = "dp0";
        const PORT_MAC: Mac = Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        const MTU: u16 = 1400;
        const OURS_V4: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
        const OURS_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        in_private_netns(|| async {
            let handle = tokio::runtime::Handle::current();
            let shutdown = Shutdown::new();
            let name = InterfaceName::try_from(PORT_NAME).unwrap();
            let (bridge, ends) =
                CpBridge::create(&handle, &shutdown.mgmt, std::iter::once(name.clone()))
                    .unwrap_or_else(|e| panic!("could not build the control-plane bridge: {e}"));
            let index = bridge
                .taps()
                .get(&name)
                .unwrap_or_else(|| panic!("the bridge holds no tap named {PORT_NAME}"))
                .index()
                .to_u32();

            let (connection, netlink, _) = rtnetlink::new_connection().unwrap();
            tokio::spawn(connection);

            let get_link = async || -> LinkMessage {
                netlink
                    .link()
                    .get()
                    .match_index(index)
                    .execute()
                    .try_next()
                    .await
                    .unwrap_or_else(|e| panic!("could not look {PORT_NAME} up: {e}"))
                    .unwrap_or_else(|| panic!("{PORT_NAME} is gone"))
            };
            // Admin state, and the operational state the kernel reports.
            let states = |link: &LinkMessage| -> (bool, Option<State>) {
                let admin_up = link.header.flags.contains(LinkFlags::Up);
                let oper = link.attributes.iter().find_map(|attr| match attr {
                    LinkAttribute::OperState(state) => Some(*state),
                    _ => None,
                });
                (admin_up, oper)
            };

            // What zebra does before the port is reported: bring the tap up and address it.
            netlink
                .link()
                .set(LinkUnspec::new_with_index(index).up().build())
                .execute()
                .await
                .unwrap_or_else(|e| panic!("could not bring {PORT_NAME} up: {e}"));
            for (address, len) in [(IpAddr::V4(OURS_V4), 24), (IpAddr::V6(OURS_V6), 64)] {
                netlink
                    .address()
                    .add(index, address, len)
                    .execute()
                    .await
                    .unwrap_or_else(|e| panic!("could not give {PORT_NAME} {address}: {e}"));
            }

            let before = states(&get_link().await);
            assert!(
                before.0,
                "{PORT_NAME} should be administratively up before it is dressed"
            );

            ends.report(PortIdentity {
                name: PORT_NAME.to_string(),
                mac: PORT_MAC,
                mtu: Some(MTU),
                hardware: None,
                datapath_index: None,
            });

            // Applying the identity is asynchronous: wait for the MAC to change.
            let mut dressed = None;
            for _ in 0..50 {
                let link = get_link().await;
                if link.attributes.iter().any(
                    |attr| matches!(attr, LinkAttribute::Address(mac) if mac[..] == PORT_MAC.0),
                ) {
                    dressed = Some(link);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let dressed =
                dressed.unwrap_or_else(|| panic!("{PORT_NAME} never took its port's MAC"));

            assert_eq!(
                states(&dressed),
                before,
                "taking its port's identity changed the (admin, oper) state of {PORT_NAME}"
            );

            for address in [IpAddr::V4(OURS_V4), IpAddr::V6(OURS_V6)] {
                let kept = netlink
                    .address()
                    .get()
                    .set_link_index_filter(index)
                    .set_address_filter(address)
                    .execute()
                    .try_next()
                    .await
                    .unwrap_or_else(|e| panic!("could not list the addresses of {PORT_NAME}: {e}"));
                assert!(
                    kept.is_some(),
                    "{PORT_NAME} lost {address} when it took its port's identity; nothing would \
                     put it back, and the control plane would not be reachable on it"
                );
            }

            drop(bridge);
        });
    }

    /// The whole LLDP path short of a NIC: once the datapath reports a port up and a config names the
    /// gateway, LLDP frames naming both arrive on the port's injection queue, and stopping retracts
    /// them.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn a_named_gateway_advertises_on_a_port_that_is_up() {
        use lldp::Link;
        use net::headers::Headers;
        use net::lldp::{ChassisId, IdOctets, Lldpdu, OptionalTlv, PortId, Text};
        use net::parse::Parse;
        use tokio::sync::{mpsc, watch};

        const PORT_NAME: &str = "dp0";

        /// The next LLDP frame on `inject`, skipping whatever the kernel sends through the tap.
        async fn next_lldpdu(inject: &mut mpsc::Receiver<Vec<u8>>) -> Lldpdu {
            let next = async {
                loop {
                    let frame = inject.recv().await.expect("the injection queue closed");
                    if frame.get(12..14) != Some(&[0x88, 0xcc][..]) {
                        continue;
                    }
                    let (mut headers, _) = Headers::parse(&frame).expect("an LLDP frame parses");
                    return *headers
                        .take_lldp()
                        .expect("an LLDP frame carries an LLDPDU");
                }
            };
            tokio::time::timeout(Duration::from_secs(10), next)
                .await
                .expect("no LLDP frame arrived")
        }

        in_private_netns(|| async {
            let handle = tokio::runtime::Handle::current();
            let shutdown = Shutdown::new();
            let name = InterfaceName::try_from(PORT_NAME).unwrap();
            let (bridge, mut ends) =
                CpBridge::create(&handle, &shutdown.mgmt, std::iter::once(name.clone()))
                    .unwrap_or_else(|e| panic!("could not build the control-plane bridge: {e}"));
            let mut inject = ends.take(PORT_NAME).unwrap().inject.take().unwrap();
            let link = ends.take_link(PORT_NAME).unwrap();

            let (gateway_name, named) = watch::channel(None);
            let (_management, management) = watch::channel(None);
            let _new_neighbors = crate::lldp_agent::start(
                &handle,
                &shutdown.mgmt,
                bridge.ports(),
                &named,
                &management,
            );

            ends.report(PortIdentity {
                name: PORT_NAME.to_string(),
                mac: Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
                mtu: Some(1500),
                hardware: Some("0000:00:00.0 (test)".to_string()),
                datapath_index: None,
            });
            link.send_replace(Link::Up);
            gateway_name.send_replace(Some("gw-test".to_string()));

            let pdu = next_lldpdu(&mut inject).await;
            assert_eq!(
                *pdu.chassis_id(),
                ChassisId::LocallyAssigned(IdOctets::new(b"gw-test").unwrap())
            );
            assert_eq!(
                *pdu.port_id(),
                PortId::InterfaceName(IdOctets::new(PORT_NAME.as_bytes()).unwrap())
            );
            assert_eq!(pdu.ttl().as_secs(), 121);
            assert!(pdu.optional().contains(&OptionalTlv::PortDescription(
                Text::new(b"0000:00:00.0 (test)").unwrap()
            )));
            assert!(
                pdu.optional()
                    .contains(&OptionalTlv::SystemName(Text::new(b"gw-test").unwrap()))
            );

            shutdown.mgmt.cancel_token().cancel();
            loop {
                if next_lldpdu(&mut inject).await.ttl().is_shutdown() {
                    break;
                }
            }
            drop(bridge);
        });
    }

    /// The kernel driver reports each port once and drops its end when it has finished starting.
    /// What it reported has to stay published: LLDP stops advertising on a port whose identity
    /// closes, which is how a gateway in vlab came to send nothing at all.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn a_reported_identity_outlives_the_datapath_end() {
        const PORT_NAME: &str = "dp0";

        in_private_netns(|| async {
            let handle = tokio::runtime::Handle::current();
            let shutdown = Shutdown::new();
            let name = InterfaceName::try_from(PORT_NAME).unwrap();
            let (bridge, ends) =
                CpBridge::create(&handle, &shutdown.mgmt, std::iter::once(name.clone()))
                    .unwrap_or_else(|e| panic!("could not build the control-plane bridge: {e}"));
            let mut identity = bridge.ports()[0].identity.clone();

            ends.report(PortIdentity {
                name: PORT_NAME.to_string(),
                mac: Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
                mtu: Some(1500),
                hardware: None,
                datapath_index: None,
            });
            drop(ends);

            tokio::time::timeout(Duration::from_secs(10), identity.wait_for(Option::is_some))
                .await
                .expect("the reported identity was never published")
                .expect("the identity closed before it was published");
            // Long enough for the applier to notice that the datapath's end is gone.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(
                identity.has_changed().is_ok(),
                "the identity closed when the datapath dropped its end"
            );

            shutdown.mgmt.cancel_token().cancel();
            drop(bridge);
        });
    }

    /// The receive half of LLDP against real taps: a neighbour's frame that the datapath punts reaches
    /// the neighbour table, and the port going down forgets it.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn a_punted_lldp_frame_teaches_the_neighbour_table() {
        use lldp::{Advertisement, Link};
        use net::eth::mac::SourceMac;
        use net::lldp::{ChassisId, IdOctets, PortId, TimeToLive};
        use tokio::sync::watch;

        const PORT_NAME: &str = "dp0";

        in_private_netns(|| async {
            let handle = tokio::runtime::Handle::current();
            let shutdown = Shutdown::new();
            let name = InterfaceName::try_from(PORT_NAME).unwrap();
            let (mut bridge, mut ends) =
                CpBridge::create(&handle, &shutdown.mgmt, std::iter::once(name.clone()))
                    .unwrap_or_else(|e| panic!("could not build the control-plane bridge: {e}"));
            let queues = ends.take(PORT_NAME).unwrap();
            let link = ends.take_link(PORT_NAME).unwrap();
            link.send_replace(Link::Up);

            let (publish, mut snapshot) =
                watch::channel(crate::lldp_agent::NeighborSnapshot::default());
            let heard = bridge.take_heard().expect("the bridge hears LLDP once");
            crate::lldp_agent::listen(
                &handle,
                &shutdown.mgmt,
                heard,
                bridge.ports(),
                std::collections::HashMap::new(),
                publish,
            );

            let leaf = Advertisement::new(
                SourceMac::new(Mac([0x02, 0, 0, 0, 0, 0x10])).unwrap(),
                ChassisId::LocallyAssigned(IdOctets::new(b"leaf-1").unwrap()),
                PortId::InterfaceName(IdOctets::new(b"Ethernet8").unwrap()),
                [],
            )
            .unwrap();
            queues
                .punt
                .send(leaf.frame(TimeToLive::new(120)))
                .await
                .unwrap();

            let within = Duration::from_secs(10);
            tokio::time::timeout(within, snapshot.wait_for(|s| s.len() == 1))
                .await
                .expect("the neighbour was never learned")
                .unwrap();

            link.send_replace(Link::Down);
            tokio::time::timeout(within, snapshot.wait_for(|s| s.len() == 0))
                .await
                .expect("a downed port kept its neighbour")
                .unwrap();
            drop(bridge);
        });
    }
}
