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

use concurrency::sync::Arc;
use interface_manager::interface::{TapDevice, TapRegistry};
use lifecycle::{CancellationToken, Subsystem};
use net::eth::mac::Mac;
use net::interface::{InterfaceIndex, InterfaceName};
use net::packet::DoneReason;
use tokio::sync::mpsc;
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
    /// The MTU the port settled on, which may not be the one that was asked for.
    pub(crate) mtu: u16,
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
}

impl DatapathEnds {
    /// Take the bridge ends for the port named `name`, if the bridge made any.
    ///
    /// Taken rather than borrowed, so a port claimed twice gets `None` the second time instead of
    /// two workers quietly sharing one injection queue.
    pub(crate) fn take(&mut self, name: &str) -> Option<PortCpQueues> {
        self.ports.remove(name)
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

/// Where the datapath should send a packet the pipeline has finished with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Transmit it on the interface the pipeline chose.
    Transmit,
    /// Hand it to the kernel through the tap of the port it arrived on.
    Punt,
    /// Free it.
    Drop,
}

/// Choose whether to forward, punt, or drop a completed packet.
///
/// `Local` always punts. `Unhandled`, `NotIp`, and `RouteFailure` punt only when
/// addressed to us, including broadcast and multicast. This carries ARP requests
/// and replies through the kernel. Explicit drops never punt.
///
/// This fixed policy uses destination MAC rather than protocol; unroutable IP
/// traffic addressed to the port also reaches the kernel.
pub(crate) fn disposition(done: Option<DoneReason>, addressed_to_us: bool) -> Disposition {
    // Exhaustive on purpose. A new `DoneReason` is a new decision about whether the kernel should
    // see that packet, and this is where it has to be made; a wildcard would answer "no" silently.
    match done {
        Some(DoneReason::Delivered) => Disposition::Transmit,

        Some(DoneReason::Local) => Disposition::Punt,

        // Addressed to us, and the datapath had nothing to do with it.
        Some(DoneReason::Unhandled | DoneReason::NotIp | DoneReason::RouteFailure) => {
            if addressed_to_us {
                Disposition::Punt
            } else {
                Disposition::Drop
            }
        }

        // Decisions the datapath made, and failures the kernel cannot do anything about -- together
        // with `None`, which is no verdict at all: a pipeline that did not finish with the packet
        // is a bug rather than a routing outcome, and dropping matches what the driver has always
        // done with one.
        None
        | Some(
            DoneReason::InternalFailure
            | DoneReason::InterfaceUnknown
            | DoneReason::InterfaceDetached
            | DoneReason::InterfaceAdmDown
            | DoneReason::InterfaceOperDown
            | DoneReason::InterfaceUnsupported
            | DoneReason::NotEthernet
            | DoneReason::MacNotForUs
            | DoneReason::InvalidDstMac
            | DoneReason::MissingEtherType
            | DoneReason::RouteDrop
            | DoneReason::HopLimitExceeded
            | DoneReason::MissL2resolution
            | DoneReason::VxlanDecapFailure
            | DoneReason::VxlanEncapFailure
            | DoneReason::Filtered
            | DoneReason::AclDropped
            | DoneReason::NatOutOfResources
            | DoneReason::FlowCapacityExceeded
            | DoneReason::NatUnsupportedProto
            | DoneReason::NatFailure
            | DoneReason::NatNotPortForwarded
            | DoneReason::Malformed
            | DoneReason::Unroutable
            | DoneReason::InvalidChecksum
            | DoneReason::IcmpErrorIncomplete
            | DoneReason::InternalDrop
            | DoneReason::DeparseError
            | DoneReason::NoHeadRoom,
        ) => Disposition::Drop,
    }
}

/// True if a frame with this destination MAC was addressed to a port with this one.
///
/// Broadcast and multicast count: the peer's ARP request, the fabric's LLDP, and IPv6 neighbour
/// discovery all arrive that way, and all of them are the control plane's business.
#[must_use]
pub(crate) fn addressed_to(destination: Mac, port: Mac) -> bool {
    destination == port || destination.is_broadcast() || destination.is_multicast()
}

/// Anything that can go wrong building the bridge.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BridgeError {
    /// A netlink socket could not be opened in the control namespace.
    #[error("could not open a netlink socket for the control-plane bridge: {0}")]
    Netlink(String),
    /// A tap device could not be created.
    #[error("could not create the tap device for interface {name}: {source}")]
    Tap {
        /// The interface whose tap could not be made.
        name: InterfaceName,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A tap was created but the kernel would not say what index it got.
    ///
    /// Fatal rather than skipped: without the index the datapath has no name for this interface
    /// that the rest of the dataplane would recognise.
    #[error("could not learn the interface index of the tap for {name}: {problem}")]
    TapIndex {
        /// The interface whose tap could not be identified.
        name: InterfaceName,
        /// What went wrong.
        problem: String,
    },
}

/// The control plane's end of the bridge: the taps, and the tasks which pump them.
pub(crate) struct CpBridge {
    /// The descriptors that keep the taps alive. Dropping this removes every one of them.
    taps: Arc<TapRegistry>,
    /// Stops the pump tasks so that they let go of their share of the descriptors.
    cancel: CancellationToken,
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
    pub(crate) fn create<'a>(
        handle: &tokio::runtime::Handle,
        mgmt: &Subsystem,
        interfaces: impl Iterator<Item = &'a InterfaceName>,
    ) -> Result<(Self, DatapathEnds), BridgeError> {
        let names: Vec<InterfaceName> = interfaces.cloned().collect();
        let cancel = mgmt.cancel_token();
        let taps = Arc::new(TapRegistry::default());

        let _guard = handle.enter();

        // The bridge's own netlink socket, opened here so that it belongs to the control namespace
        // like everything else on this runtime. It is only ever used to dress the taps.
        let (connection, netlink, _) =
            rtnetlink::new_connection().map_err(|e| BridgeError::Netlink(e.to_string()))?;
        handle.spawn(connection);
        let netlink = Arc::new(netlink);

        let mut ports = HashMap::with_capacity(names.len());
        for name in &names {
            // Created here, on this runtime, in this namespace. Everything downstream is just
            // descriptors, which travel anywhere.
            let tap = taps.open(name).map_err(|source| BridgeError::Tap {
                name: name.clone(),
                source,
            })?;

            // Asked for now, on the thread that made it and in the namespace it lives in. This
            // index is what the whole dataplane above the driver will call this interface -- see
            // `PortCpQueues::index` -- so a bridge that could not learn it has not built a usable
            // port.
            let index = tap_index(name).map_err(|problem| BridgeError::TapIndex {
                name: name.clone(),
                problem,
            })?;

            let (punt_tx, punt_rx) = mpsc::channel(QUEUE_DEPTH);
            let (inject_tx, inject_rx) = mpsc::channel(QUEUE_DEPTH);

            handle.spawn(pump(
                name.to_string(),
                tap,
                punt_rx,
                inject_tx,
                cancel.clone(),
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
        handle.spawn(dress_taps(netlink, identity_rx, cancel.clone()));

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
            CpBridge { taps, cancel },
            DatapathEnds {
                ports,
                identities: identity_tx,
            },
        ))
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
async fn pump(
    name: String,
    tap: Arc<TapDevice>,
    mut punt: mpsc::Receiver<Frame>,
    inject: mpsc::Sender<Frame>,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; TapDevice::MAX_FRAME];
    let mut punt_write_errors: u64 = 0;
    let mut inject_drops: u64 = 0;

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,

            // The kernel has a frame for the wire.
            read = tap.read(&mut buf) => match read {
                Ok(0) => {
                    warn!("tap {name} returned a zero-length frame; ignoring");
                }
                Ok(len) => {
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
                Err(e) => {
                    error!("tap {name} could not be read: {e}; the control plane on this port is now deaf");
                    break;
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

/// Give each tap the MAC and MTU of the port it stands for, and bring it up.
///
/// This cannot happen when the tap is created: the ports are not up then, and a port's MAC and MTU
/// are things the PMD reports rather than things the configuration states. So the datapath reports
/// each port as it comes up and this applies it.
async fn dress_taps(
    netlink: Arc<rtnetlink::Handle>,
    mut identities: mpsc::Receiver<PortIdentity>,
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

        if let Err(e) = dress_one(&netlink, &identity).await {
            error!(
                "could not give tap {} the identity of its port ({}, mtu {}): {e}. ARP for this \
                 port will not resolve and no adjacency will form.",
                identity.name, identity.mac, identity.mtu
            );
        } else {
            info!(
                "tap {} is up with its port's MAC {} and MTU {}",
                identity.name, identity.mac, identity.mtu
            );
        }
    }
    debug!("tap identity applier stopped");
}

/// Look up the tap synchronously in the calling thread's network namespace.
/// This avoids needing to await a netlink request during bridge construction.
fn tap_index(name: &InterfaceName) -> Result<InterfaceIndex, String> {
    let raw = nix::net::if_::if_nametoindex(name.to_string().as_str())
        .map_err(|e| format!("if_nametoindex: {e}"))?;
    InterfaceIndex::try_new(raw).map_err(|e| e.to_string())
}

/// Apply one port's identity to its tap.
async fn dress_one(
    netlink: &rtnetlink::Handle,
    identity: &PortIdentity,
) -> Result<(), rtnetlink::Error> {
    use futures::TryStreamExt;
    use rtnetlink::LinkUnspec;

    // Resolved to an index rather than addressed by name, so that a tap which vanished is a clear
    // error here rather than a `RTM_SETLINK` the kernel quietly applies to nothing.
    let link = netlink
        .link()
        .get()
        .match_name(identity.name.clone())
        .execute()
        .try_next()
        .await?
        .ok_or(rtnetlink::Error::RequestFailed)?;
    let index = link.header.index;

    // The address has to be set while the link is down; the MTU and the admin state then follow.
    netlink
        .link()
        .set(
            LinkUnspec::new_with_index(index)
                .down()
                .address(identity.mac.0.to_vec())
                .build(),
        )
        .execute()
        .await?;

    netlink
        .link()
        .set(
            LinkUnspec::new_with_index(index)
                .mtu(u32::from(identity.mtu))
                .build(),
        )
        .execute()
        .await?;

    netlink
        .link()
        .set(LinkUnspec::new_with_index(index).up().build())
        .execute()
        .await
}

#[cfg(test)]
mod test {
    use super::{Disposition, addressed_to, disposition};
    use net::eth::mac::Mac;
    use net::packet::DoneReason;
    use strum::EnumCount as _;

    const PORT: Mac = Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const SOMEBODY_ELSE: Mac = Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    const BROADCAST: Mac = Mac([0xff; 6]);
    /// The IPv6 all-nodes multicast MAC, which is what neighbour discovery arrives on.
    const MULTICAST: Mac = Mac([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);

    #[test]
    fn only_frames_for_us_are_addressed_to_us() {
        assert!(addressed_to(PORT, PORT), "our own MAC is for us");
        assert!(addressed_to(BROADCAST, PORT), "broadcast is for everyone");
        assert!(
            addressed_to(MULTICAST, PORT),
            "multicast carries neighbour discovery and must reach the kernel"
        );
        assert!(
            !addressed_to(SOMEBODY_ELSE, PORT),
            "a frame for another station is not ours"
        );
    }

    /// The whole punt policy, verdict by verdict.
    ///
    /// Written out rather than derived from [`disposition`] on purpose: a test that recomputed the
    /// policy would agree with any policy at all. This is the statement of what the control plane
    /// is entitled to see, and changing [`disposition`] should have to change it here too.
    ///
    /// Break-tested: inverting any single arm below (say, making `AclDropped` punt when addressed
    /// to us, or making `NotIp` drop) fails this test.
    // The table below is data, not logic: every arm is one verdict, and the point is that all of
    // them are written out. Splitting it to satisfy a line count would only hide that.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn punt_policy_table() {
        // (verdict, disposition when addressed to us, disposition otherwise)
        let table: &[(DoneReason, Disposition, Disposition)] = &[
            // Transmitted regardless of who the frame was for: by this point the pipeline has
            // rewritten the destination MAC to the next hop's, so "addressed to us" is meaningless.
            (
                DoneReason::Delivered,
                Disposition::Transmit,
                Disposition::Transmit,
            ),
            // The pipeline said so explicitly.
            (DoneReason::Local, Disposition::Punt, Disposition::Punt),
            // The three that carry the control plane.
            (DoneReason::Unhandled, Disposition::Punt, Disposition::Drop),
            (DoneReason::NotIp, Disposition::Punt, Disposition::Drop),
            (
                DoneReason::RouteFailure,
                Disposition::Punt,
                Disposition::Drop,
            ),
            // Everything else is a decision the datapath already made.
            (
                DoneReason::InternalFailure,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::InterfaceUnknown,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::InterfaceDetached,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::InterfaceAdmDown,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::InterfaceOperDown,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::InterfaceUnsupported,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::NotEthernet,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::MacNotForUs,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::InvalidDstMac,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::MissingEtherType,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (DoneReason::RouteDrop, Disposition::Drop, Disposition::Drop),
            (
                DoneReason::HopLimitExceeded,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::MissL2resolution,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::VxlanDecapFailure,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::VxlanEncapFailure,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (DoneReason::Filtered, Disposition::Drop, Disposition::Drop),
            (DoneReason::AclDropped, Disposition::Drop, Disposition::Drop),
            (
                DoneReason::NatOutOfResources,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::FlowCapacityExceeded,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::NatUnsupportedProto,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (DoneReason::NatFailure, Disposition::Drop, Disposition::Drop),
            (
                DoneReason::NatNotPortForwarded,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (DoneReason::Malformed, Disposition::Drop, Disposition::Drop),
            (DoneReason::Unroutable, Disposition::Drop, Disposition::Drop),
            (
                DoneReason::InvalidChecksum,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::IcmpErrorIncomplete,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::InternalDrop,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (
                DoneReason::DeparseError,
                Disposition::Drop,
                Disposition::Drop,
            ),
            (DoneReason::NoHeadRoom, Disposition::Drop, Disposition::Drop),
        ];

        for (verdict, for_us, not_for_us) in table {
            assert_eq!(
                disposition(Some(*verdict), true),
                *for_us,
                "wrong disposition for {verdict:?} addressed to us"
            );
            assert_eq!(
                disposition(Some(*verdict), false),
                *not_for_us,
                "wrong disposition for {verdict:?} addressed elsewhere"
            );
        }

        // The table has to name every verdict, not merely the interesting ones. Without this a
        // verdict added later would default to whatever `disposition`'s author decided, with no
        // test asserting that the control plane was considered at all.
        assert_eq!(
            table.len(),
            DoneReason::COUNT,
            "the punt policy table has drifted from `DoneReason`: every verdict is a decision \
             about whether the control plane may see that packet, so a new one has to be made \
             here as well as in `disposition`"
        );
    }

    #[test]
    fn a_packet_with_no_verdict_is_dropped() {
        assert_eq!(disposition(None, true), Disposition::Drop);
        assert_eq!(disposition(None, false), Disposition::Drop);
    }

    // ------------------------------------------------------------------------------------------
    // The bridge itself, against a real kernel.
    // ------------------------------------------------------------------------------------------

    use super::{CpBridge, PortIdentity};
    use caps::Capability;
    use fixin::wrap;
    use futures::TryStreamExt;
    use lifecycle::Shutdown;
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
                CpBridge::create(&handle, &shutdown.mgmt, std::iter::once(&name))
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
                mtu: MTU,
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
}
