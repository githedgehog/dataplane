// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! This module contains the ARP/ND "daemon" for ARP and ND.
//! The daemon runs as a single tokio task, made of two parts:
//!    - the netlink listener, which updates the ARP/ND cache from netlink messages
//!    - the resolving task, which handles control messages, takes in the packets that need
//!      resolution, keeps them in the backlog until their targets get resolved (or are given
//!      up) and queries for those targets via netlink. It also has the kernel confirm the
//!      neighbors that are stale in the cache.

use lifecycle::Subsystem;
use net::buffer::PacketBufferMut;
use net::interface::{InterfaceIndex, InterfaceName};
use net::packet::{DoneReason, Packet};
use nix::net::if_::if_nametoindex;
use pkt_io::PktQueue;

use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tokio::time::{Duration, MissedTickBehavior, interval};
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::backlog::Backlog;
use crate::cache::{NeighCacheReader, NeighCacheWriter, NeighListener};
use crate::querier::{ArpNdQuerier, Target};

#[derive(Error, Debug)]
pub enum ArpNdError {
    #[error("Control failure: {0}")]
    ControlFailure(#[from] SendError<ArpNdCtlMsg>),
    #[error("Netlink failure: {0}")]
    Netlink(#[from] std::io::Error),
}

struct ArpNd<Buf: PacketBufferMut> {
    inq: PktQueue<Buf>,
    outq: PktQueue<Buf>,
    querier: ArpNdQuerier,
}

/// Object to control the ARP/ND daemon
#[derive(Clone)]
pub struct ArpNdCtl(Sender<ArpNdCtlMsg>);
impl ArpNdCtl {
    #[must_use]
    pub fn new(size: usize) -> (Self, Receiver<ArpNdCtlMsg>) {
        let (ctl_tx, ctl_rx) = channel::<ArpNdCtlMsg>(size);
        (ArpNdCtl(ctl_tx), ctl_rx)
    }
    pub async fn enable(&self, interfaces: &[InterfaceName]) -> Result<(), ArpNdError> {
        self.0
            .send(ArpNdCtlMsg::Enable(interfaces.to_vec()))
            .await
            .map_err(ArpNdError::ControlFailure)
    }
}

fn resolve_interface(ifname: &InterfaceName) -> Option<InterfaceIndex> {
    if_nametoindex(ifname.as_ref())
        .inspect_err(|e| error!("Could not find ifindex for {ifname}: {e}"))
        .ok()?
        .try_into()
        .inspect_err(|e| error!("Invalid ifindex for interface {ifname}:{e}"))
        .ok()
}
fn resolve_interfaces(required: &[InterfaceName]) -> Vec<InterfaceIndex> {
    required.iter().filter_map(resolve_interface).collect()
}

/// Control messages to control daemon: enable interfaces
pub enum ArpNdCtlMsg {
    Enable(Vec<InterfaceName>),
}

impl<Buf: PacketBufferMut> ArpNd<Buf> {
    // Period of the checks of the main task, done even if nothing else wakes it up: retrying or
    // giving up the targets in the backlog, and asking the kernel to confirm stale neighbors.
    // A neighbor being confirmed may be asked again (a no-op), since the kernel does not notify
    // that it left stale until it is confirmed or probed.
    const CHECK_PERIOD: Duration = Duration::from_secs(2);

    /// Create `ArpNd`. This spawns the netlink connection of its querier on the current
    /// tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails if the netlink connection for the querier cannot be created.
    pub fn new(inq: PktQueue<Buf>, outq: PktQueue<Buf>) -> Result<Self, ArpNdError> {
        let querier = ArpNdQuerier::new()?;
        Ok(Self { inq, outq, querier })
    }

    /// Get the target for a packet
    fn get_packet_target(packet: &Packet<Buf>) -> Option<Target> {
        let oif = packet.meta().oif?;
        let addr = if let Some(nh_addr) = packet.meta().nh_addr {
            Some(nh_addr)
        } else {
            packet.ip_destination()
        }?;
        Some(Target::new(addr, oif))
    }

    /// Drop a packet that cannot be resolved. The packet is handed back to the pipeline
    /// (via the output queue) so that the drop is accounted for.
    fn drop_packet(&self, mut packet: Packet<Buf>, reason: DoneReason) {
        packet.done(reason);
        if let Err(packet) = self.outq.push(packet) {
            trace!("Output queue is full: unable to return dropped packet\n{packet}");
        }
    }

    /// Determine the target of a packet that needs resolution and place the packet in the
    /// backlog, under that target. Packets for which no target can be determined, or whose
    /// target is not over an enabled interface, are rejected and sent back to the outq. The
    /// backlog may reject packets too due to space constraints.
    fn packet_resolve(
        &self,
        backlog: &mut Backlog<Buf>,
        packet: Packet<Buf>,
        enabled_ifs: &[InterfaceIndex],
    ) {
        let Some(target) = Self::get_packet_target(&packet) else {
            warn!("Could not determine the target for packet");
            self.drop_packet(packet, DoneReason::InternalDrop); // FIXME
            return;
        };
        if !enabled_ifs.contains(&target.ifindex) {
            debug!("Target {target} is not over an enabled interface");
            self.drop_packet(packet, DoneReason::InternalDrop); // FIXME
            return;
        }
        backlog.add(target, packet);
    }

    /// The resolving task of the daemon which:
    ///   - handles control messages indicating which interfaces are to be enabled / used
    ///   - processes incoming packets that require resolution, placing them in the backlog queue
    ///   - issues queries for the corresponding targets
    ///   - when targets get resolved (it gets notified by the listener), re-processes the
    ///     backlog and returns packets back to the pipeline.
    ///   - handles the retries for un-answered ARP/ND requests and gives up unresolved targets
    ///   - periodically, has the kernel confirm the neighbors that are stale in the cache, if they
    ///     are over an enabled interface. Those that the kernel cannot confirm fail, and become
    ///     unusable in the cache.
    async fn resolving_task(
        &self,
        mut ctl: Receiver<ArpNdCtlMsg>,
        cacher: NeighCacheReader,
        added: Arc<Notify>,
    ) {
        let mut backlog = Backlog::new(cacher.clone(), self.outq.clone());
        let mut enabled_ifs: Vec<InterfaceIndex> = vec![];
        let mut check = interval(Self::CHECK_PERIOD);
        check.set_missed_tick_behavior(MissedTickBehavior::Delay);

        info!("ARP/ND main task started...");
        loop {
            let mut check_stale = false;
            // biased: branches are polled in order, so control messages take effect before the
            // packets ready at the same time. Packets can't starve: they are drained every pass.
            tokio::select! {
                biased;
                msg = ctl.recv() => match msg {
                    Some(ArpNdCtlMsg::Enable(required)) => {
                        info!("Got enable request. Required interfaces are: {required:?}");
                        let new_ifs = resolve_interfaces(&required);
                        // give up the targets over the interfaces no longer enabled
                        for ifindex in enabled_ifs.iter().filter(|i| !new_ifs.contains(i)) {
                            info!("ARP/ND disabled on interface {ifindex}: giving up its targets");
                            backlog.give_up_interface(*ifindex);
                        }
                        enabled_ifs = new_ifs;
                    }
                    None => {
                        info!("ARP/ND control channel closed");
                        break;
                    }
                },
                _ = check.tick() => {
                    check_stale = true;
                }
                () = added.notified() => debug!("ARP/ND cache was updated."),
                Some(packet) = self.inq.pop_async() => {
                    debug!("Got packets to resolve");
                    self.packet_resolve(&mut backlog, packet, &enabled_ifs);
                }
            }

            // take the rest of the packets that need resolution. Only the packets queued at this
            // point are taken, so that the pipeline cannot prevent us task from checking, querying and giving up targets.
            for packet in self.inq.pop_ready() {
                self.packet_resolve(&mut backlog, packet, &enabled_ifs);
            }

            // resolve backloged packets if their target got resolved (mac is in cache)
            backlog.check_targets();

            //
            // query the targets that need it (new ones and those to retry), and give up
            // those with no retries left. The netlink listener should see the responses,
            // update the cache and wake up this task.
            let targets = backlog.targets_to_query();
            if !targets.is_empty() {
                self.querier.multi_query(targets.iter()).await;
            }

            // periodically, check if there are stale entries in the cache (as reported by the kernel).
            // If there are, let the querier ask the kernel to confirm them by probing them.
            if check_stale {
                let stale = cacher.stale_entries(&enabled_ifs);
                if !stale.is_empty() {
                    self.querier.multi_confirm(stale.into_iter()).await;
                }
            }
        }
    }

    /// Run the daemon: first, learn the neighbors that the kernel already has (see
    /// [`NeighListener::sync`]); then, the main task and the netlink listener, concurrently. The
    /// daemon ends when stopped (see [`ArpNdCtl::stop`]), when `subsystem` is cancelled, or if
    /// learning the existing neighbors fails or the listener ends, which are reported as fatal
    /// errors of `subsystem`.
    async fn run(
        self,
        ctl: Receiver<ArpNdCtlMsg>,
        mut listener: NeighListener,
        cacher: NeighCacheReader,
        cache_notify: Arc<Notify>,
        subs: Subsystem,
    ) {
        info!("ARP/ND daemon started");
        let cancel = subs.cancel_token();

        // learn the neighbors that the kernel already has, before resolving anything: their
        // packets would be queried otherwise, and probing a static neighbor destroys it.
        match listener.sync().await {
            Ok(num_entries) => info!("Learnt {num_entries} existing neighbors"),
            Err(e) => {
                error!("Could not learn the existing neighbors: {e}");
                subs.report_fatal("ARP/ND failed to learn the existing neighbors");
                return;
            }
        }

        tokio::select! {
            () = self.resolving_task(ctl, cacher, cache_notify) => {
                info!("ARP/ND main task ended");
            }
            () = listener.start() => {
                subs.report_fatal("ARP/ND netlink listener ended");
            }
            () = cancel.cancelled() => info!("ARP/ND daemon cancelled"),
        }
        info!("ARP/ND daemon stopped");
    }
}

/// Spawn the ARP/ND daemon on `handle`, tracked under the given `subsystem`. The daemon
/// becomes the writer of the ARP/ND cache `cachew`.
///
/// # Errors
///
/// Fails if the netlink connections used to issue ARP/ND queries or to listen to neighbor
/// changes cannot be created.
pub(crate) fn start_arp_nd<Buf: PacketBufferMut + Send + 'static>(
    rt_handle: &tokio::runtime::Handle,
    subs: &Subsystem,
    inq: PktQueue<Buf>,
    outq: PktQueue<Buf>,
    cachew: NeighCacheWriter,
) -> Result<(JoinHandle<()>, ArpNdCtl), ArpNdError> {
    info!("Starting ARP/ND daemon...");

    // create cache reader for resolver task
    let cacher = cachew.factory().handle();

    // create notifier: listener will notify of cache changes to daemon
    let cache_notify = Arc::new(Notify::new());

    // enter the runtime so that the netlink sockets are created there
    let (arpd, listener) = {
        let _guard = rt_handle.enter();
        let arpd = ArpNd::new(inq, outq)?;
        let listener = NeighListener::new(cachew, cache_notify.clone())?;
        (arpd, listener)
    };

    // create ArpNd control channel
    let (arp_ctl, ctl_rx) = ArpNdCtl::new(100);

    let jh = subs.spawn_on(
        arpd.run(ctl_rx, listener, cacher, cache_notify, subs.clone()),
        rt_handle,
    );
    info!("Successfully started ARP/ND daemon...");
    Ok((jh, arp_ctl))
}
