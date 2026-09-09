// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bringing DPDK ports up, and the queue split that gives each worker its own.

use dpdk::dev::{Dev, DevConfig, DevInfo, RssConf, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::mem::{Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use errno::ErrorCode;
use net::eth::mac::Mac;
use net::interface::InterfaceIndex;
use stats::PortCounters;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::DriverError;
use crate::drivers::cpbridge::{DatapathEnds, Frame};

/// Receive descriptors per queue.
///
/// This is buffering, measured in frames the port can hold while a worker is busy elsewhere. It is
/// only worth what the offload configuration lets it be worth: requesting the device's full
/// receive-offload capability mask enables LRO, which reserves enough descriptors per packet to
/// return a 64 KiB coalesced segment and so cuts the usable depth by a factor of 32. See
/// [`rx_offloads`](Port::bring_up).
const RX_DESCRIPTORS: u16 = 1024;

/// Transmit descriptors per queue.
const TX_DESCRIPTORS: u16 = 1024;

/// Mbufs in a port's receive pool, per worker.
///
/// Each receive queue parks `RX_DESCRIPTORS` of these in its ring before a single frame arrives, so
/// this has to exceed that with room to spare: the surplus is what covers mbufs in flight through
/// the pipeline and mbufs sitting in a transmit ring waiting to be reclaimed. Too small shows up as
/// `rx_nombuf` on the port, not as an allocation error here.
const POOL_MBUFS_PER_WORKER: u32 = 4 * RX_DESCRIPTORS as u32;

/// Decide the RSS configuration for a port, warning if the device cannot spread at all.
///
/// RSS is what actually distributes received frames across the per-worker receive queues. Without
/// it every frame lands on queue 0 and exactly one worker does all the work, however many were
/// configured. The key is the standard Toeplitz one and the hash covers whatever subset of L3
/// addresses and L4 ports the device advertises.
///
/// Deliberately *not* symmetric. Two reasons, and the second is the one that settles it: mlx5
/// rejects any hash function but the default at `rte_eth_dev_configure`, so symmetric Toeplitz is
/// reachable only through the `rte_flow` RSS action (see [`RssConf`]); and a NAT'd flow's reverse
/// packet carries the *translated* tuple rather than the reversed one, so no symmetry property the
/// NIC could have would land a flow's two halves on the same worker. It does not need to: flow
/// state lives in one `FlowTable` shared by every worker, so any worker can service any packet.
///
/// Returns `None` for a device that advertises no RSS hash functions -- how the emulated NICs
/// (e1000, e1000e, virtio without multi-queue negotiation) report. Such a port still works; it
/// simply cannot use more than one worker.
fn rss_for(info: &DevInfo, name: &str, num_workers: u16) -> Option<RssConf> {
    let rss = RssConf::supported_on(info);
    if rss.is_none() && num_workers > 1 {
        warn!(
            "port {index} ({name}) advertises no RSS hash functions, so all {num_workers} workers \
             will share receive queue 0 and only one of them will do any work",
            index = info.index()
        );
    }
    rss
}

/// Say what the port's link is doing, loudly when it is down.
///
/// Separate from `bring_up` only to keep that function within its line budget; it belongs to it.
///
/// A port with no carrier is otherwise indistinguishable from a working one: every configuration
/// step succeeds, the driver reports "started", the workers poll happily, and nothing arrives.
/// Nothing is wrong from DPDK's side, so nothing in the driver complains. For a bifurcated device
/// the usual cause is the kernel netdev being administratively down -- the port follows the netdev,
/// and moving an interface between network namespaces clears `IFF_UP`.
fn report_link(
    dev: &Dev<'_, Started>,
    index: dpdk::dev::DevIndex,
    name: &str,
    if_index: InterfaceIndex,
    mac: Mac,
    mtu: u16,
    num_workers: u16,
) {
    match dev.link() {
        Ok(link) if link.up => info!(
            "DPDK port {index} ({name}) up: ifindex {if_index}, mac {mac}, mtu {mtu}, \
             {num_workers} rx/tx queue pair(s), link {link}"
        ),
        Ok(link) => warn!(
            "DPDK port {index} ({name}) is configured and started but its link is {link}: \
             ifindex {if_index}, mac {mac}, mtu {mtu}, {num_workers} rx/tx queue pair(s). No \
             traffic will pass. For a bifurcated device such as mlx5 the port follows its kernel \
             netdev, so check that the netdev is up inside the datapath network namespace."
        ),
        Err(e) => info!(
            "DPDK port {index} ({name}) up: ifindex {if_index}, mac {mac}, mtu {mtu}, \
             {num_workers} rx/tx queue pair(s); link state unavailable ({e:?})"
        ),
    }
}

/// How many mbufs a port's receive pool holds and how big each one's data room is.
///
/// Split out to keep `bring_up` within its line budget; it belongs to it.
///
/// The room is sized against the MTU the device was just configured with, not against
/// `PoolParams::default()`. The cost is logged because it multiplies: one room per mbuf and a
/// 24-worker port wants ~98k of them, so this is the difference between ~200 MiB and ~900 MiB of
/// hugepages on a single port, and a port reserving most of a grant should say so.
fn pool_shape(
    dev: &Dev<'_, dpdk::dev::Stopped>,
    index: dpdk::dev::DevIndex,
    name: &str,
    num_workers: u16,
) -> (u32, u16) {
    let data_room = dpdk::mem::mbuf_data_room(dev.mtu().unwrap_or(1500));
    let pool_mbufs = POOL_MBUFS_PER_WORKER * u32::from(num_workers);
    info!(
        "port {index} ({name}) receive pool: {pool_mbufs} mbufs of {data_room} B = {} MiB",
        (u64::from(pool_mbufs) * u64::from(data_room)) / (1024 * 1024)
    );
    (pool_mbufs, data_room)
}

/// A port that has been configured and started, with the pool its receive queues draw from.
///
/// Held by the driver for the whole run. Workers borrow nothing from this; they are handed owned
/// queue handles taken out of it once, before any of them starts.
pub(crate) struct Port<'eal> {
    /// The started device. Kept so the port can be stopped and closed explicitly at shutdown.
    pub(crate) dev: Dev<'eal, Started>,
    /// The kernel `ifindex` of this port's netdev, which is what the pipeline knows it by.
    pub(crate) if_index: InterfaceIndex,
    /// Human-readable name for logs and status.
    ///
    /// This is the *configured* interface name, which is also the name of the tap that stands in
    /// for this port in the kernel. It is the key the control-plane bridge is addressed by.
    pub(crate) name: String,
    /// The MAC the PMD reports for this port.
    ///
    /// The port's tap has to be given this, or the peer resolves the wrong address for it and the
    /// frames it sends back come in as `MacNotForUs`.
    pub(crate) mac: Mac,
    /// The MTU the port settled on, which is not necessarily the one that was requested: it is
    /// clamped into the device's advertised range at configuration time.
    pub(crate) mtu: u16,
    /// Where injected control-plane frames are allocated from, and where received frames live.
    pub(crate) rx_pool: Pool<'eal>,
}

impl<'eal> Port<'eal> {
    /// Configure a device with one receive and one transmit queue per worker, and start it.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError`] if the device cannot be configured, queued or started, or if the
    /// PMD reports an `if_index` the kernel does not recognise.
    pub(crate) fn bring_up(
        eal: &'eal Eal,
        info: DevInfo<'eal>,
        name: String,
        num_workers: u16,
        mtu: Option<u16>,
    ) -> Result<Self, DriverError> {
        let index = info.index();

        let rss = rss_for(&info, &name, num_workers);

        // One queue per worker, on every port. That is what makes a queue exclusively owned: a
        // worker holds its rx and tx handles by value for the run, and no two workers ever touch
        // the same ring. `rte_eth_rx_burst` and `rte_eth_tx_burst` are not safe to call
        // concurrently on one queue, and this is the arrangement that makes that unrepresentable
        // rather than merely avoided.
        let config = DevConfig {
            num_rx_queues: num_workers,
            num_tx_queues: num_workers,
            num_hairpin_queues: 0,
            // Explicitly empty rather than `None`, which requests every offload the device
            // supports. That is not a sensible default: it enables LRO, which coalesces received
            // segments -- changing what the pipeline sees -- and costs a factor of 32 in receive
            // buffering, because the PMD must reserve enough 2 KiB mbufs per packet to return a
            // 64 KiB coalesced segment.
            //
            // `RSS_HASH` is the exception, and only when RSS is on (DPDK rejects the offload
            // otherwise): it makes the NIC report the hash it steered by in each mbuf, which is
            // the only way to see from software how well traffic is actually spreading.
            rx_offloads: Some(if rss.is_some() {
                RxOffload::RSS_HASH
            } else {
                RxOffload::NONE
            }),
            tx_offloads: Some(TxOffloadConfig::default()),
            // From the configuration when it named one. Left `None` the device takes DPDK's
            // default of 1500, which on a 9036 fabric stops every connection the moment slow
            // start reaches a full-size segment.
            mtu,
            rss,
        };

        let mut dev = config.apply(info).map_err(|e| {
            DriverError::PortSetup(format!("failed to configure port {index}: {e:?}"))
        })?;

        // The kernel ifindex comes from the PMD rather than from a sysfs walk. It is the link
        // between a DPDK port and the interface the routing tables, ACLs and VPC mappings name.
        // On a bifurcated driver (mlx5) the netdev stays with the kernel and this is populated;
        // on a port bound to vfio-pci there is no netdev and it is 0, which is not a usable
        // identity -- see the module docs.
        let raw_if_index = dev.info.if_index();
        let if_index = InterfaceIndex::try_new(raw_if_index).map_err(|e| {
            DriverError::PortSetup(format!(
                "port {index} ({name}) reports if_index {raw_if_index}, which is not a usable \
                 interface index: {e}. A port with no kernel netdev cannot currently be mapped \
                 onto the interface identity the pipeline uses."
            ))
        })?;

        let (pool_mbufs, data_room) = pool_shape(&dev, index, &name, num_workers);
        let rx_pool = eal
            .mem
            .new_pkt_pool(
                PoolConfig::new(
                    format!("rx_{index}"),
                    PoolParams {
                        size: POOL_MBUFS_PER_WORKER * u32::from(num_workers),
                        data_size: data_room,
                        ..Default::default()
                    },
                )
                .map_err(|e| {
                    DriverError::PortSetup(format!(
                        "invalid rx pool config for port {index}: {e:?}"
                    ))
                })?,
            )
            .map_err(|e| {
                DriverError::PortSetup(format!("failed to create rx pool for port {index}: {e:?}"))
            })?;

        for queue in 0..num_workers {
            dev.new_rx_queue(RxQueueConfig {
                dev: index,
                queue_index: RxQueueIndex(queue),
                num_descriptors: RX_DESCRIPTORS,
                socket_preference: socket::Preference::Dev(index),
                offloads: RxOffload::NONE,
                pool: rx_pool,
            })
            .map_err(|e| {
                DriverError::PortSetup(format!(
                    "failed to set up rx queue {queue} on port {index}: {e:?}"
                ))
            })?;

            dev.new_tx_queue(TxQueueConfig {
                queue_index: TxQueueIndex(queue),
                num_descriptors: TX_DESCRIPTORS,
                socket_preference: socket::Preference::Dev(index),
                config: (),
            })
            .map_err(|e| {
                DriverError::PortSetup(format!(
                    "failed to set up tx queue {queue} on port {index}: {e:?}"
                ))
            })?;
        }

        let dev = dev
            .start()
            .map_err(|e| DriverError::PortSetup(format!("failed to start port {index}: {e}")))?;

        // Both read after the port has started, because both are properties of the running device
        // rather than of the configuration: the MTU was clamped into the device's range and the MAC
        // came from the PMD. A port whose identity cannot be read is still usable for forwarding
        // but cannot have a working control plane, which is worth failing over rather than
        // discovering as an adjacency that never forms.
        let mac = dev.mac_address().map_err(|e| {
            DriverError::PortSetup(format!(
                "port {index} ({name}) is up but would not report its MAC address: {e:?}. Its tap \
                 could not then answer ARP for it."
            ))
        })?;
        let mtu = dev.mtu().map_err(|e| {
            DriverError::PortSetup(format!(
                "port {index} ({name}) is up but would not report its MTU: {e:?}"
            ))
        })?;

        report_link(&dev, index, &name, if_index, mac, mtu, num_workers);

        Ok(Port {
            dev,
            if_index,
            name,
            mac,
            mtu,
            rx_pool,
        })
    }

    /// Read the counters the device keeps for this port.
    ///
    /// These are the port's own totals, cumulative since it started, and they see what the
    /// dataplane cannot: a frame dropped for want of a receive descriptor
    /// ([`rx_missed`](PortCounters::rx_missed)) or for want of an mbuf
    /// ([`rx_no_mbuf`](PortCounters::rx_no_mbuf)) never reaches a worker and so appears in no
    /// pipeline counter at all. Without them an overloaded dataplane and an idle wire look alike.
    ///
    /// # Errors
    ///
    /// Returns the driver's error code; a PMD that implements no statistics reports `ENOTSUP`.
    pub(crate) fn counters(&self) -> Result<PortCounters, ErrorCode> {
        let stats = self.dev.stats()?;
        Ok(PortCounters {
            rx_packets: stats.ipackets,
            tx_packets: stats.opackets,
            rx_bytes: stats.ibytes,
            tx_bytes: stats.obytes,
            rx_missed: stats.imissed,
            rx_errors: stats.ierrors,
            tx_errors: stats.oerrors,
            rx_no_mbuf: stats.rx_nombuf,
        })
    }

    /// Stop and close the port, reporting the driver's error rather than leaving the backstop in
    /// `PortLifecycle`'s `Drop` to log it.
    pub(crate) fn shutdown(self) {
        let name = self.name.clone();
        match self.dev.stop() {
            Ok(stopped) => {
                if let Err(e) = stopped.close() {
                    error!("failed to close port {name}: {e}");
                }
            }
            Err(e) => error!("failed to stop port {name}: {e}"),
        }
    }
}

/// One port's queue pair, as handed to a single worker.
pub(crate) struct PortQueues<'p> {
    /// Which interface frames off this queue arrived on.
    pub(crate) if_index: InterfaceIndex,
    pub(crate) name: String,
    /// The MAC this port answers to, which is what decides whether a frame was addressed to us.
    pub(crate) mac: Mac,
    pub(crate) rx: RxQueue<'p>,
    pub(crate) tx: TxQueue<'p>,
    /// The pool injected control-plane frames are copied into.
    ///
    /// The port's receive pool, deliberately: a second pool per port would be memory reserved for
    /// a handful of frames a second. The cost is that a burst of injection competes with receive
    /// buffering, which at control-plane rates it will not do noticeably.
    pub(crate) pool: Pool<'p>,
    /// Where to hand a frame this port received which the kernel should see.
    ///
    /// `None` when there is no control-plane bridge, which is every configuration that did not ask
    /// for one -- there is then nowhere to punt to and local delivery is dropped as it always was.
    pub(crate) punt: Option<mpsc::Sender<Frame>>,
    /// Frames the kernel wants this port to transmit, on the one worker that drains them.
    pub(crate) inject: Option<mpsc::Receiver<Frame>>,
}

/// Deal every port's queues out to the workers: worker `i` gets queue `i` of each port.
///
/// Takes each device's queue set exactly once -- `take_queues` will not hand it out twice -- and
/// moves the handles out by value, so after this call the returned vectors are the only way to
/// drive any queue on any of these ports.
///
/// # Errors
///
/// Returns [`DriverError`] if a device's queue set was already taken, or if a queue that was
/// configured is missing from it.
pub(crate) fn deal_queues<'p>(
    ports: &'p [Port<'_>],
    num_workers: u16,
    bridge: Option<&mut DatapathEnds>,
) -> Result<Vec<Vec<PortQueues<'p>>>, DriverError> {
    let mut per_worker: Vec<Vec<PortQueues<'p>>> = (0..num_workers)
        .map(|_| Vec::with_capacity(ports.len()))
        .collect();

    let mut bridge = bridge;
    // Whether there is a bridge at all, as distinct from whether it knows about a given port. No
    // bridge is an ordinary configuration -- the kernel still has the netdevs and carries the
    // control plane itself. A bridge that is missing *this* port is a mismatch worth a warning.
    let bridged = bridge.is_some();
    for port in ports {
        // The injection queue goes to exactly one worker; the punt sender is cloned to all of them,
        // because any worker can receive a frame the kernel should see but only one may drain a
        // queue without reordering the session it carries.
        let (if_index, punt, mut inject) = if let Some(queues) =
            bridge.as_deref_mut().and_then(|b| b.take(&port.name))
        {
            // The tap's index, not the port's. Interface indices are per-namespace and these two
            // live in different ones; everything above the driver was built from the control
            // plane's view, so it speaks in tap indices. See `cpbridge::PortCpQueues::index`.
            (queues.index, Some(queues.punt), queues.inject)
        } else {
            if bridged {
                warn!(
                    "the control-plane bridge has no tap for port {}; frames the kernel should see \
                     will be dropped and nothing can be injected",
                    port.name
                );
            } else {
                debug!(
                    "no control-plane bridge, so port {} delivers nothing to the kernel",
                    port.name
                );
            }
            // No bridge, so nothing moved and the port's own index is the one the control plane
            // saw too.
            (port.if_index, None, None)
        };

        let mut queues = port.dev.take_queues().ok_or_else(|| {
            DriverError::PortSetup(format!(
                "queues for port {} were already taken; each device hands its set out once",
                port.name
            ))
        })?;

        for worker in 0..num_workers {
            let rx = queues.take_rx(RxQueueIndex(worker)).ok_or_else(|| {
                DriverError::PortSetup(format!(
                    "rx queue {worker} missing on port {} after start",
                    port.name
                ))
            })?;
            let tx = queues.take_tx(TxQueueIndex(worker)).ok_or_else(|| {
                DriverError::PortSetup(format!(
                    "tx queue {worker} missing on port {} after start",
                    port.name
                ))
            })?;
            per_worker[worker as usize].push(PortQueues {
                if_index,
                name: port.name.clone(),
                mac: port.mac,
                rx,
                tx,
                pool: port.rx_pool,
                punt: punt.clone(),
                // `take` rather than `clone`: worker 0 gets it, everybody else gets `None`.
                inject: inject.take(),
            });
        }
    }

    Ok(per_worker)
}
