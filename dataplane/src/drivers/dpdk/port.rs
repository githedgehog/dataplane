// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bringing DPDK ports up, and the queue split that gives each worker its own.

use dpdk::dev::{Dev, DevConfig, PortClaim, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::mem::{Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use net::eth::mac::Mac;
use net::interface::InterfaceIndex;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::drivers::DriverError;
use crate::drivers::cpbridge::{DatapathEnds, Frame};

/// Receive descriptors per queue.
const RX_DESCRIPTORS: u16 = 1024;

/// Transmit descriptors per queue.
const TX_DESCRIPTORS: u16 = 1024;

/// Mbufs per worker, covering RX descriptors, pipeline processing, and pending TX.
const POOL_MBUFS_PER_WORKER: u32 = 4 * RX_DESCRIPTORS as u32;

/// A started port and its receive pool. Workers borrow its queue handles.
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
        port: PortClaim<'eal>,
        name: String,
        num_workers: u16,
    ) -> Result<Self, DriverError> {
        let index = port.info().index();

        // Each worker receives its own RX/TX queue pair on every port.
        let config = DevConfig {
            num_rx_queues: num_workers,
            num_tx_queues: num_workers,
            num_hairpin_queues: 0,
            // The pipeline handles checksums in software and requires uncoalesced packets.
            rx_offloads: RxOffload::NONE,
            tx_offloads: TxOffloadConfig::none(),
            mtu: None,
            // TODO: Enable symmetric RSS to distribute flows across workers.
            rss: None,
        };

        let mut dev = config
            .apply(port)
            .map_err(|e| DriverError::PortSetup(e.to_string()))?;

        // The pipeline uses kernel ifindices; ports without a netdev cannot be mapped yet.
        let raw_if_index = dev.info().if_index();
        let if_index = InterfaceIndex::try_new(raw_if_index).map_err(|e| {
            DriverError::PortSetup(format!(
                "port {index} ({name}) reports if_index {raw_if_index}, which is not a usable \
                 interface index: {e}. A port with no kernel netdev cannot currently be mapped \
                 onto the interface identity the pipeline uses."
            ))
        })?;

        let rx_pool = eal
            .mem
            .new_pkt_pool(
                PoolConfig::new(
                    format!("rx_{index}"),
                    PoolParams {
                        size: POOL_MBUFS_PER_WORKER * u32::from(num_workers),
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
                queue_index: RxQueueIndex(queue),
                num_descriptors: RX_DESCRIPTORS,
                socket_preference: socket::Preference::Dev(index),
                offloads: RxOffload::NONE,
                pool: rx_pool.clone(),
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

        info!(
            "DPDK port {index} ({name}) up: ifindex {if_index}, mac {mac}, mtu {mtu}, \
             {num_workers} rx/tx queue pair(s)"
        );

        Ok(Port {
            dev,
            if_index,
            name,
            mac: mac.into(),
            mtu,
            rx_pool,
        })
    }

    /// Stop and close the port, logging failures.
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

/// Give worker `i` queue pair `i` from every port.
///
/// # Errors
///
/// Returns an error if queues were already taken or a configured queue is missing.
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
                pool: port.rx_pool.clone(),
                punt: punt.clone(),
                // `take` rather than `clone`: worker 0 gets it, everybody else gets `None`.
                inject: inject.take(),
            });
        }
    }

    Ok(per_worker)
}
