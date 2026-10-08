// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bringing DPDK ports up, and the queue split that gives each worker its own.

use dpdk::dev::{Dev, DevConfig, PortClaim, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::mem::{Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use net::interface::InterfaceIndex;
use tracing::{error, info};

use crate::drivers::DriverError;

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
    pub(crate) name: String,
    /// Kept only so it is visible in diagnostics; the mempool itself belongs to the EAL.
    #[allow(dead_code)]
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

        info!(
            "DPDK port {index} ({name}) up: ifindex {if_index}, {num_workers} rx/tx queue pair(s)"
        );

        Ok(Port {
            dev,
            if_index,
            name,
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
    pub(crate) rx: RxQueue<'p>,
    pub(crate) tx: TxQueue<'p>,
}

/// Give worker `i` queue pair `i` from every port.
///
/// # Errors
///
/// Returns an error if queues were already taken or a configured queue is missing.
pub(crate) fn deal_queues<'p>(
    ports: &'p [Port<'_>],
    num_workers: u16,
) -> Result<Vec<Vec<PortQueues<'p>>>, DriverError> {
    let mut per_worker: Vec<Vec<PortQueues<'p>>> = (0..num_workers)
        .map(|_| Vec::with_capacity(ports.len()))
        .collect();

    for port in ports {
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
                if_index: port.if_index,
                name: port.name.clone(),
                rx,
                tx,
            });
        }
    }

    Ok(per_worker)
}
