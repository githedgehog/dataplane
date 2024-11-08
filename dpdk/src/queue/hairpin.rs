// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Hairpin queue configuration and management.
use super::{rx, tx};
use crate::dev::{Dev, DevInfo};
use crate::queue::rx::RxQueue;
use crate::queue::tx::{TxQueue};
use dpdk_sys::*;
use tracing::debug;
use errno::ErrorCode;

/// A stopped DPDK hairpin queue.
#[derive(Debug)]
pub struct HairpinQueue {
    pub(crate) rx: RxQueue,
    pub(crate) tx: TxQueue,
    pub(crate) peering: HairpinPeering,
}

#[derive(Debug)]
pub(crate) struct HairpinPeering {
    pub(crate) rx: rte_eth_hairpin_conf,
    pub(crate) tx: rte_eth_hairpin_conf,
}

impl HairpinPeering {
    /// Define a new hairpin configuration.
    fn define(dev: &DevInfo, rx_queue: &RxQueue, tx_queue: &TxQueue) -> Self {
        let mut rx = rte_eth_hairpin_conf::default();
        rx.set_peer_count(1);
        let mut tx = rte_eth_hairpin_conf::default();
        tx.set_peer_count(1);
        rx.peers[0].port = dev.index.as_u16();
        rx.peers[0].queue = tx_queue.config.queue_index.as_u16();
        tx.peers[0].port = dev.index.as_u16();
        tx.peers[0].queue = rx_queue.config.queue_index.as_u16();
        HairpinPeering { rx, tx }
    }
}

/// An error occurred while configuring a hairpin queue.
#[derive(Debug)]
pub enum HairpinConfigFailure {
    /// An error occurred while configuring the rx queue portion of the hairpin queue.
    RxQueueCreationFailed(rx::ConfigFailure),
    /// An error occurred while configuring the tx queue portion of the hairpin queue.
    TxQueueCreationFailed(tx::ConfigFailure),
    /// An error occurred while configuring the hairpin queue.
    CreationFailed(ErrorCode),
}

impl HairpinQueue {
    /// Create and configure a new hairpin queue.
    ///
    /// This method is crate internal.
    /// The library end user should call this by way of the
    /// [`dev::Dev::configure_hairpin_queue`] method.
    ///
    /// This design ensures that the hairpin queue is correctly tracked in the list of queues
    /// associated with the device.
    pub(crate) fn new(
        dev: &Dev,
        rx: RxQueue,
        tx: TxQueue,
    ) -> Result<Self, HairpinConfigFailure> {
        let peering = HairpinPeering::define(&dev.info, &rx, &tx);
        // configure the rx queue

        let ret = unsafe {
            rte_eth_rx_hairpin_queue_setup(
                dev.info.index.as_u16(),
                rx.config.queue_index.as_u16(),
                0,
                &peering.rx,
            )
        };

        if ret < 0 {
            return Err(HairpinConfigFailure::CreationFailed(
                ErrorCode::parse_i32(ret)
            ));
        }
        debug!("RX hairpin queue configured");

        let ret = unsafe {
            rte_eth_tx_hairpin_queue_setup(
                dev.info.index.as_u16(),
                tx.config.queue_index.as_u16(),
                0,
                &peering.tx,
            )
        };

        if ret < 0 {
            return Err(HairpinConfigFailure::CreationFailed(
                ErrorCode::parse_i32(ret)
            ));
        }
        debug!("TX hairpin queue configured");

        Ok(HairpinQueue { rx, tx, peering })
    }

    pub fn start(self) -> HairpinQueue {
        let rx = match self.rx.start() {
            Ok(rx) => rx,
            Err(_) => todo!(),
        };
        let tx = match self.tx.start() {
            Ok(tx) => tx,
            Err(_) => todo!(),
        };
        HairpinQueue { rx, tx, peering: self.peering }
    }
}

impl HairpinQueue {
    /// Stop the hairpin queue.
    pub fn stop(self) -> HairpinQueue {
        let rx = match self.rx.stop() {
            Ok(rx) => rx,
            Err(_) => todo!(),
        };
        let tx = match self.tx.stop() {
            Ok(tx) => tx,
            Err(_) => todo!(),
        };
        HairpinQueue {
            rx,
            tx,
            peering: self.peering,
        }
    }
}
