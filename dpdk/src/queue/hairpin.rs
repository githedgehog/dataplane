// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Hairpin queue configuration and management.
use super::{rx, tx};
use crate::dev::{Dev, DevInfo};
use crate::queue::rx::RxQueue;
use crate::queue::tx::TxQueue;
use errno::ErrorCode;
use tracing::debug;

/// A stopped DPDK hairpin queue.
///
/// Owns the rx and tx halves of the pairing, and carries the same device brand they do.
#[allow(unused)]
#[derive(Debug)]
pub struct HairpinQueue<'dev> {
    pub(crate) rx: RxQueue<'dev>,
    pub(crate) tx: TxQueue<'dev>,
    pub(crate) peering: HairpinPeering,
}

#[derive(Debug)]
pub(crate) struct HairpinPeering {
    pub(crate) rx: dpdk_sys::rte_eth_hairpin_conf,
    pub(crate) tx: dpdk_sys::rte_eth_hairpin_conf,
}

impl HairpinPeering {
    /// Define a new hairpin configuration.
    fn define(dev: &DevInfo, rx_queue: &RxQueue, tx_queue: &TxQueue) -> Self {
        let mut rx = dpdk_sys::rte_eth_hairpin_conf::default();
        rx.set_peer_count(1);
        let mut tx = dpdk_sys::rte_eth_hairpin_conf::default();
        tx.set_peer_count(1);
        rx.peers[0].port = dev.index.as_u16();
        rx.peers[0].queue = tx_queue.config.queue_index.as_u16();
        tx.peers[0].port = dev.index.as_u16();
        tx.peers[0].queue = rx_queue.config.queue_index.as_u16();
        HairpinPeering { rx, tx }
    }
}

/// A hairpin queue could not be started.
#[derive(Debug, thiserror::Error)]
pub enum HairpinStartFailure {
    /// The receive half could not be started.
    #[error("could not start the receive half of the hairpin queue: {0}")]
    Rx(#[source] rx::RxQueueStartError),
    /// The transmit half could not be started.
    #[error("could not start the transmit half of the hairpin queue: {0}")]
    Tx(#[source] tx::TxQueueStartError),
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

impl<'dev> HairpinQueue<'dev> {
    /// Create and configure a new hairpin queue.
    ///
    /// This method is crate internal.
    /// The library end user should call this by way of the
    /// [`dev::Dev::configure_hairpin_queue`] method.
    ///
    /// This design ensures that the hairpin queue is correctly tracked in the list of queues
    /// associated with the device.
    #[tracing::instrument(level = "info", ret)]
    pub(crate) fn new(
        dev: &Dev,
        rx: RxQueue<'dev>,
        tx: TxQueue<'dev>,
    ) -> Result<Self, HairpinConfigFailure> {
        let peering = HairpinPeering::define(&dev.info, &rx, &tx);
        // configure the rx queue

        let ret = unsafe {
            dpdk_sys::rte_eth_rx_hairpin_queue_setup(
                dev.info.index.as_u16(),
                rx.config.queue_index.as_u16(),
                0,
                &peering.rx,
            )
        };

        if ret < 0 {
            return Err(HairpinConfigFailure::CreationFailed(ErrorCode::parse_i32(
                ret,
            )));
        }
        debug!("RX hairpin queue configured");

        let ret = unsafe {
            dpdk_sys::rte_eth_tx_hairpin_queue_setup(
                dev.info.index.as_u16(),
                tx.config.queue_index.as_u16(),
                0,
                &peering.tx,
            )
        };

        if ret < 0 {
            return Err(HairpinConfigFailure::CreationFailed(ErrorCode::parse_i32(
                ret,
            )));
        }
        debug!("TX hairpin queue configured");

        Ok(HairpinQueue { rx, tx, peering })
    }

    /// Start both halves of the hairpin pairing.
    ///
    /// The transmit half is started first: the receive half peers with it, and starting a receive
    /// queue whose peer is not yet running is rejected by some PMDs.
    ///
    /// # Errors
    ///
    /// Returns [`HairpinStartFailure`] identifying which half failed and why. If the transmit half
    /// starts and the receive half then fails, the transmit half is left running -- stopping the
    /// device is the way to unwind that.
    pub fn start(&mut self) -> Result<(), HairpinStartFailure> {
        self.tx.start().map_err(HairpinStartFailure::Tx)?;
        self.rx.start().map_err(HairpinStartFailure::Rx)?;
        Ok(())
    }
}
