// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK queue abstractions.
pub mod hairpin;
pub mod rx;
pub mod tx;

#[cfg(test)]
mod tests;

use crate::queue::hairpin::HairpinQueue;
use crate::queue::rx::{RxQueue, RxQueueIndex};
use crate::queue::tx::{TxQueue, TxQueueIndex};
use alloc::vec::Vec;

/// The queues configured on a device.
#[derive(Debug, Default)]
pub(crate) struct QueueStore<'eal> {
    pub(crate) rx: Vec<RxQueue<'eal>>,
    pub(crate) tx: Vec<TxQueue>,
    pub(crate) hairpin: Vec<HairpinQueue<'eal>>,
}

impl QueueStore<'_> {
    /// Whether a receive queue, plain or hairpin, already uses `index`.
    pub(crate) fn has_rx(&self, index: RxQueueIndex) -> bool {
        self.rx.iter().any(|q| q.config.queue_index == index)
            || self
                .hairpin
                .iter()
                .any(|q| q.rx.config.queue_index == index)
    }

    /// Whether a transmit queue, plain or hairpin, already uses `index`.
    pub(crate) fn has_tx(&self, index: TxQueueIndex) -> bool {
        self.tx.iter().any(|q| q.config.queue_index == index)
            || self
                .hairpin
                .iter()
                .any(|q| q.tx.config.queue_index == index)
    }
}
