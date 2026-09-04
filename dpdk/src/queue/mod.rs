// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK queue abstractions.
pub mod hairpin;
pub mod rx;
pub mod tx;

use crate::queue::hairpin::HairpinQueue;
use crate::queue::rx::{RxQueue, RxQueueIndex};
use crate::queue::tx::{TxQueue, TxQueueIndex};
use alloc::vec::Vec;

/// A device's queues, before they have been bound to the device's lifetime.
///
/// Produced by [`Dev::<Stopped>::start`](crate::dev::Dev::start) and consumed by
/// [`Dev::<Started>::take_queues`](crate::dev::Dev::take_queues); callers do not construct one.
#[derive(Debug, Default)]
pub(crate) struct QueueStore<'eal> {
    pub(crate) rx: Vec<RxQueue<'eal>>,
    pub(crate) tx: Vec<TxQueue<'eal>>,
    pub(crate) hairpin: Vec<HairpinQueue<'eal>>,
}

/// The set of a device's queues, for distribution to workers.
///
/// Obtained once from [`Dev::<Started>::take_queues`](crate::dev::Dev::take_queues). Each queue is
/// removed from the set by value, so a given queue can be handed to exactly one worker -- which is
/// what makes DPDK's one-queue-one-thread rule a property of the type system rather than a
/// convention.
///
/// Every handle carries the device's lifetime, so no queue can be used after the device is
/// stopped.
///
/// A future offload queue kind slots in here as another field plus another `take_*`; nothing else
/// about the shape needs to change.
#[derive(Debug)]
pub struct Queues<'dev> {
    rx: Vec<RxQueue<'dev>>,
    tx: Vec<TxQueue<'dev>>,
    hairpin: Vec<HairpinQueue<'dev>>,
}

impl<'dev> Queues<'dev> {
    pub(crate) fn new(
        rx: Vec<RxQueue<'dev>>,
        tx: Vec<TxQueue<'dev>>,
        hairpin: Vec<HairpinQueue<'dev>>,
    ) -> Queues<'dev> {
        Queues { rx, tx, hairpin }
    }

    /// Remove the receive queue with this index from the set and hand it over.
    ///
    /// Returns `None` if the queue was never configured, or has already been taken.
    pub fn take_rx(&mut self, index: RxQueueIndex) -> Option<RxQueue<'dev>> {
        let at = self.rx.iter().position(|q| q.config.queue_index == index)?;
        Some(self.rx.remove(at))
    }

    /// Remove the transmit queue with this index from the set and hand it over.
    ///
    /// Returns `None` if the queue was never configured, or has already been taken.
    pub fn take_tx(&mut self, index: TxQueueIndex) -> Option<TxQueue<'dev>> {
        let at = self.tx.iter().position(|q| q.config.queue_index == index)?;
        Some(self.tx.remove(at))
    }

    /// Remove the hairpin queue at `position` (in configuration order) and hand it over.
    pub fn take_hairpin(&mut self, position: usize) -> Option<HairpinQueue<'dev>> {
        (position < self.hairpin.len()).then(|| self.hairpin.remove(position))
    }

    /// The indices of the receive queues still in the set.
    pub fn rx_indices(&self) -> impl Iterator<Item = RxQueueIndex> + '_ {
        self.rx.iter().map(|q| q.config.queue_index)
    }

    /// The indices of the transmit queues still in the set.
    pub fn tx_indices(&self) -> impl Iterator<Item = TxQueueIndex> + '_ {
        self.tx.iter().map(|q| q.config.queue_index)
    }
}
