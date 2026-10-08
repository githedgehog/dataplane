// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK queue abstractions.
pub mod hairpin;
pub mod rx;
pub mod tx;

#[cfg(test)]
mod store_tests;
#[cfg(test)]
mod tests;

use crate::queue::hairpin::{HairpinQueue, HairpinQueueId};
use crate::queue::rx::{RxQueue, RxQueueIndex};
use crate::queue::tx::{TxQueue, TxQueueIndex};
use alloc::boxed::Box;
use core::iter::repeat_with;
use core::mem;

/// What occupies one receive queue ID.
#[derive(Debug)]
enum RxSlot<'q> {
    /// Not configured, or already taken.
    Free,
    Plain(RxQueue<'q>),
    /// Stored here with its transmit slot reserved by [`TxSlot::Hairpin`].
    /// Boxed to keep the larger peering configuration out of every slot.
    Hairpin(Box<HairpinQueue<'q>>),
}

/// What occupies one transmit queue ID.
#[derive(Debug)]
enum TxSlot<'q> {
    /// Not configured, or already taken.
    Free,
    Plain(TxQueue<'q>),
    /// Reserved by the hairpin queue stored in the paired receive slot.
    Hairpin,
}

/// A device's queues, in one slot per DPDK queue ID.
///
/// Slots preserve queue IDs when queues are taken and enforce the configured queue counts.
/// `'q` borrows the EAL during setup and the device after [`Dev::take_queues`](crate::dev::Dev::take_queues).
#[derive(Debug)]
pub(crate) struct QueueStore<'q> {
    rx: Box<[RxSlot<'q>]>,
    tx: Box<[TxSlot<'q>]>,
}

impl<'q> QueueStore<'q> {
    /// Empty slots for a port configured with `rx` receive and `tx` transmit queue IDs.
    pub(crate) fn new(rx: u16, tx: u16) -> QueueStore<'q> {
        QueueStore {
            rx: repeat_with(|| RxSlot::Free).take(usize::from(rx)).collect(),
            tx: repeat_with(|| TxSlot::Free).take(usize::from(tx)).collect(),
        }
    }

    /// Whether receive queue `index` can be configured.
    ///
    /// # Errors
    ///
    /// [`OutOfRange`](rx::ConfigFailure::OutOfRange) past the configured count, or
    /// [`AlreadyConfigured`](rx::ConfigFailure::AlreadyConfigured) if a plain or hairpin queue
    /// holds it.
    pub(crate) fn check_rx(&self, index: RxQueueIndex) -> Result<(), rx::ConfigFailure> {
        match self.rx.get(usize::from(index.as_u16())) {
            None => Err(rx::ConfigFailure::OutOfRange {
                index,
                configured: Self::count(&self.rx),
            }),
            Some(RxSlot::Free) => Ok(()),
            Some(_) => Err(rx::ConfigFailure::AlreadyConfigured(index)),
        }
    }

    /// Whether transmit queue `index` can be configured.
    ///
    /// # Errors
    ///
    /// As [`check_rx`](Self::check_rx), for transmit queues.
    pub(crate) fn check_tx(&self, index: TxQueueIndex) -> Result<(), tx::ConfigFailure> {
        match self.tx.get(usize::from(index.as_u16())) {
            None => Err(tx::ConfigFailure::OutOfRange {
                index,
                configured: Self::count(&self.tx),
            }),
            Some(TxSlot::Free) => Ok(()),
            Some(_) => Err(tx::ConfigFailure::AlreadyConfigured(index)),
        }
    }

    /// The slot count, which `new` took from a `u16`.
    fn count<T>(slots: &[T]) -> u16 {
        u16::try_from(slots.len()).unwrap_or(u16::MAX)
    }

    /// Store a receive queue whose index passed [`check_rx`](Self::check_rx).
    pub(crate) fn insert_rx(&mut self, queue: RxQueue<'q>) {
        let slot = &mut self.rx[usize::from(queue.config.queue_index.as_u16())];
        debug_assert!(matches!(slot, RxSlot::Free), "checked by check_rx");
        *slot = RxSlot::Plain(queue);
    }

    /// Store a transmit queue whose index passed [`check_tx`](Self::check_tx).
    pub(crate) fn insert_tx(&mut self, queue: TxQueue<'q>) {
        let slot = &mut self.tx[usize::from(queue.config.queue_index.as_u16())];
        debug_assert!(matches!(slot, TxSlot::Free), "checked by check_tx");
        *slot = TxSlot::Plain(queue);
    }

    /// Store a hairpin queue whose halves passed both checks, and return its ID.
    pub(crate) fn insert_hairpin(&mut self, queue: HairpinQueue<'q>) -> HairpinQueueId {
        let id = queue.id();
        let tx = &mut self.tx[usize::from(queue.tx.config.queue_index.as_u16())];
        debug_assert!(matches!(tx, TxSlot::Free), "checked by check_tx");
        *tx = TxSlot::Hairpin;
        let rx = &mut self.rx[usize::from(id.rx().as_u16())];
        debug_assert!(matches!(rx, RxSlot::Free), "checked by check_rx");
        *rx = RxSlot::Hairpin(Box::new(queue));
        id
    }
}

/// Queues borrowed from a started device.
/// Each queue can be taken once by ID and assigned to a worker.
#[derive(Debug)]
pub struct Queues<'dev> {
    store: QueueStore<'dev>,
}

impl<'dev> Queues<'dev> {
    pub(crate) fn new(store: QueueStore<'dev>) -> Queues<'dev> {
        Queues { store }
    }

    /// Take the receive queue with this index.
    ///
    /// Returns `None` if it was never configured, is a hairpin queue, or has already been taken.
    pub fn take_rx(&mut self, index: RxQueueIndex) -> Option<RxQueue<'dev>> {
        let slot = self.store.rx.get_mut(usize::from(index.as_u16()))?;
        match mem::replace(slot, RxSlot::Free) {
            RxSlot::Plain(queue) => Some(queue),
            other => {
                *slot = other;
                None
            }
        }
    }

    /// Take the transmit queue with this index.
    ///
    /// Returns `None` if it was never configured, belongs to a hairpin queue, or has already been
    /// taken.
    pub fn take_tx(&mut self, index: TxQueueIndex) -> Option<TxQueue<'dev>> {
        let slot = self.store.tx.get_mut(usize::from(index.as_u16()))?;
        match mem::replace(slot, TxSlot::Free) {
            TxSlot::Plain(queue) => Some(queue),
            other => {
                *slot = other;
                None
            }
        }
    }

    /// Take a hairpin queue by the ID returned by [`Dev::new_hairpin_queue`](crate::dev::Dev::new_hairpin_queue).
    ///
    /// Returns `None` if it has already been taken. Its transmit ID stays reserved.
    pub fn take_hairpin(&mut self, id: HairpinQueueId) -> Option<HairpinQueue<'dev>> {
        let slot = self.store.rx.get_mut(usize::from(id.rx().as_u16()))?;
        match mem::replace(slot, RxSlot::Free) {
            RxSlot::Hairpin(queue) => Some(*queue),
            other => {
                *slot = other;
                None
            }
        }
    }

    /// The indices of the receive queues not yet taken, in order.
    pub fn rx_indices(&self) -> impl Iterator<Item = RxQueueIndex> + '_ {
        self.store.rx.iter().filter_map(|slot| match slot {
            RxSlot::Plain(queue) => Some(queue.config.queue_index),
            _ => None,
        })
    }

    /// The indices of the transmit queues not yet taken, in order.
    pub fn tx_indices(&self) -> impl Iterator<Item = TxQueueIndex> + '_ {
        self.store.tx.iter().filter_map(|slot| match slot {
            TxSlot::Plain(queue) => Some(queue.config.queue_index),
            _ => None,
        })
    }

    /// The IDs of the hairpin queues not yet taken, in order of receive index.
    pub fn hairpin_ids(&self) -> impl Iterator<Item = HairpinQueueId> + '_ {
        self.store.rx.iter().filter_map(|slot| match slot {
            RxSlot::Hairpin(queue) => Some(queue.id()),
            _ => None,
        })
    }
}
