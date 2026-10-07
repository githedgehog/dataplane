// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The queue store's slot table, driven with synthetic queues that never reach a driver.

use super::*;
use crate::dev::{DevIndex, RxOffload};
use crate::queue::hairpin::HairpinPeering;
use crate::queue::rx::RxQueueConfig;
use crate::queue::tx::TxQueueConfig;
use crate::socket::{Preference, SocketId};
use crate::test_support::packet_pool;
use core::marker::PhantomData;

const PORT: DevIndex = DevIndex(0);

fn rx(index: u16) -> RxQueue<'static> {
    RxQueue {
        config: RxQueueConfig {
            dev: PORT,
            queue_index: RxQueueIndex(index),
            num_descriptors: 8,
            socket_preference: Preference::Id(SocketId::ANY),
            offloads: RxOffload::NONE,
            pool: packet_pool(7),
        },
        dev: PORT,
        _dev: PhantomData,
    }
}

fn tx(index: u16) -> TxQueue<'static> {
    TxQueue {
        config: TxQueueConfig {
            queue_index: TxQueueIndex(index),
            num_descriptors: 8,
            socket_preference: Preference::Id(SocketId::ANY),
            config: (),
        },
        dev: PORT,
        _dev: PhantomData,
    }
}

fn hairpin(rx_index: u16, tx_index: u16) -> HairpinQueue<'static> {
    HairpinQueue {
        rx: rx(rx_index),
        tx: tx(tx_index),
        peering: HairpinPeering {
            rx: dpdk_sys::rte_eth_hairpin_conf::default(),
            tx: dpdk_sys::rte_eth_hairpin_conf::default(),
        },
    }
}

/// Three receive and three transmit IDs: plain queues at 0 and 2, a hairpin at 1.
fn populated() -> (QueueStore<'static>, HairpinQueueId) {
    let mut store = QueueStore::new(3, 3);
    store.insert_rx(rx(0));
    store.insert_rx(rx(2));
    store.insert_tx(tx(0));
    store.insert_tx(tx(2));
    let id = store.insert_hairpin(hairpin(1, 1));
    (store, id)
}

#[test]
fn taking_a_queue_leaves_every_other_id_alone() {
    let (store, id) = populated();
    let mut queues = Queues::new(store);
    assert_eq!(id.rx(), RxQueueIndex(1));

    let first = queues.take_rx(RxQueueIndex(0)).expect("rx 0");
    assert_eq!(first.config.queue_index, RxQueueIndex(0));
    assert_eq!(queues.rx_indices().collect::<Vec<_>>(), [RxQueueIndex(2)]);
    let last = queues.take_rx(RxQueueIndex(2)).expect("rx 2 keeps its ID");
    assert_eq!(last.config.queue_index, RxQueueIndex(2));
    assert!(queues.take_rx(RxQueueIndex(0)).is_none(), "taken once");

    assert!(
        queues.take_rx(RxQueueIndex(1)).is_none(),
        "a hairpin is not a plain receive queue"
    );
    assert!(
        queues.take_tx(TxQueueIndex(1)).is_none(),
        "a hairpin's transmit ID is reserved"
    );
    assert_eq!(queues.hairpin_ids().collect::<Vec<_>>(), [id]);
    let pair = queues.take_hairpin(id).expect("hairpin");
    assert_eq!(pair.id(), id);
    assert!(queues.take_hairpin(id).is_none(), "taken once");
    assert!(
        queues.take_tx(TxQueueIndex(1)).is_none(),
        "still reserved after the hairpin is taken"
    );

    assert_eq!(
        queues.tx_indices().collect::<Vec<_>>(),
        [TxQueueIndex(0), TxQueueIndex(2)]
    );
    assert!(queues.take_tx(TxQueueIndex(2)).is_some());
    assert!(queues.take_tx(TxQueueIndex(0)).is_some());
    assert!(queues.take_rx(RxQueueIndex(3)).is_none(), "out of range");
}

#[test]
fn an_id_is_configured_at_most_once_and_only_in_range() {
    let (store, _) = populated();
    for index in 0..3 {
        assert!(matches!(
            store.check_rx(RxQueueIndex(index)),
            Err(rx::ConfigFailure::AlreadyConfigured(RxQueueIndex(i))) if i == index
        ));
        assert!(matches!(
            store.check_tx(TxQueueIndex(index)),
            Err(tx::ConfigFailure::AlreadyConfigured(TxQueueIndex(i))) if i == index
        ));
    }
    assert!(matches!(
        store.check_rx(RxQueueIndex(3)),
        Err(rx::ConfigFailure::OutOfRange {
            index: RxQueueIndex(3),
            configured: 3
        })
    ));
    assert!(matches!(
        store.check_tx(TxQueueIndex(u16::MAX)),
        Err(tx::ConfigFailure::OutOfRange {
            index: TxQueueIndex(u16::MAX),
            configured: 3
        })
    ));

    let empty = QueueStore::new(1, 1);
    assert!(empty.check_rx(RxQueueIndex(0)).is_ok());
    assert!(empty.check_tx(TxQueueIndex(0)).is_ok());
}
