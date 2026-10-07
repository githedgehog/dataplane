// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::*;
use crate::queue::rx::RxQueueIndex;
use crate::queue::tx::TxQueueIndex;
use crate::socket::Preference;
use crate::test_support::{RingPort, packet_pool, start_eal};

fn configured(ring: &RingPort) -> Dev<'static> {
    let config = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: TxOffloadConfig::none(),
        rx_offloads: RxOffload::NONE,
        mtu: None,
        rss: None,
    };
    let owner = Box::leak(Box::new(Ownership::new().unwrap()));
    let claim = PortClaim::new(owner, start_eal().dev().info(ring.index).unwrap()).unwrap();
    config.apply(claim).unwrap()
}

fn rx_config(ring: &RingPort) -> RxQueueConfig<'static> {
    RxQueueConfig {
        dev: ring.index,
        queue_index: RxQueueIndex(0),
        num_descriptors: 128,
        socket_preference: Preference::Id(SocketId::ANY),
        offloads: RxOffload::NONE,
        pool: packet_pool(127),
    }
}

fn tx_config() -> TxQueueConfig {
    TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 128,
        socket_preference: Preference::Id(SocketId::ANY),
        config: (),
    }
}

/// Two handles to one queue would let two threads poll it at once.
#[test]
fn a_queue_index_is_configured_at_most_once() {
    let ring = RingPort::new();
    let mut dev = configured(&ring);

    dev.new_rx_queue(rx_config(&ring)).unwrap();
    assert!(matches!(
        dev.new_rx_queue(rx_config(&ring)),
        Err(rx::ConfigFailure::AlreadyConfigured(RxQueueIndex(0)))
    ));

    dev.new_tx_queue(tx_config()).unwrap();
    assert!(matches!(
        dev.new_tx_queue(tx_config()),
        Err(tx::ConfigFailure::AlreadyConfigured(TxQueueIndex(0)))
    ));
}

#[test]
fn a_queue_index_must_be_within_the_configured_count() {
    let ring = RingPort::new();
    let mut dev = configured(&ring);

    let mut config = rx_config(&ring);
    config.queue_index = RxQueueIndex(1);
    assert!(matches!(
        dev.new_rx_queue(config),
        Err(rx::ConfigFailure::OutOfRange {
            index: RxQueueIndex(1),
            configured: 1
        })
    ));
    let mut config = tx_config();
    config.queue_index = TxQueueIndex(1);
    assert!(matches!(
        dev.new_tx_queue(config),
        Err(tx::ConfigFailure::OutOfRange {
            index: TxQueueIndex(1),
            configured: 1
        })
    ));
}

#[test]
fn a_started_device_hands_its_queues_out_once() {
    let ring = RingPort::new();
    let mut dev = configured(&ring);
    dev.new_rx_queue(rx_config(&ring)).unwrap();
    dev.new_tx_queue(tx_config()).unwrap();
    let dev = dev.start().unwrap();

    let mut queues = dev.take_queues().expect("first take");
    assert!(dev.take_queues().is_none());
    assert_eq!(queues.rx_indices().collect::<Vec<_>>(), [RxQueueIndex(0)]);
    assert_eq!(queues.tx_indices().collect::<Vec<_>>(), [TxQueueIndex(0)]);
    assert!(queues.take_rx(RxQueueIndex(0)).is_some());
    assert!(queues.take_rx(RxQueueIndex(0)).is_none());
    assert!(queues.take_tx(TxQueueIndex(0)).is_some());
    assert!(queues.take_tx(TxQueueIndex(0)).is_none());
}
