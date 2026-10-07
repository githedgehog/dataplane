// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::*;
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
    config
        .apply(start_eal().dev().info(ring.index).unwrap())
        .unwrap()
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
