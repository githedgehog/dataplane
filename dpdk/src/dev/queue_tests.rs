// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::*;
use crate::queue::rx::RxQueueIndex;
use crate::queue::tx::TxQueueIndex;
use crate::socket::Preference;
use crate::test_support::{RingPort, packet_pool, start_eal};

/// One owner for every device these tests configure; a static rather than a leak so
/// LeakSanitizer can still reach it.
static OWNER: concurrency::process_global::LazyLock<Ownership> =
    concurrency::process_global::LazyLock::new(|| Ownership::new().unwrap());

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
    let claim = PortClaim::new(&OWNER, start_eal().dev().info(ring.index).unwrap()).unwrap();
    config.apply(claim).unwrap()
}

fn rx_config() -> RxQueueConfig<'static> {
    RxQueueConfig {
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

    dev.new_rx_queue(rx_config()).unwrap();
    assert!(matches!(
        dev.new_rx_queue(rx_config()),
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

    let mut config = rx_config();
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
    dev.new_rx_queue(rx_config()).unwrap();
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

/// Configured again, a device forgets its queues, which are set up afresh before it starts.
#[test]
fn a_reconfigured_device_sets_its_queues_up_again() {
    let ring = RingPort::new();
    let mut dev = configured(&ring);
    dev.new_rx_queue(rx_config()).unwrap();
    dev.new_tx_queue(tx_config()).unwrap();

    let again = dev.config().clone();
    let mut dev = dev.reconfigure(&again).unwrap();
    dev.new_rx_queue(rx_config()).unwrap();
    dev.new_tx_queue(tx_config()).unwrap();
    let dev = dev.start().unwrap();
    let queues = dev.take_queues().expect("queues");
    assert_eq!(queues.rx_indices().collect::<Vec<_>>(), [RxQueueIndex(0)]);
}

/// Even a Rust-side refusal requires configuration again before queue setup or start.
#[test]
fn a_refused_reconfiguration_requires_configuration_again() {
    let ring = RingPort::new();
    let mut dev = configured(&ring);
    dev.new_rx_queue(rx_config()).unwrap();

    let too_many = DevConfig {
        num_rx_queues: u16::MAX,
        ..dev.config().clone()
    };
    let failure = dev.reconfigure(&too_many).unwrap_err();
    assert!(matches!(
        failure.error,
        DevConfigError::TooManyQueues { .. }
    ));
    let dev = failure.dev;
    assert_eq!(dev.config().num_rx_queues, 1);
    assert!(matches!(dev.lifecycle.stage, Stage::Unconfigured));
    assert!(dev.queues.lock().is_none());
    let previous = dev.config().clone();
    let mut dev = dev.reconfigure(&previous).unwrap();
    dev.new_rx_queue(rx_config()).unwrap();
    dev.new_tx_queue(tx_config()).unwrap();
    dev.start().unwrap();
}

/// DPDK clears dev_configured on entry, even if the request fails before queue allocation. A
/// failed driver configuration can also release the queues; neither failure leaves a Configured
/// device. Exercise the native error path as well as the Rust-side validation above.
#[test]
fn a_native_reconfiguration_failure_can_be_retried_or_closed() {
    for retry in [false, true] {
        let ring = RingPort::new();
        let mut dev = configured(&ring);
        dev.new_rx_queue(rx_config()).unwrap();
        dev.new_tx_queue(tx_config()).unwrap();
        let previous = dev.config().clone();

        // Make the cached capability snapshot admit a request the real ring port rejects, so
        // this failure comes from rte_eth_dev_configure rather than the Rust queue-count check.
        let max_rx = dev.info.max_rx_queues();
        let too_many = DevConfig {
            num_rx_queues: max_rx + 1,
            ..previous.clone()
        };
        dev.info.inner.max_rx_queues = too_many.num_rx_queues;
        let failure = dev.reconfigure(&too_many).unwrap_err();
        assert!(matches!(
            failure.error,
            DevConfigError::DriverSpecificError { .. }
        ));
        let mut dev = failure.dev;
        dev.info.inner.max_rx_queues = max_rx;
        assert_eq!(dev.config(), &previous);
        assert!(matches!(dev.lifecycle.stage, Stage::Unconfigured));
        assert!(dev.queues.lock().is_none());

        if retry {
            // A second failure must still leave retry available.
            let dev = dev.reconfigure(&too_many).unwrap_err().dev;
            let mut dev = dev.reconfigure(&previous).unwrap();
            dev.new_rx_queue(rx_config()).unwrap();
            dev.new_tx_queue(tx_config()).unwrap();
            let dev = dev.start().unwrap();
            let mut queues = dev.take_queues().unwrap();
            let mut rx = queues.take_rx(RxQueueIndex(0)).unwrap();
            let mut tx = queues.take_tx(TxQueueIndex(0)).unwrap();
            assert!(
                tx.transmit(packet_pool(127).alloc_bulk(1).unwrap())
                    .is_empty()
            );
            assert_eq!(rx.receive().len(), 1);
        } else {
            dev.close().unwrap();
        }
    }
}
