// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A ring cable carries each queue's frames to the same queue at the other end, both ways.
//!
//! A test binary of its own, because the cable is made through an exclusively owned EAL.

use dataplane_dpdk::dev::{Dev, DevConfig, DevIndex, RxOffload, Started, TxOffloadConfig};
use dataplane_dpdk::eal::{self, Eal};
use dataplane_dpdk::mem::{MbufArray, Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;
use net::buffer::Append;

const QUEUES: u16 = 3;

fn start<'eal>(eal: &'eal Eal, index: DevIndex, pool: &Pool<'eal>) -> Dev<'eal, Started> {
    let claim = eal.claim(index).unwrap();
    let mut dev = DevConfig {
        num_rx_queues: QUEUES,
        num_tx_queues: QUEUES,
        num_hairpin_queues: 0,
        tx_offloads: TxOffloadConfig::none(),
        rx_offloads: RxOffload::NONE,
        mtu: None,
        rss: None,
    }
    .apply(claim)
    .unwrap();
    for queue in 0..QUEUES {
        dev.new_rx_queue(RxQueueConfig {
            queue_index: RxQueueIndex(queue),
            num_descriptors: 64,
            socket_preference: Preference::Dev(index),
            offloads: RxOffload::NONE,
            pool: pool.clone(),
        })
        .unwrap();
        dev.new_tx_queue(TxQueueConfig {
            queue_index: TxQueueIndex(queue),
            num_descriptors: 64,
            socket_preference: Preference::Dev(index),
            config: (),
        })
        .unwrap();
    }
    dev.start().unwrap()
}

/// `count` one-byte frames, numbered from `first`.
fn frames<'eal>(pool: &Pool<'eal>, first: u8, count: u8) -> MbufArray<'eal> {
    let mut frames = pool.alloc_bulk(usize::from(count)).unwrap();
    for (id, mbuf) in (first..).zip(frames.iter_mut()) {
        mbuf.append(1).unwrap()[0] = id;
    }
    frames
}

fn ids(frames: &MbufArray<'_>) -> Vec<u8> {
    frames.iter().map(|mbuf| mbuf.raw_data()[0]).collect()
}

#[test]
fn each_queue_reaches_the_same_queue_at_the_other_end_both_ways() {
    let mut eal = eal::init([
        "--no-huge",
        "--no-pci",
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--no-hpet",
        "--iova-mode=va",
        "--lcores",
        &eal::main_lcore_arg(),
    ]);
    let cable = eal.attach_ring_cable("cable", QUEUES, 64).unwrap();
    assert_eq!(cable.queues, QUEUES);
    assert!(
        eal.attach_ring_cable("cable", QUEUES, 64).is_err(),
        "a second cable of the same name should be refused, not share the first one's rings"
    );

    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new(
                "cable_frames",
                PoolParams {
                    size: 1023,
                    ..Default::default()
                },
            )
            .unwrap(),
        )
        .unwrap();
    let a = start(&eal, cable.a, &pool);
    let b = start(&eal, cable.b, &pool);
    let mut a_queues = a.take_queues().unwrap();
    let mut b_queues = b.take_queues().unwrap();
    let mut a_rx: Vec<_> = (0..QUEUES)
        .map(|q| a_queues.take_rx(RxQueueIndex(q)).unwrap())
        .collect();
    let mut a_tx: Vec<_> = (0..QUEUES)
        .map(|q| a_queues.take_tx(TxQueueIndex(q)).unwrap())
        .collect();
    let mut b_rx: Vec<_> = (0..QUEUES)
        .map(|q| b_queues.take_rx(RxQueueIndex(q)).unwrap())
        .collect();
    let mut b_tx: Vec<_> = (0..QUEUES)
        .map(|q| b_queues.take_tx(TxQueueIndex(q)).unwrap())
        .collect();

    for (q, first) in (0..usize::from(QUEUES)).zip((0u8..).step_by(10)) {
        assert!(a_tx[q].transmit(frames(&pool, first, 4)).is_empty());
        assert!(b_tx[q].transmit(frames(&pool, first + 100, 3)).is_empty());
        for other in (0..usize::from(QUEUES)).filter(|&other| other != q) {
            assert!(
                b_rx[other].receive().is_empty(),
                "queue {q} leaked to {other}"
            );
            assert!(
                a_rx[other].receive().is_empty(),
                "queue {q} leaked to {other}"
            );
        }
        assert_eq!(
            ids(&b_rx[q].receive()),
            (first..first + 4).collect::<Vec<_>>()
        );
        assert_eq!(
            ids(&a_rx[q].receive()),
            (first + 100..first + 103).collect::<Vec<_>>()
        );
    }
}
