// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(
    clippy::disallowed_types,
    reason = "the DPDK port registry is process-wide"
)]

use super::rx::{RxQueue, RxQueueConfig};
use super::tx::{TxQueue, TxQueueConfig};
use crate::dev::DevIndex;
use crate::mem::{MBUF_BURST, MbufArray, Pool};
use crate::socket::{Preference, SocketId};
use crate::test_support::{available, packet_pool};
use concurrency::process_global::{Mutex, MutexGuard};
use net::buffer::Append;
use std::ffi::{CStr, CString, c_int};
use std::marker::PhantomData;
use std::ptr::NonNull;

// The ring PMD is used only by these tests. Signature from rte_eth_ring.h.
#[link(name = "rte_net_ring", kind = "static")]
unsafe extern "C" {
    fn rte_eth_from_ring(ring: *mut dpdk_sys::rte_ring) -> c_int;
}

struct Loopback {
    rx: RxQueue<'static>,
    tx: TxQueue<'static>,
    ring: NonNull<dpdk_sys::rte_ring>,
    name: CString,
    _guard: MutexGuard<'static, ()>,
}

impl Loopback {
    fn new(ring_size: u32) -> Self {
        // Port creation and teardown are not thread-safe in DPDK.
        static PORT: Mutex<()> = Mutex::new(());
        let guard = PORT.lock().unwrap();
        let pool = packet_pool(127);
        // SAFETY: EAL is initialized; the ring outlives the port using it.
        let ring = NonNull::new(unsafe {
            dpdk_sys::rte_ring_create(c"batch_loopback".as_ptr(), ring_size, -1, 0)
        })
        .expect("create loopback ring");
        let port = unsafe { rte_eth_from_ring(ring.as_ptr()) };
        assert!(port >= 0, "create ring port: {port}");
        let dev = DevIndex(port as u16);
        let mut name = [0; dpdk_sys::RTE_ETH_NAME_MAX_LEN as usize];
        // SAFETY: this test exclusively owns the port, ring, and pool.
        unsafe {
            assert_eq!(
                dpdk_sys::rte_eth_dev_get_name_by_port(dev.0, name.as_mut_ptr()),
                0
            );
            assert_eq!(
                dpdk_sys::rte_eth_dev_configure(dev.0, 1, 1, &Default::default()),
                0
            );
            assert_eq!(
                dpdk_sys::rte_eth_rx_queue_setup(
                    dev.0,
                    0,
                    128,
                    SocketId::ANY.as_c_uint(),
                    &Default::default(),
                    pool.as_mut_ptr(),
                ),
                0
            );
            assert_eq!(
                dpdk_sys::rte_eth_tx_queue_setup(
                    dev.0,
                    0,
                    128,
                    SocketId::ANY.as_c_uint(),
                    &Default::default(),
                ),
                0
            );
            assert_eq!(dpdk_sys::rte_eth_dev_start(dev.0), 0);
        }
        Self {
            rx: RxQueue {
                config: RxQueueConfig {
                    dev,
                    queue_index: 0.into(),
                    num_descriptors: 128,
                    socket_preference: Preference::Id(SocketId::ANY),
                    offloads: 0.into(),
                    pool,
                },
                dev,
                _dev: PhantomData,
            },
            tx: TxQueue {
                config: TxQueueConfig {
                    queue_index: 0.into(),
                    num_descriptors: 128,
                    socket_preference: Preference::Id(SocketId::ANY),
                    config: (),
                },
                dev,
                _dev: PhantomData,
            },
            ring,
            // SAFETY: the successful lookup wrote a NUL-terminated port name.
            name: unsafe { CStr::from_ptr(name.as_ptr()) }.to_owned(),
            _guard: guard,
        }
    }

    fn pool(&self) -> &Pool {
        &self.rx.config.pool
    }

    fn packets(&self, count: usize) -> MbufArray {
        let mut packets = self.pool().alloc_bulk(count).unwrap();
        for (id, mbuf) in packets.iter_mut().enumerate() {
            mbuf.append(1).unwrap()[0] = id as u8;
        }
        packets
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        while !self.rx.receive().is_empty() {}
        // SAFETY: drain and close the port before freeing its ring and pool.
        unsafe {
            assert_eq!(dpdk_sys::rte_eth_dev_stop(self.tx.dev.0), 0);
            assert_eq!(dpdk_sys::rte_vdev_uninit(self.name.as_ptr()), 0);
            dpdk_sys::rte_ring_free(self.ring.as_ptr());
        }
    }
}

fn packet_ids(batch: &MbufArray) -> Vec<u8> {
    batch.iter().map(|mbuf| mbuf.raw_data()[0]).collect()
}

#[test]
fn empty_rx_and_tx_leave_the_pool_untouched() {
    let mut port = Loopback::new(8);
    assert!(port.rx.receive().is_empty());
    assert!(port.tx.transmit(MbufArray::new_empty()).is_empty());
    assert!(port.rx.receive().is_empty());
    assert_eq!(available(port.pool()), 127);
}

#[test]
fn transmitted_packets_stay_owned_by_the_driver_until_received() {
    let mut port = Loopback::new(128);
    let packets = port.packets(MBUF_BURST);
    let pointers: Vec<_> = packets.iter().map(|mbuf| mbuf.raw).collect();
    assert!(port.tx.transmit(packets).is_empty());
    assert_eq!(available(port.pool()), 127 - MBUF_BURST);

    let received = port.rx.receive();
    assert_eq!(
        packet_ids(&received),
        (0..MBUF_BURST as u8).collect::<Vec<_>>()
    );
    assert_eq!(
        received.iter().map(|mbuf| mbuf.raw).collect::<Vec<_>>(),
        pointers
    );
    assert_eq!(available(port.pool()), 127 - MBUF_BURST);
    drop(received);
    assert_eq!(available(port.pool()), 127);
}

#[test]
fn partial_tx_returns_the_unsent_tail_for_retry() {
    let mut port = Loopback::new(8); // Seven usable ring entries.
    let unsent = port.tx.transmit(port.packets(10));
    assert_eq!(packet_ids(&unsent), [7, 8, 9]);
    assert_eq!(available(port.pool()), 117);

    let unsent = port.tx.transmit(unsent);
    assert_eq!(packet_ids(&unsent), [7, 8, 9]);
    assert_eq!(available(port.pool()), 117);
    let received = port.rx.receive();
    assert_eq!(packet_ids(&received), [0, 1, 2, 3, 4, 5, 6]);
    drop(received);
    assert_eq!(available(port.pool()), 124);

    assert!(port.tx.transmit(unsent).is_empty());
    assert_eq!(available(port.pool()), 124);
    let received = port.rx.receive();
    assert_eq!(packet_ids(&received), [7, 8, 9]);
    drop(received);
    assert_eq!(available(port.pool()), 127);
}

#[test]
fn dropping_unsent_packets_preserves_the_accepted_prefix() {
    let mut port = Loopback::new(8);
    for count in 0..=MBUF_BURST {
        let accepted = count.min(7);
        let unsent = port.tx.transmit(port.packets(count));
        assert_eq!(
            packet_ids(&unsent),
            (accepted as u8..count as u8).collect::<Vec<_>>()
        );
        drop(unsent);
        assert_eq!(available(port.pool()), 127 - accepted);
        let received = port.rx.receive();
        assert_eq!(
            packet_ids(&received),
            (0..accepted as u8).collect::<Vec<_>>()
        );
        drop(received);
        assert_eq!(available(port.pool()), 127);
    }
}

#[test]
fn dropping_an_rx_iterator_frees_undelivered_packets() {
    let mut port = Loopback::new(128);
    assert!(port.tx.transmit(port.packets(MBUF_BURST)).is_empty());
    let mut received = port.rx.receive().into_iter();
    let first = received.next().unwrap();
    drop(received);
    assert_eq!(available(port.pool()), 126);
    assert_eq!(first.raw_data(), &[0]);
    drop(first);
    assert_eq!(available(port.pool()), 127);
}
