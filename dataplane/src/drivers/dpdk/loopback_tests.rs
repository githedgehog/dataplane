// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The whole DPDK driver over a ring cable, with the test standing in for the far end of the wire
//! and for the kernel behind the port's tap.

use std::num::NonZero;
use std::time::Duration;

use concurrency::sync::Arc;
use concurrency::thread;
use dpdk::dev::ring::RingCable;
use dpdk::dev::{Dev, DevConfig, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::{self, Eal};
use dpdk::mem::{Mbuf, MbufArray, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use dpdk::socket::Preference;
use lifecycle::{CancellationToken, Subsystem};
use lldp::Link;
use net::buffer::Append;
use net::eth::mac::Mac;
use net::interface::{InterfaceIndex, InterfaceName};
use pipeline::DynPipeline;
use tokio::sync::watch;
use traffic_control::ControlPlane;

use super::source::{PortSettings, RingPort, attach_ports, bring_up_ports};
use super::{DatapathEnds, DriverDpdk};
use crate::drivers::cpbridge::DetachedPort;
use crate::drivers::status::driver_status_access;

const WORKERS: u16 = 2;

/// Data queues and the control queue.
const QUEUES: u16 = WORKERS + 1;

/// The dataplane port's address, which a ring port cannot supply itself.
const PORT_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0x10]);

/// The configured name of the dataplane's end of the cable.
fn loop0() -> InterfaceName {
    InterfaceName::try_from("loop0").unwrap()
}

/// How long anything in these tests may take to happen before it is taken not to.
const PATIENCE: Duration = Duration::from_secs(10);

/// The far end of the cable: every queue the dataplane's end has, unsteered.
struct FarEnd<'eal> {
    pool: Pool<'eal>,
    rx: Vec<RxQueue<'eal>>,
    tx: Vec<TxQueue<'eal>>,
}

impl<'eal> FarEnd<'eal> {
    fn start(eal: &'eal Eal, cable: RingCable) -> (Dev<'eal, Started>, Pool<'eal>) {
        let pool = eal
            .mem
            .new_pkt_pool(
                PoolConfig::new(
                    "far_end",
                    PoolParams {
                        size: 1023,
                        ..Default::default()
                    },
                )
                .unwrap(),
            )
            .unwrap();
        let mut dev = DevConfig {
            num_rx_queues: cable.queues,
            num_tx_queues: cable.queues,
            num_hairpin_queues: 0,
            tx_offloads: TxOffloadConfig::none(),
            rx_offloads: RxOffload::NONE,
            mtu: None,
            rss: None,
        }
        .apply(eal.claim(cable.b).unwrap())
        .unwrap();
        for queue in 0..cable.queues {
            dev.new_rx_queue(RxQueueConfig {
                queue_index: RxQueueIndex(queue),
                num_descriptors: 512,
                socket_preference: Preference::Dev(cable.b),
                offloads: RxOffload::NONE,
                pool: pool.clone(),
            })
            .unwrap();
            dev.new_tx_queue(TxQueueConfig {
                queue_index: TxQueueIndex(queue),
                num_descriptors: 512,
                socket_preference: Preference::Dev(cable.b),
                config: (),
            })
            .unwrap();
        }
        (dev.start().unwrap(), pool)
    }

    fn queues(dev: &'eal Dev<'_, Started>, pool: Pool<'eal>, queues: u16) -> Self {
        let mut taken = dev.take_queues().unwrap();
        FarEnd {
            pool,
            rx: (0..queues)
                .map(|q| taken.take_rx(RxQueueIndex(q)).unwrap())
                .collect(),
            tx: (0..queues)
                .map(|q| taken.take_tx(TxQueueIndex(q)).unwrap())
                .collect(),
        }
    }

    /// Send `frame` into the dataplane's receive queue `queue`.
    fn send(&mut self, queue: usize, frame: &[u8]) {
        let mut burst = self.pool.alloc_bulk(1).unwrap();
        for mbuf in &mut burst {
            mbuf.append(u16::try_from(frame.len()).unwrap())
                .unwrap()
                .copy_from_slice(frame);
        }
        assert!(self.tx[queue].transmit(burst).is_empty());
    }

    /// The next frame the dataplane transmitted on its queue `queue`, if one comes in time.
    fn receive(&mut self, queue: usize) -> Option<Vec<u8>> {
        let deadline = clock::now() + PATIENCE;
        while clock::now() < deadline {
            let burst: MbufArray<'_> = self.rx[queue].receive();
            if let Some(mbuf) = burst.iter().next() {
                return Some(Mbuf::raw_data(mbuf).to_vec());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        None
    }
}

/// A pipeline that does nothing, so whatever it is given leaves with no output interface.
fn empty_pipeline<'p>() -> Arc<dyn Send + Sync + Fn() -> DynPipeline<'p, Mbuf<'p>> + 'p> {
    Arc::new(DynPipeline::new)
}

/// A broadcast ARP request from `sender`, padded to the Ethernet minimum.
fn arp_request(sender: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(60);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&sender);
    frame.extend_from_slice(&[0x08, 0x06]); // ARP
    frame.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]); // Ethernet/IPv4 request
    frame.extend_from_slice(&sender);
    frame.extend_from_slice(&[192, 0, 2, 1]);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&[192, 0, 2, 2]);
    frame.resize(60, 0);
    frame
}

/// Check, through a running driver, that control frames cross the port both ways.
fn exchange_control_frames(far: &mut FarEnd<'_>, kernel: &mut DetachedPort) {
    let deadline = clock::now() + PATIENCE;
    while *kernel.link.borrow() != Link::Up {
        assert!(
            clock::now() < deadline,
            "a started ring port should be reported up"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Until the control worker finds the ring port has no rules and falls back to software,
    // ARP goes through the (empty) pipeline and is dropped; keep asking.
    let request = arp_request([0x02, 0, 0, 0, 0, 1]);
    let deadline = clock::now() + PATIENCE;
    let punted = loop {
        far.send(0, &request);
        if let Ok(frame) = kernel.control.try_recv() {
            break Some(frame);
        }
        if clock::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        punted.as_deref(),
        Some(request.as_slice()),
        "an ARP request on a data queue should reach the kernel on the control channel"
    );
    assert!(
        kernel.punted.try_recv().is_err(),
        "control traffic should not come up the data path's punt channel"
    );

    let reply = arp_request([0x02, 0, 0, 0, 0, 2]);
    kernel.inject.try_send(reply.clone()).unwrap();
    assert_eq!(
        far.receive(usize::from(WORKERS)).as_deref(),
        Some(reply.as_slice()),
        "an injected frame should leave on the control queue"
    );
}

/// A ring cable carries control traffic both ways through the full DPDK driver: an ARP request
/// sent into a data queue is taken off the data path in software (a ring port has no `rte_flow`
/// to steer it) and reaches the kernel's side of the bridge, and a frame the kernel injects
/// leaves on the control queue.
#[test]
fn control_frames_cross_a_ring_cable_both_ways() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let mut eal = eal::init([
        "--no-huge",
        // Without hugepages the EAL reserves 64 MiB, less than one port's pools.
        "-m",
        "512",
        "--no-pci",
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--no-hpet",
        "--iova-mode=va",
        "--lcores",
        &eal::main_lcore_arg(),
    ]);
    let cable = eal.attach_ring_cable("loop", QUEUES, 1024).unwrap();
    let sources = attach_ports(
        &mut eal,
        vec![RingPort {
            settings: PortSettings {
                name: loop0(),
                mtu: None,
                rx_descriptors: None,
                fallback_mac: Some(PORT_MAC),
            },
            dev: cable.a,
        }],
    )
    .unwrap();
    let eal: &Eal = &eal;
    let ports = bring_up_ports(eal, &sources, WORKERS).unwrap();
    assert_eq!(ports[0].if_index, None, "a ring port has no kernel netdev");
    assert_eq!(
        ports[0].mac.inner(),
        PORT_MAC,
        "a ring port has no address of its own"
    );

    let (far_dev, far_pool) = FarEnd::start(eal, cable);
    let mut far = FarEnd::queues(&far_dev, far_pool, QUEUES);

    let (mut bridge, mut kernel, _identities) =
        DatapathEnds::detached([(loop0(), InterfaceIndex::try_new(1000).unwrap())]);
    let mut kernel = kernel.pop().unwrap();
    assert_eq!(kernel.name, loop0());

    let timers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let workers = Subsystem::new("workers", CancellationToken::new());
    let (status, _status_reader) = driver_status_access();
    let (_control_plane_tx, control_plane) = watch::channel(ControlPlane::new([], []));

    thread::scope(|scope| {
        // Stop the workers however this closure ends, or a failed assertion would leave the scope
        // waiting on them forever.
        let _stop = workers.cancel_token().drop_guard();
        let pipeline = empty_pipeline();
        DriverDpdk::start(
            scope,
            &workers,
            timers.handle(),
            &ports,
            NonZero::new(WORKERS).unwrap(),
            &pipeline,
            status,
            Some(&mut bridge),
            control_plane,
        )
        .unwrap();

        exchange_control_frames(&mut far, &mut kernel);
    });

    drop(far);
    drop(far_dev);
    for port in ports {
        port.shutdown();
    }
}
