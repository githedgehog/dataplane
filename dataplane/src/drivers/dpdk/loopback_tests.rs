// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The whole DPDK driver over a ring cable, with the test standing in for the far end of the wire
//! and for the kernel behind the port's tap.

use std::net::IpAddr;
use std::num::{NonZero, NonZeroUsize};
use std::time::{Duration, Instant};

use concurrency::sync::Arc;
use concurrency::thread;
use config::external::overlay::vpcpeering::contract::{
    LOCAL_VNI, REMOTE_VNI, overlay_with_exposes_and_acl,
};
use dpdk::dev::ring::RingCable;
use dpdk::dev::{Dev, DevConfig, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::{self, Eal};
use dpdk::mem::{Mbuf, MbufArray, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use dpdk::socket::Preference;
use flow_entry::flow_table::FlowTable;
use lifecycle::{CancellationToken, Subsystem};
use lldp::Link;
use net::buffer::{Append, TestBuffer};
use net::eth::mac::Mac;
use net::headers::{TryEth, TryVxlan};
use net::interface::{InterfaceIndex, InterfaceName};
use net::packet::Packet;
use net::vxlan::Vxlan;
use pipeline::DynPipeline;
use tokio::sync::watch;
use traffic_control::ControlPlane;

use super::source::{PortSettings, RingPort, attach_ports, bring_up_ports};
use super::{DatapathEnds, DriverDpdk};
use crate::drivers::cpbridge::DetachedPort;
use crate::drivers::status::driver_status_access;
use crate::packet_processor::PipelineIngredients;
use crate::packet_processor::fixture::{
    Fleet, GATEWAY_MAC, LOCAL_VTEP, PEER_MAC, PEER_VTEP, exposes, inner, inside, topology,
    tunnelled, uplink, vni,
};

const WORKERS: u16 = 2;

/// Data queues and the control queue.
const QUEUES: u16 = WORKERS + 1;

/// How often the driver's supervisor collects its workers' counters: often, so that a check of
/// them need wait only moments for the counts to settle.
const SUPERVISOR_POLL: Duration = Duration::from_millis(10);

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
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
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
    // Until the control worker finds the ring port has no rules and falls back to software,
    // ARP goes through the (empty) pipeline and is dropped; keep asking.
    let request = arp_request([0x02, 0, 0, 0, 0, 1]);
    let deadline = Instant::now() + PATIENCE;
    let punted = loop {
        far.send(0, &request);
        if let Ok(frame) = kernel.control.try_recv() {
            break Some(frame);
        }
        if Instant::now() > deadline {
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

/// What stands on the dataplane's side of the cable.
struct Gateway {
    /// The port's address.
    mac: Mac,
    /// What the pipeline calls the port.
    index: InterfaceIndex,
    /// The pipeline the workers run; one that does nothing if `None`.
    pipeline: Option<PipelineIngredients>,
}

/// Bring the DPDK driver up on one end of a ring cable and run `exchange` against the other end
/// and the kernel's side of the port's bridge.
///
/// `setup` runs once the EAL exists and inside the timer runtime, as the gateway's state needs;
/// whatever else it returns is kept alive until the driver has stopped.
fn over_cable<K>(
    setup: impl FnOnce() -> (Gateway, K),
    exchange: impl FnOnce(&mut FarEnd<'_>, &mut DetachedPort),
) {
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
    let timers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (gateway, _upkeep) = {
        let _runtime = timers.enter();
        setup()
    };

    let cable = eal.attach_ring_cable("loop", QUEUES, 1024).unwrap();
    let sources = attach_ports(
        &mut eal,
        vec![RingPort {
            settings: PortSettings {
                name: loop0(),
                mtu: None,
                rx_descriptors: None,
                fallback_mac: Some(gateway.mac),
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
        gateway.mac,
        "a ring port has no address of its own"
    );

    let (far_dev, far_pool) = FarEnd::start(eal, cable);
    let mut far = FarEnd::queues(&far_dev, far_pool, QUEUES);

    let (mut bridge, mut kernel, _identities) = DatapathEnds::detached([(loop0(), gateway.index)]);
    let mut kernel = kernel.pop().unwrap();
    assert_eq!(kernel.name, loop0());

    let workers = Subsystem::new("workers", CancellationToken::new());
    let (status, _status_reader) = driver_status_access();
    let (_control_plane_tx, control_plane) = watch::channel(ControlPlane::new([], []));

    thread::scope(|scope| {
        // Stop the workers however this closure ends, or a failed assertion would leave the scope
        // waiting on them forever.
        let _stop = workers.cancel_token().drop_guard();
        let pipeline = gateway
            .pipeline
            .map_or_else(empty_pipeline, PipelineIngredients::factory);
        DriverDpdk::start(
            scope,
            &workers,
            timers.handle(),
            &ports,
            NonZero::new(WORKERS).unwrap(),
            SUPERVISOR_POLL,
            &pipeline,
            status,
            Some(&mut bridge),
            control_plane,
        )
        .unwrap();

        let deadline = Instant::now() + PATIENCE;
        while *kernel.link.borrow() != Link::Up {
            assert!(
                Instant::now() < deadline,
                "a started ring port should be reported up"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        exchange(&mut far, &mut kernel);
    });

    drop(far);
    drop(far_dev);
    for port in ports {
        port.shutdown();
    }
}

/// A ring cable carries control traffic both ways through the full DPDK driver: an ARP request
/// sent into a data queue is taken off the data path in software (a ring port has no `rte_flow`
/// to steer it) and reaches the kernel's side of the bridge, and a frame the kernel injects
/// leaves on the control queue.
#[test]
fn control_frames_cross_a_ring_cable_both_ways() {
    over_cable(
        || {
            let gateway = Gateway {
                mac: Mac([0x02, 0, 0, 0, 0, 0x10]),
                index: InterfaceIndex::try_new(1000).unwrap(),
                pipeline: None,
            };
            (gateway, ())
        },
        exchange_control_frames,
    );
}

/// A tunnelled frame crosses the cable, the production pipeline and the cable again: decapsulated,
/// masqueraded and sent back out to the peer VTEP in the remote VPC.
#[test]
fn a_tunnelled_frame_makes_a_round_trip_through_the_pipeline() {
    over_cable(
        || {
            let tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
            let overlay = overlay_with_exposes_and_acl(exposes(), None)
                .unwrap()
                .validate()
                .unwrap();
            let fleet = Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
            let workers = NonZeroUsize::new(usize::from(WORKERS)).unwrap();
            let (pipeline, upkeep) = fleet.ingredients(&tables, workers);
            let gateway = Gateway {
                mac: GATEWAY_MAC,
                index: uplink(),
                pipeline: Some(pipeline),
            };
            (gateway, (tables, fleet, upkeep))
        },
        |far, kernel| {
            let sent = tunnelled(&inner());
            far.send(0, sent.serialize().unwrap().as_ref());

            // A worker transmits on its own queue, and only worker 0 receives on queue 0.
            let frame = far
                .receive(0)
                .expect("the frame should come back out of the gateway");
            let back = Packet::new(TestBuffer::from_raw_data(&frame))
                .expect("what the gateway sends should parse");
            assert_eq!(
                back.try_eth()
                    .map(|eth| (eth.source().inner(), eth.destination().inner())),
                Some((GATEWAY_MAC, PEER_MAC)),
                "from this gateway to the resolved next hop"
            );
            assert_eq!(back.ip_source(), Some(LOCAL_VTEP.parse().unwrap()));
            assert_eq!(back.ip_destination(), Some(PEER_VTEP.parse().unwrap()));
            assert_eq!(
                back.try_vxlan().map(Vxlan::vni),
                Some(vni(REMOTE_VNI)),
                "encapsulated towards the remote VPC"
            );

            let carried = inside(&back).expect("the frame should still be encapsulated");
            let Some(IpAddr::V4(source)) = carried.ip_source() else {
                panic!("the carried packet has no IPv4 source: {carried:?}");
            };
            assert_eq!(source.octets()[..2], [2, 2], "masqueraded into 2.2.0.0/16");
            assert_eq!(carried.ip_destination(), Some("3.3.3.1".parse().unwrap()));
            assert!(
                kernel.punted.try_recv().is_err(),
                "a forwarded frame should not also reach the kernel"
            );
        },
    );
}
