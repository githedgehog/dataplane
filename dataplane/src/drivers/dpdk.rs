// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK dataplane driver

#![allow(unused)]

use dpdk::dev::{Dev, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::lcore::{LCoreId, WorkerThread};
use dpdk::mem::{Mbuf, Pool, PoolConfig, PoolParams, RteAllocator};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, eal, socket};
use tracing::{debug, error, info, trace, warn};

use crate::CmdArgs;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::sample_nfs::Passthrough;
use pipeline::{self, DynPipeline, NetworkFunction};

/*
#[global_allocator]
static GLOBAL_ALLOCATOR: RteAllocator = RteAllocator::new_uninitialized();
 */

fn init_eal(args: impl IntoIterator<Item = impl AsRef<str>>) -> Eal {
    let rte = eal::init(args);
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_thread_names(true)
        .init();
    rte
}

fn init_devices(eal: &Eal) -> Vec<Dev> {
    eal.dev
        .iter()
        .map(|dev| {
            let config = dev::DevConfig {
                num_rx_queues: 2,
                num_tx_queues: 2,
                num_hairpin_queues: 0,
                rx_offloads: None,
                tx_offloads: Some(TxOffloadConfig::default()),
            };
            let mut dev = match config.apply(dev) {
                Ok(stopped_dev) => {
                    warn!("Device configured {stopped_dev:?}");
                    stopped_dev
                }
                Err(err) => {
                    Eal::fatal_error(format!("Failed to configure device: {err:?}"));
                }
            };
            LCoreId::iter().enumerate().for_each(|(i, lcore_id)| {
                let rx_queue_config = RxQueueConfig {
                    dev: dev.info.index(),
                    queue_index: RxQueueIndex(u16::try_from(i).unwrap()),
                    num_descriptors: 2048,
                    socket_preference: socket::Preference::LCore(lcore_id),
                    offloads: dev.info.rx_offload_caps(),
                    pool: Pool::new_pkt_pool(
                        PoolConfig::new(
                            format!("dev-{d}-lcore-{l}", d = dev.info.index(), l = lcore_id.0),
                            PoolParams {
                                socket_id: socket::Preference::LCore(lcore_id).try_into().unwrap(),
                                ..Default::default()
                            },
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                };
                dev.new_rx_queue(rx_queue_config).unwrap();
                let tx_queue_config = TxQueueConfig {
                    queue_index: TxQueueIndex(u16::try_from(i).unwrap()),
                    num_descriptors: 2048,
                    socket_preference: socket::Preference::LCore(lcore_id),
                    config: (),
                };
                dev.new_tx_queue(tx_queue_config).unwrap();
            });
            dev.start().unwrap();
            dev
        })
        .collect()
}

fn start_rte_workers(devices: &[Dev], setup_pipeline: &(impl Sync + Fn() -> DynPipeline<Mbuf>)) {
    LCoreId::iter().enumerate().for_each(|(i, lcore_id)| {
        info!("Starting RTE Worker on {lcore_id:?}");
        WorkerThread::launch(lcore_id, move || {
            let mut pipeline = setup_pipeline();
            let rx_queue = devices[0]
                .rx_queue(RxQueueIndex(u16::try_from(i).unwrap()))
                .unwrap();
            let tx_queue = devices[0]
                .tx_queue(TxQueueIndex(u16::try_from(i).unwrap()))
                .unwrap();
            loop {
                let mbufs = rx_queue.receive();
                let pkts = mbufs.filter_map(|mbuf| match Packet::new(mbuf) {
                    Ok(pkt) => {
                        debug!("packet: {pkt:?}");
                        Some(pkt)
                    }
                    Err(e) => {
                        trace!("Failed to parse packet: {e:?}");
                        None
                    }
                });

                let pkts_out = pipeline.process(pkts);
                let buffers = pkts_out.filter_map(|pkt| match pkt.serialize() {
                    Ok(buf) => Some(buf),
                    Err(e) => {
                        error!("{e:?}");
                        None
                    }
                });
                tx_queue.transmit(buffers);
            }
        });
    });
}

pub struct DriverDpdk;

impl DriverDpdk {
    pub fn start(
        args: impl IntoIterator<Item = impl AsRef<str>>,
        setup_pipeline: &(impl Sync + Fn() -> DynPipeline<Mbuf>),
    ) {
        let eal = init_eal(args);
        let devices = init_devices(&eal);
        start_rte_workers(&devices, setup_pipeline);
    }
}
