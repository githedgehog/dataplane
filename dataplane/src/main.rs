// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod args;
mod nat;
mod packet;
mod pipeline;

use dpdk::dev::{Dev, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::lcore::{LCoreId, WorkerThread};
use dpdk::mem::{Mbuf, Pool, PoolConfig, PoolParams, RteAllocator};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, eal, socket};
use tracing::{info, trace, warn};

use crate::args::{CmdArgs, Parser};
use crate::packet::Packet;
use crate::pipeline::sample_nfs::Passthrough;
use crate::pipeline::{DynPipeline, NetworkFunction};

#[global_allocator]
static GLOBAL_ALLOCATOR: RteAllocator = RteAllocator::new_uninitialized();

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

// FIXME(mvachhar) construct pipline elsewhere, ideally from config file
fn setup_pipeline() -> DynPipeline<Mbuf> {
    let pipeline = DynPipeline::new();

    pipeline.add_stage(Passthrough)
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

fn start_rte_workers(devices: &[Dev]) {
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
                    Ok(pkt) => Some(pkt),
                    Err(e) => {
                        trace!("Failed to parse packet: {e:?}");
                        None
                    }
                });

                let pkts_out = pipeline.process(pkts);
                tx_queue.transmit(pkts_out.map(Packet::reserialize));
            }
        });
    });
}

fn main() {
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
        .expect("failed to set SIGINT handler");

    let args = CmdArgs::parse();
    let eal: Eal = init_eal(args.eal_params());

    let devices: Vec<Dev> = init_devices(&eal);

    start_rte_workers(&devices);

    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    std::process::exit(0);
}
