// SPDX-License-Identifier: Apache-2.0

use dpdk::dev::{Dev, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::lcore::{LCoreId, WorkerThread};
use dpdk::mem::{Pool, PoolConfig, PoolParams, RteAllocator};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, eal, socket};
use net::packet::Packet;
use net::parse::Parse;
use tracing::{info, warn};

#[global_allocator]
static GLOBAL_ALLOCATOR: RteAllocator = RteAllocator::new_uninitialized();

fn init(args: impl IntoIterator<Item = impl AsRef<str>>) -> Eal {
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

fn main() {
    let eal: Eal = init([
        "--main-lcore",
        "2",
        "--lcores",
        "2-4",
        "--in-memory",
        "--allow",
        "0000:01:00.0,dv_flow_en=1",
        "--huge-worker-stack=8192",
        "--socket-mem=8192,0,0,0",
        "--no-telemetry",
        "--iova-mode=va",
    ]);

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
        .expect("failed to set SIGINT handler");

    let devices: Vec<Dev> = eal
        .dev
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
                    queue_index: RxQueueIndex(i as u16),
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
                    queue_index: TxQueueIndex(i as u16),
                    num_descriptors: 2048,
                    socket_preference: socket::Preference::LCore(lcore_id),
                    config: (),
                };
                dev.new_tx_queue(tx_queue_config).unwrap();
            });
            dev.start().unwrap();
            dev
        })
        .collect();

    LCoreId::iter().enumerate().for_each(|(i, lcore_id)| {
        info!("Starting RTE Worker on {lcore_id:?}");
        let rx_queue = devices[0].rx_queue(RxQueueIndex(i as u16)).unwrap();
        let tx_queue = devices[0].tx_queue(TxQueueIndex(i as u16)).unwrap();
        WorkerThread::launch(lcore_id, move || loop {
            let mut pkts: Vec<_> = rx_queue.receive().collect();
            for pkt in pkts.iter_mut() {
                let Ok((packet, _rest)) = Packet::parse(pkt.raw_data_mut()) else {
                    info!("failed to parse packet");
                    continue;
                };
                info!("received packet: {packet:?}");
            }
            tx_queue.transmit(pkts);
        });
    });
    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    std::process::exit(0);
}
