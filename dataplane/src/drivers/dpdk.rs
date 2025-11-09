// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK dataplane driver

use std::convert::Infallible;
use std::sync::Arc;

use dpdk::dev::{Dev, TxOffloadConfig};
use dpdk::eal::{self, Eal};
use dpdk::lcore::{LCoreId, WorkerThread};
use dpdk::mem::{Mbuf, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, socket};
use net::packet::Packet;
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, info, trace, warn};

#[allow(unused)] //TEMP
fn init_devices(eal: &Eal<eal::Started>, num_workers: u16) -> Vec<Dev> {
    eal.state
        .dev
        .iter()
        .map(|dev| {
            let config = dev::DevConfig {
                num_rx_queues: num_workers,
                num_tx_queues: num_workers,
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
                info!("creating rx queue on lcore: {rx_queue_config:?}");
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

#[non_exhaustive]
pub struct Configuration<'driver> {
    pub eal: &'driver Eal<'driver, eal::Started<'driver>>,
    pub workers: u16,
    pub setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Mbuf>>,
}

#[non_exhaustive]
pub struct Configured<'driver> {
    eal: &'driver Eal<'driver, eal::Started<'driver>>,
    workers: u16,
    setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Mbuf>>,
}

#[non_exhaustive]
pub struct Started<'driver> {
    eal: &'driver Eal<'driver, eal::Started<'driver>>,
    devices: Box<Vec<Dev>>,
    workers: Vec<LCoreId>,
}

#[non_exhaustive]
pub struct Stopped<'driver> {
    eal: &'driver Eal<'driver, eal::Started<'driver>>,
}

pub struct Dpdk<S> {
    // TODO: absolutely must not be pub at release
    pub state: S,
}

impl<'driver> driver::Configure for Dpdk<Configured<'driver>> {
    type Configuration = Configuration<'driver>;
    type Configured = Dpdk<Configured<'driver>>;
    type Error = Infallible;

    fn configure(configuration: Self::Configuration) -> Result<Self::Configured, Self::Error> {
        Ok(Self::Configured {
            state: Configured {
                eal: configuration.eal,
                workers: configuration.workers,
                setup_pipeline: configuration.setup_pipeline,
            },
        })
    }
}

impl<'config> driver::Start for Dpdk<Configured<'config>> {
    type Started = Dpdk<self::Started<'config>>;

    type Error = Infallible;

    fn start(self) -> Result<Self::Started, Self::Error> {
        let Configured {
            eal,
            workers,
            setup_pipeline,
        } = self.state;
        let devices = Box::new(init_devices(eal, workers));


        let workers = LCoreId::iter()
            .enumerate()
            .map(|(i, lcore_id)| {
                info!("starting RTE Worker on lcore {lcore_id:?}");
                let setup = setup_pipeline.clone();
                let devices = devices.as_ref();
                WorkerThread::launch(lcore_id, move || {
                    info!("starting worker thread runtime");
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .max_blocking_threads(1) // deliberately very low.  No need for a lot of lcores here
                        .on_thread_stop(|| unsafe {
                            dpdk::lcore::ServiceThread::unregister_current_thread();
                        })
                        .build()
                        .unwrap();
                    let _guard = runtime.enter();
                    runtime.block_on(async move {
                        let mut pipeline = setup();
                        let queues: Vec<_> = devices
                            .iter()
                            .map(|device| {
                                let rx_queue = device
                                    .rx_queue(RxQueueIndex(u16::try_from(i).unwrap()))
                                    .unwrap();
                                let tx_queue = device
                                    .tx_queue(TxQueueIndex(u16::try_from(i).unwrap()))
                                    .unwrap();
                                (rx_queue, tx_queue)
                            })
                            .collect();
                        loop {
                            for (rx_queue, tx_queue) in &queues {
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
                        }
                    });
                })
                .unwrap()
            })
            .collect();

        Ok(Self::Started {
            state: Started {
                eal,
                devices,
                workers,
            },
        })
    }
}

impl<'config> driver::Stop for Dpdk<Started<'config>> {
    type Outcome = &'config Eal<'config, eal::Started<'config>>;

    type Error = Infallible;

    fn stop(self) -> Result<Self::Outcome, Self::Error> {
        Ok(self.state.eal)
    }
}

// impl driver::Configure for DpdkDriver<Config> {
//     type Configuration = &'static ArchivedLaunchConfiguration;

//     type Error = Infallible;

//     fn configure<'a>(
//         launch_config_archive: &'static ArchivedLaunchConfiguration,
//     ) -> Result<Self, Self::Error> {
//         match launch_config_archive.driver {
//             args::ArchivedDriverConfigSection::Dpdk(s) => {
//                 let x = s
//                     .eal_args
//                     .iter()
//                     .map(|&x| {
//                         let out: Vec<u8, System> = Vec::from(x.as_bytes_with_nul());
//                         out
//                     })
//                     .collect::<Vec<Vec<u8, System>, System>>();
//             }
//             args::ArchivedDriverConfigSection::Kernel(_) => panic!(),
//         }
//         Ok(Self {
//             state: args,
//             launch_config,
//         })
//     }
// }

// pub struct DpdkDriver<T> {
//     state: T
// }
