// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK dataplane driver

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use args::NetworkDeviceDescription;
use dpdk::dev::{Dev, TxOffloadConfig};
use dpdk::eal::{self, Eal};
use dpdk::lcore::{LCoreId, WorkerThread};
use dpdk::mem::{Mbuf, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, socket};
use net::interface::InterfaceIndex;
use net::packet::Packet;
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, info, trace, warn};

fn init_devices(config: &Configured<'_>) -> Vec<Dev> {
    config
        .eal
        .state
        .dev
        .iter()
        .filter_map(|dev| {
            let description = match dev.description() {
                Ok(description) => description,
                Err(err) => {
                    error!("unable to interpret discovered DPDK device description: {err}");
                    return None;
                }
            };
            let Some(&tap) = config.interfaces.get(&description) else {
                error!("no tap device found for {description}");
                return None;
            };
            let config = dev::DevConfig {
                description,
                tap,
                num_rx_queues: config.workers,
                num_tx_queues: config.workers,
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
            Some(dev)
        })
        .collect()
}

#[non_exhaustive]
pub struct Configuration<'driver> {
    pub interfaces: HashMap<NetworkDeviceDescription, InterfaceIndex>,
    pub eal: &'driver Eal<'driver, eal::Started<'driver>>,
    pub workers: u16,
    pub setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Mbuf>>,
}

#[non_exhaustive]
pub struct Configured<'driver> {
    interfaces: HashMap<NetworkDeviceDescription, InterfaceIndex>,
    eal: &'driver Eal<'driver, eal::Started<'driver>>,
    workers: u16,
    setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Mbuf>>,
}

#[non_exhaustive]
pub struct Started<'driver> {
    eal: &'driver Eal<'driver, eal::Started<'driver>>,
    devices: Arc<Vec<Dev>>,
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
                interfaces: configuration.interfaces,
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
        let devices = Arc::new(init_devices(&self.state));
        let workers = LCoreId::iter()
            .enumerate()
            .map(|(i, lcore_id)| {
                info!("starting RTE Worker on lcore {lcore_id:?}");
                let setup = self.state.setup_pipeline.clone();
                let devices = devices.as_ref();
                WorkerThread::launch(lcore_id, move || {
                    info!("starting worker thread runtime");
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .max_blocking_threads(32) // deliberately very low.  No need for a lot of lcores here
                        // .on_thread_stop(|| unsafe {
                        //     dpdk::lcore::ServiceThread::unregister_current_thread();
                        // })
                        .build()
                        .unwrap();
                    let _guard = runtime.enter();
                    runtime.block_on(async move {
                        let mut pipeline = setup();
                        let mut rx_queues = vector_map::VecMap::with_capacity(devices.len());
                        let mut tx_queues = vector_map::VecMap::with_capacity(devices.len());
                        for device in devices {
                            let rx_queue = device
                                .rx_queue(RxQueueIndex(u16::try_from(i).unwrap()))
                                .unwrap();
                            let tx_queue = device
                                .tx_queue(TxQueueIndex(u16::try_from(i).unwrap()))
                                .unwrap();
                            rx_queues.insert(device.config.tap, rx_queue);
                            tx_queues
                                .insert(device.config.tap, (Vec::with_capacity(512), tx_queue));
                        }
                        loop {
                            for (&iif, &rx_queue) in &rx_queues {
                                let mbufs = rx_queue.receive();
                                let pkts = mbufs.filter_map(|mbuf| match Packet::new(mbuf) {
                                    Ok(mut pkt) => {
                                        pkt.get_meta_mut().iif = Some(iif);
                                        trace!("received packet: {pkt:?}");
                                        Some(pkt)
                                    }
                                    Err(e) => {
                                        error!("Failed to parse packet: {e:?}");
                                        None
                                    }
                                });
                                error!("about to sleep in busy loop");
                                tokio::time::sleep(Duration::from_millis(100)).await;

                                pipeline.process(pkts).for_each(|pkt| {
                                    trace!("to transmit by pipeline {pkt:?}");
                                    let Some(oif) = pkt.meta.oif else {
                                        warn!("no output interface available for packet {pkt:?}");
                                        return;
                                    };
                                    match pkt.serialize() {
                                        Ok(buf) => {
                                            let Some((schedule, _)) = tx_queues.get_mut(&oif)
                                            else {
                                                warn!(
                                                    "unknown output index {oif}, dropping packet"
                                                );
                                                return;
                                            };
                                            schedule.push(buf);
                                        }
                                        Err(err) => {
                                            warn!("unable to serialize packet: {err}");
                                        }
                                    }
                                });
                            }
                            for (_, (schedule, tx_queue)) in &mut tx_queues {
                                if schedule.is_empty() {
                                    continue;
                                }
                                info!("scheduling transmit of {} packets", schedule.len());
                                tx_queue.transmit(schedule);
                                schedule.clear();
                            }
                        }
                    });
                })
                .unwrap()
            })
            .collect();

        Ok(Self::Started {
            state: Started {
                eal: self.state.eal,
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
