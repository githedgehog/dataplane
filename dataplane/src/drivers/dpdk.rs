// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK dataplane driver

use std::convert::Infallible;

use args::LaunchConfiguration;
use dpdk::dev::{Dev, TxOffloadConfig};
use dpdk::eal::{Eal, EalArgs};
use dpdk::lcore::LCoreId;
use dpdk::mem::{Pool, PoolConfig, PoolParams, RteAllocator};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, socket};
use tracing::warn;

#[global_allocator]
static GLOBAL_ALLOCATOR: RteAllocator = RteAllocator::new_uninitialized();

#[allow(unused)] //TEMP
fn init_devices(eal: &Eal, num_workers: u16) -> Vec<Dev> {
    eal.dev
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
pub struct Started {
    eal: Eal,
    // devices: Vec<Dev>,
    workers: u16,
}

#[non_exhaustive]
pub struct Stopped;

pub struct Dpdk<S> {
    state: S,
}

impl<'config> driver::Configure for Dpdk<&'config rkyv::Archived<LaunchConfiguration>> {
    type Configuration = &'config rkyv::Archived<LaunchConfiguration>;

    type Error = Infallible;

    fn configure<'a>(config: Self::Configuration) -> Result<Self, Self::Error> {
        Ok(Dpdk { state: config })
    }
}

impl<'a> driver::Start for Dpdk<&'a rkyv::Archived<LaunchConfiguration>> {
    type Started = Dpdk<Started>;
    type Error = Infallible;

    /// Memory allocation ok if this function is successful
    fn start(self) -> Result<Self::Started, Self::Error> {
        let eal_args = match &self.state.driver {
            args::ArchivedDriverConfigSection::Dpdk(section) => {
                EalArgs::new(&section.eal_args)
            },
            args::ArchivedDriverConfigSection::Kernel(_) => {
                unreachable!()
            },
        };
        let eal = dpdk::eal::init(eal_args);
        // memory allocation ok after this line
        // let devices = init_devices(&eal, self.state.dataplane_workers.to_native());
        Ok(Self::Started {
            state: Started {
                eal,
                // devices,
                workers: self.state.dataplane_workers.to_native(),
            },
        })
    }
}

impl driver::Stop for Dpdk<Started> {
    type Outcome = ();

    fn stop(self) -> Self::Outcome {
        todo!()
    }
}

// mod private {
//     pub(super) trait Sealed {}
// }

// pub enum Dataplane {
//     Configured(DpdkDriver<Config>),
//     Started(DpdkDriver<Started>),
//     Stopped(DpdkDriver<Stopped>),
// }

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

// impl driver::Start for DpdkDriver<Config> {
//     type Started = DpdkDriver<Started>;

//     type Error = Infallible;

//     fn start(self) -> Result<Self::Started, Self::Error> {
//         let eal = eal::init(args);
//         let devices = init_devices(&eal, num_workers);
//         LCoreId::iter().enumerate().for_each(|(i, lcore_id)| {
//             info!("starting RTE Worker on lcore {lcore_id:?}");
//             let setup = self.setup_pipeline.clone();
//             WorkerThread::launch(lcore_id, move || {
//                 info!("starting worker thread runtime");
//                 let runtime = tokio::runtime::Builder::new_current_thread()
//                     .max_blocking_threads(1)
//                     .on_thread_start(|| {
//                         // TODO: banish dpdk-sys back to  where it belongs
//                         info!("initializing RTE runtime async worker thread");
//                         let ret = unsafe { dpdk_sys::rte_thread_register() };
//                         if ret != 0 {
//                             let errno = unsafe { dpdk_sys::rte_errno_get() };
//                             let msg = format!("rte thread exited with code {ret}, errno: {errno}");
//                             Eal::fatal_error(msg)
//                         }
//                     })
//                     .on_thread_stop(|| unsafe { dpdk_sys::rte_thread_unregister() })
//                     .build()
//                     .unwrap();
//                 let _guard = runtime.enter();
//                 runtime.block_on(async move {
//                     let mut pipeline = setup();
//                     let queues: Vec<_> = self
//                         .devices
//                         .iter()
//                         .map(|device| {
//                             let rx_queue = device
//                                 .rx_queue(RxQueueIndex(u16::try_from(i).unwrap()))
//                                 .unwrap();
//                             let tx_queue = device
//                                 .tx_queue(TxQueueIndex(u16::try_from(i).unwrap()))
//                                 .unwrap();
//                             (rx_queue, tx_queue)
//                         })
//                         .collect();
//                     loop {
//                         for (rx_queue, tx_queue) in &queues {
//                             let mbufs = rx_queue.receive();
//                             let pkts = mbufs.filter_map(|mbuf| match Packet::new(mbuf) {
//                                 Ok(pkt) => {
//                                     debug!("packet: {pkt:?}");
//                                     Some(pkt)
//                                 }
//                                 Err(e) => {
//                                     trace!("Failed to parse packet: {e:?}");
//                                     None
//                                 }
//                             });

//                             let pkts_out = pipeline.process(pkts);
//                             let buffers = pkts_out.filter_map(|pkt| match pkt.serialize() {
//                                 Ok(buf) => Some(buf),
//                                 Err(e) => {
//                                     error!("{e:?}");
//                                     None
//                                 }
//                             });
//                             tx_queue.transmit(buffers);
//                         }
//                     }
//                 });
//             })
//             .unwrap();
//         });
//     }
// }
