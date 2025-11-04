// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK dataplane driver

#![allow(unused)]

use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use args::LaunchConfiguration;
use dpdk::dev::{Dev, RxOffload, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::lcore::{LCoreId, WorkerThread};
use dpdk::mem::{Mbuf, Pool, PoolConfig, PoolParams, RteAllocator};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, eal, socket};
use mgmt::processor::launch::start_mgmt;
use routing::RouterParamsBuilder;
use tracing::{debug, error, info, trace, warn};

use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::sample_nfs::Passthrough;
use pipeline::{self, DynPipeline, NetworkFunction};
use tracing_subscriber::filter::combinator::Or;

use crate::drivers::kernel::DriverKernel;
use crate::packet_processor::start_router;
use crate::statistics::MetricsServer;

/*
#[global_allocator]
static GLOBAL_ALLOCATOR: RteAllocator = RteAllocator::new_uninitialized();
*/

pub struct Dataplane<D: Driver + Stop> {
    driver: D,
}

impl<D: Driver + Stop> Drop for Dataplane<D> {
    fn drop(&mut self) {
        self.driver.stop();
    }
}

impl Dataplane<DriverDpdk<Stopped>> {
    pub(crate) fn new(launch_config: LaunchConfiguration) -> Dataplane<DriverDpdk<Stopped>> {
        /* router parameters */
        let config = match RouterParamsBuilder::default()
            .metrics_addr(launch_config.metrics.address)
            .cli_sock_path(launch_config.cli.cli_sock_path)
            .cpi_sock_path(launch_config.routing.control_plane_socket)
            .frr_agent_path(launch_config.routing.frr_agent_socket)
            .build()
        {
            Ok(config) => config,
            Err(e) => {
                error!("error building router parameters: {e}");
                panic!("error building router parameters: {e}");
            }
        };

        // start the router; returns control-plane handles and a pipeline factory (Arc<... Fn() -> DynPipeline<_> >)
        let setup = start_router(config).expect("failed to start router");

        let _metrics_server = MetricsServer::new(launch_config.metrics.address, setup.stats);

        /* pipeline builder */
        let pipeline_factory = setup.pipeline;

        /* start management */
        start_mgmt(
            launch_config.config_server.address,
            setup.router.get_ctl_tx(),
            setup.nattablew,
            setup.natallocatorw,
            setup.vpcdtablesw,
            setup.vpcmapw,
            setup.vpc_stats_store,
        )
        .expect("Failed to start gRPC server");

        let driver = match &launch_config.driver {
            args::DriverConfigSection::Dpdk(dpdk_driver_config) => {
                info!("setting up DPDK driver");
                DriverDpdk::new(
                    dpdk_driver_config.eal_args.iter(),
                    launch_config.workers.num_workers,
                    pipeline_factory,
                )
            }
            args::DriverConfigSection::Kernel(kernel_driver_config) => {
                unreachable!() // refactor flow to zap this branch
            }
        };
        Self { driver }
    }
}

impl Start for DriverDpdk<Stopped> {
    type Started = DriverDpdk<Started>;
    fn start(mut self) -> DriverDpdk<Started> {
        self.start_rte_workers();
        DriverDpdk {
            eal: self.eal,
            devices: self.devices,
            setup_pipeline: self.setup_pipeline,
            shutdown_rx: self.shutdown_rx,
            shutdown_tx: self.shutdown_tx,
            state: Started,
        }
    }
}

impl Stop for Dataplane<DriverDpdk<Stopped>> {
    type Error = Infallible;
    fn stop(&mut self) -> Result<(), Infallible> {
        Ok(())
    }
}

impl Stop for DriverDpdk<Stopped> {
    type Error = Infallible;
    fn stop(&mut self) -> Result<(), Infallible> {
        Ok(())
    }
}

impl Stop for Dataplane<DriverDpdk<Started>> {
    type Error = Infallible;
    fn stop(&mut self) -> Result<(), Infallible> {
        self.driver.stop();
        Ok(())
    }
}

impl Start for Dataplane<DriverDpdk<Stopped>> {
    type Started = Dataplane<DriverDpdk<Started>>;

    fn start(self) -> Self::Started {
        Self::Started {
            driver: self.driver.start(),
        }
    }
}

impl Stop for DriverDpdk<Started> {
    type Error = Infallible;
    fn stop(&mut self) -> Result<(), Infallible> {
        match self.shutdown_tx.send(true) {
            Ok(()) => {
                info!("sent shutdown signal to eal worker threads");
                Ok(())
            }
            Err(err) => {
                error!("failed to sind shutdown signal to eal worker threads: {err}");
                Eal::fatal_error("failed to sind shutdown signal to eal worker threads");
            }
        }
    }
}

fn init_devices(eal: &Eal, num_workers: u16) -> Vec<Dev> {
    // TODO: pipe in number of workers to compute correct number of queues
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

pub struct DriverDpdk {
    eal: Eal,
    devices: Vec<Dev>,
    setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Mbuf>>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl Stop for DriverDpdk {
    type Error = tokio::error::SendError<bool>;

    fn stop(&mut self) -> Result<(), Self::Error> {
        self.shutdown.send(true)
    }
}

impl Driver for DriverDpdk {}

impl DriverDpdk {
    pub(crate) fn new(
        args: impl IntoIterator<Item = impl AsRef<str>>,
        num_workers: u16,
        setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Mbuf>>,
    ) -> Self {
        let eal = eal::init(args);
        let devices = init_devices(&eal, num_workers);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        DriverDpdk {
            eal,
            devices,
            setup_pipeline,
            shutdown_rx,
            shutdown_tx,
            state: Stopped,
        }
    }

    fn start_rte_workers(&self) {
        LCoreId::iter().enumerate().for_each(|(i, lcore_id)| {
            info!("starting RTE Worker on lcore {lcore_id:?}");
            let rx = self.shutdown_rx.clone();
            let setup = self.setup_pipeline.clone();
            WorkerThread::launch(lcore_id, move || {
                info!("starting worker thread runtime");
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .max_blocking_threads(1)
                    .on_thread_start(|| {
                        // TODO: banish dpdk-sys back to  where it belongs
                        info!("initializing RTE runtime async worker thread");
                        let ret = unsafe { dpdk_sys::rte_thread_register() };
                        if ret != 0 {
                            let errno = unsafe { dpdk_sys::rte_errno_get() };
                            let msg = format!("rte thread exited with code {ret}, errno: {errno}");
                            Eal::fatal_error(msg)
                        }
                    })
                    .on_thread_stop(|| unsafe { dpdk_sys::rte_thread_unregister() })
                    .build()
                    .unwrap();
                let _guard = runtime.enter();
                runtime.block_on(async move {
                    let mut pipeline = setup();
                    let queues: Vec<_> = self
                        .devices
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
                        if *rx.borrow() {
                            info!("shutdown signal received, closing lcore {lcore_id:?}");
                            break;
                        }
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
            .unwrap();
        });
    }
}
