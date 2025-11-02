// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK dataplane driver

#![allow(unused)]

use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;

use args::LaunchConfiguration;
use dpdk::dev::{Dev, TxOffloadConfig};
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

use crate::drivers::kernel::DriverKernel;
use crate::drivers::{Driver, Start, Started, State, Stop, Stopped};
use crate::packet_processor::start_router;
use crate::statistics::MetricsServer;

/*
#[global_allocator]
static GLOBAL_ALLOCATOR: RteAllocator = RteAllocator::new_uninitialized();
*/

pub struct Dataplane<D: Driver> {
    driver: D,
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
        )
        .expect("Failed to start gRPC server");

        let driver = match &launch_config.driver {
            args::DriverConfigSection::Dpdk(dpdk_driver_config) => {
                info!("setting up DPDK driver");
                DriverDpdk::new(dpdk_driver_config.eal_args.iter(), pipeline_factory)
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
    fn start(self) -> DriverDpdk<Started> {
        self.start_rte_workers(&self.setup_pipeline);
        DriverDpdk {
            eal: self.eal,
            devices: self.devices,
            setup_pipeline: self.setup_pipeline,
            state: Started,
        }
    }
}

impl Stop for Dataplane<DriverDpdk<Started>> {
    type Stopped = ();
    fn stop(self) -> () {
        self.driver.stop();
    }
}

impl Stop for DriverDpdk<Started> {
    type Stopped = ();
    fn stop(self) -> Self::Stopped {
        todo!()
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

fn init_devices(eal: &Eal) -> Vec<Dev> {
    // TODO: pipe in number of workers to compute correct number of queues
    eal.dev
        .iter()
        .map(|dev| {
            let config = dev::DevConfig {
                num_rx_queues: 2, // TODO: set to number of worker threads
                num_tx_queues: 2, // TODO: set to number of worker threads + 1 (for packet injection)
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

pub struct DriverDpdk<S: State> {
    eal: Eal,
    devices: Vec<Dev>,
    setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Mbuf>>,
    state: S,
}

impl Driver for DriverDpdk<Stopped> {}
impl Driver for DriverDpdk<Started> {}

impl DriverDpdk<Stopped> {
    pub(crate) fn new(
        args: impl IntoIterator<Item = impl AsRef<str>>,
        setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<Mbuf>>,
    ) -> Self {
        let eal = eal::init(args);
        let devices = init_devices(&eal);
        // this.start_rte_workers(setup_pipeline);
        DriverDpdk {
            eal,
            devices,
            setup_pipeline,
            state: Stopped,
        }
    }

    fn start_rte_workers(&self, setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<Mbuf>>) {
        LCoreId::iter().enumerate().for_each(|(i, lcore_id)| {
            info!("Starting RTE Worker on {lcore_id:?}");
            let setup = setup_pipeline.clone();
            WorkerThread::launch(lcore_id, move || {
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
            })
            .unwrap();
        });
    }
}
