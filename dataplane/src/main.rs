// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]

mod args;
mod nat;
mod pipeline;
mod vxlan;

use crate::args::{CmdArgs, Parser};
use crate::pipeline::{DynPipeline, NetworkFunction};
use crate::vxlan::{VxlanDecap, VxlanEncap};
use dpdk::dev::{Dev, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::lcore::{LCoreId, WorkerThread};
use dpdk::mem::{Mbuf, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, eal, socket};
use net::eth::Eth;
use net::eth::ethtype::EthType;
use net::eth::mac::{DestinationMac, Mac, SourceMac};
use net::headers::{Headers, Net, Transport};
use net::ip::NextHeader;
use net::ipv4::Ipv4;
use net::ipv4::addr::UnicastIpv4Addr;
use net::packet::Packet;
use net::udp::port::UdpPort;
use net::udp::{Udp, UdpEncap};
use net::vxlan::{Vni, Vxlan};
use std::net::Ipv4Addr;
use tracing::{debug, error, info, trace, warn};
// #[global_allocator]
// static GLOBAL_ALLOCATOR: RteAllocator = RteAllocator::new_uninitialized();

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
    let vxlan_decap = VxlanDecap;
    let mut encap = Headers::new(Eth::new(
        SourceMac::new(Mac([0b10, 0, 0, 0, 0, 1])).unwrap(),
        DestinationMac::new(Mac([0xa0, 0x88, 0xc2, 0x46, 0xa8, 0xdd])).unwrap(),
        EthType::IPV4,
    ));
    let mut ipv4 = Ipv4::default();
    ipv4.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 32, 53)).unwrap());
    ipv4.set_destination(Ipv4Addr::new(192, 168, 32, 53));
    ipv4.set_ttl(64);
    unsafe {
        ipv4.set_next_header(NextHeader::UDP);
    }
    encap.net = Some(Net::Ipv4(ipv4));
    let udp = Udp::new(UdpPort::new_checked(10000).unwrap(), Vxlan::PORT);
    encap.transport = Some(Transport::Udp(udp));
    encap.udp_encap = Some(UdpEncap::Vxlan(Vxlan::new(Vni::new_checked(1234).unwrap())));
    let vxlan_encap = VxlanEncap::new(encap).unwrap();
    let mut encap2 = Headers::new(Eth::new(
        SourceMac::new(Mac([0b10, 0, 0, 0, 0, 1])).unwrap(),
        DestinationMac::new(Mac([0xa0, 0x88, 0xc2, 0x46, 0xa8, 0xdd])).unwrap(),
        EthType::IPV4,
    ));
    let mut ipv4 = Ipv4::default();
    ipv4.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 55, 55)).unwrap());
    ipv4.set_destination(Ipv4Addr::new(192, 168, 32, 111));
    ipv4.set_ttl(18);
    unsafe {
        ipv4.set_next_header(NextHeader::UDP);
    }
    encap2.net = Some(Net::Ipv4(ipv4));
    let udp = Udp::new(UdpPort::new_checked(12222).unwrap(), Vxlan::PORT);
    encap2.transport = Some(Transport::Udp(udp));
    encap2.udp_encap = Some(UdpEncap::Vxlan(Vxlan::new(Vni::new_checked(5432).unwrap())));
    let vxlan_encap2 = VxlanEncap::new(encap2).unwrap();
    pipeline
        .add_stage(vxlan_decap)
        .add_stage(vxlan_encap)
        .add_stage(vxlan_encap2)
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
