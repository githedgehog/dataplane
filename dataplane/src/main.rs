mod id;
mod work_queue;

use dpdk::dev::{Dev, RxOffload, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::lcore::LCoreId;
use dpdk::mem::{Pool, PoolConfig, PoolParams, RteAllocator};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, eal, socket};
use tracing::warn;

#[global_allocator]
static GLOBAL_ALLOCATOR: RteAllocator = RteAllocator::uninit();

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
        "0000:c1:00.0,dv_flow_en=1",
        "--huge-worker-stack=8192",
        "--socket-mem=8192,0,0,0",
        "--no-telemetry",
        "--iova-mode=va",
    ]);
    // let async_runtime = tokio::runtime::Builder::new_current_thread()
    //     .enable_io()
    //     .enable_time()
    //     .build()
    //     .expect("failed to async tokio runtime");

    let _devices: Vec<Dev> = eal
        .dev
        .iter()
        .map(|dev| {
            let config = dev::DevConfig {
                num_rx_queues: 2,
                num_tx_queues: 2,
                num_hairpin_queues: 0,
                rx_offloads: Some(RxOffload::temp()),
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

    // LCoreId::iter().enumerate().for_each(|(i, lcore_id)| {
    //     info!("Starting RTE Worker on {lcore_id:?}");
    //     let rx_queue = devices[0].rx_queue(RxQueueIndex(i as u16)).unwrap();
    //     let tx_queue = devices[0].tx_queue(TxQueueIndex(i as u16)).unwrap();
    //     WorkerThread::launch(lcore_id, move || loop {
    //         let mut pkts: Vec<_> = rx_queue.receive().collect();
    //         for mut pkt in pkts.iter_mut() {
    //             let Ok((mut packet, rest)) = Packet::parse(pkt.raw_data_mut()) else {
    //                 info!("failed to parse packet");
    //                 // drop(pkt);
    //                 continue;
    //             };
    //             info!("received packet: {packet:?}");
    //             packet.net.as_mut().map(|x| {
    //                 match x.value {
    //                     NetHeader::Ipv4(ref mut ip) => {
    //                         ip.source = [192, 168, 0, 1];
    //                         ip.destination = [192, 168, 0, 2];
    //                     }
    //                     NetHeader::Ipv6(ref mut ip) => {
    //                         ip.source = [
    //                             0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //                             0x00, 0x00, 0x00, 0x00, 0x01,
    //                         ];
    //                         ip.destination = [
    //                             0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //                             0x00, 0x00, 0x00, 0x00, 0x02,
    //                         ];
    //                     }
    //                 };
    //             });
    //             packet.transport.as_mut().map(|ref mut x| match x {
    //                 ParsedTransportHeader::Tcp(ref mut x) => {}
    //                 ParsedTransportHeader::Udp(ref mut x) => {}
    //                 ParsedTransportHeader::Icmpv4(ref mut x) => {}
    //                 ParsedTransportHeader::Icmpv6(ref mut x) => {
    //                     packet
    //                         .net
    //                         .as_ref()
    //                         .map(|net| match net.value {
    //                             NetHeader::Ipv4(_) => {
    //                                 debug!("got icmpv6 with IPv4 header");
    //                             }
    //                             NetHeader::Ipv6(ref ip) => {
    //                                 let mut nothing: [u8; 0] = [];
    //                                 x.value
    //                                     .update_checksum(
    //                                         ip.source,
    //                                         ip.destination,
    //                                         rest.unwrap_or(&mut nothing),
    //                                     )
    //                                     .unwrap();
    //                             }
    //                         })
    //                         .unwrap_or_else(|| debug!("failed to update icmpv6 checksum: {x:?}"));
    //                 }
    //             });
    //             packet.eth.value.destination = [0xff; 6];
    //             packet.eth.commit().unwrap();
    //             packet.net.as_mut().map(|net| net.commit());
    //             packet.transport.as_mut().map(|transport| match transport {
    //                 ParsedTransportHeader::Tcp(_) => {}
    //                 ParsedTransportHeader::Udp(_) => {}
    //                 ParsedTransportHeader::Icmpv4(_) => {}
    //                 ParsedTransportHeader::Icmpv6(x) => {
    //                     x.commit().unwrap();
    //                 }
    //             });
    //             info!("updated packet: {packet:?}");
    //
    //             // let (slice, headers) = {
    //             //     let packet = match LaxSlicedPacket::from_ethernet(pkt.raw_data_mut()) {
    //             //         Ok(packet) => packet,
    //             //         Err(len_err) => {
    //             //             error!("Failed to parse frame: {len_err:?}");
    //             //             continue;
    //             //         }
    //             //     };
    //             //     let link = packet.link.unwrap();
    //             //     let headers = link.to_header().unwrap();
    //             //     (slice, headers)
    //             // };
    //             // let (mut cursor, eth) = {
    //             //     let raw = &mut pkt.raw_data_mut()[..Ethernet2Header::LEN];
    //             //     let eth = match Ethernet2HeaderSlice::from_slice(raw) {
    //             //         Ok(eth) => eth.to_header(),
    //             //         Err(err) => {
    //             //             error!("Failed to parse Ethernet2HeaderSlice: {err:?}");
    //             //             continue;
    //             //         }
    //             //     };
    //             //     (std::io::Cursor::new(raw), eth)
    //             // };
    //             // let (mut cursor2, ip) = {
    //             //     let raw = &mut pkt.raw_data_mut()[Ethernet2Header::LEN..];
    //             //     let ip = match Ipv4HeaderSlice::from_slice(raw) {
    //             //         Ok(ip) => ip.to_header(),
    //             //         Err(err) => {
    //             //             error!("Failed to parse Ipv4HeaderSlice: {err:?}");
    //             //             continue;
    //             //         }
    //             //     };
    //             //     (std::io::Cursor::new(raw), ip)
    //             // };
    //             // eth.write(&mut cursor).unwrap();
    //
    //             // let len = eth.to_header().header_len();
    //             // let mut sliced = LaxSlicedPacket::from_ethernet(start).unwrap();
    //             // let eth_start = start.as_mut_ptr();
    //             // let eth_end = sliced
    //             //     .link
    //             //     .unwrap()
    //             //     .ether_payload()
    //             //     .unwrap()
    //             //     .payload
    //             //     .as_ptr();
    //             // let eth_len = unsafe { eth_end.offset_from(eth_start) };
    //             // let mut eth_block = std::io::Cursor::new(unsafe {
    //             //     from_raw_parts_mut(eth_start, eth_len as usize)
    //             // });
    //             // sliced.link.unwrap().to_header().unwrap().write(&mut eth_block).unwrap()
    //
    //             // match sliced.net.unwrap() {
    //             //     LaxNetSlice::Ipv4(slice) => {
    //             //     }
    //             //     LaxNetSlice::Ipv6(mut slice) => {
    //             //         let header = slice.header().to_header();
    //             //         header.write()
    //             //         slice.
    //             //     }
    //             // }
    //             // sliced.unwrap().transport.as_mut().unwrap().
    //             // let x: &mut LaxNetSlice = sliced.as_mut().unwrap().net.as_mut().unwrap();
    //             // let rest = pkt.raw_data();
    //             // let (eth, rest) = Ethernet2Header::from_slice(rest).unwrap();
    //             // match eth.ether_type {
    //             //     EtherType::IPV4 => {
    //             //         let (ipv4, rest) = Ipv4Header::from_slice(rest).unwrap();
    //             //         match ipv4.protocol {
    //             //             IpNumber::TCP => {
    //             //                 let (tcp, rest) = TcpHeader::from_slice(rest).unwrap();
    //             //             }
    //             //         }
    //             //     }
    //             // }
    //         }
    //         tx_queue.transmit(pkts);
    //     });
    // });
    std::thread::sleep(std::time::Duration::from_secs(65));
}
