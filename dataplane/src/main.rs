mod work_queue;

use blink_alloc::BlinkAlloc;
use dpdk::dev::{Dev, RxOffload, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::flow::MacAddr;
use dpdk::lcore::{LCoreId, WorkerThread};
use dpdk::mem::{AllocatorState, Mbuf, Pending, Pool, PoolConfig, PoolParams, RteAllocator};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::{dev, eal, socket};
use etherparse::checksum::u32_16bit_word::add_slice;
use etherparse::err::ip::LaxHeaderSliceError;
use etherparse::err::LenError;
use etherparse::LenSource::Ipv4HeaderTotalLen;
use etherparse::{
    ArpHardwareId, EtherPayloadSlice, EtherType, Ethernet2Header, Ethernet2HeaderSlice,
    Ethernet2Slice, Icmpv4Header, Icmpv4Slice, Icmpv6Header, Icmpv6Slice, IpHeaders, IpNumber,
    Ipv4Header, Ipv4HeaderSlice, Ipv6Header, Ipv6HeaderSlice, LaxIpSlice, LaxNetSlice,
    LaxPacketHeaders, LaxPayloadSlice, LaxSlicedPacket, NetHeaders, TcpHeader, TcpHeaderSlice,
    TcpSlice, TransportHeader, TransportSlice, UdpHeader, UdpHeaderSlice,
};
use net::eth::Mac;
use net::packet::{PacketHeader, PacketHeader2};
use std::alloc::System;
use std::array::TryFromSliceError;
use std::cell::Cell;
use std::env;
use std::ffi::{CStr, OsStr};
use std::hash::{Hash, Hasher};
use std::io::{Cursor, Read};
use std::mem::ManuallyDrop;
use std::ptr::{copy_nonoverlapping, NonNull};
use std::slice::{from_raw_parts, from_raw_parts_mut};
use tracing::{debug, error, info, warn};

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

    let devices: Vec<Dev> = eal
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

    LCoreId::iter().enumerate().for_each(|(i, lcore_id)| {
        info!("Starting RTE Worker on {lcore_id:?}");
        let rx_queue = devices[0].rx_queue(RxQueueIndex(i as u16)).unwrap();
        let tx_queue = devices[0].tx_queue(TxQueueIndex(i as u16)).unwrap();
        WorkerThread::launch(lcore_id, move || loop {
            let mut pkts: Vec<_> = rx_queue.receive().collect();
            for mut pkt in pkts.iter_mut() {
                let Ok((mut packet, rest)) = Packet::parse(pkt.raw_data_mut()) else {
                    info!("failed to parse packet");
                    // drop(pkt);
                    continue;
                };
                info!("received packet: {packet:?}");
                packet.net.as_mut().map(|x| {
                    match x.value {
                        NetHeader::Ipv4(ref mut ip) => {
                            ip.source = [192, 168, 0, 1];
                            ip.destination = [192, 168, 0, 2];
                        }
                        NetHeader::Ipv6(ref mut ip) => {
                            ip.source = [
                                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x01,
                            ];
                            ip.destination = [
                                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x02,
                            ];
                        }
                    };
                });
                packet.transport.as_mut().map(|ref mut x| match x {
                    ParsedTransportHeader::Tcp(ref mut x) => {}
                    ParsedTransportHeader::Udp(ref mut x) => {}
                    ParsedTransportHeader::Icmpv4(ref mut x) => {}
                    ParsedTransportHeader::Icmpv6(ref mut x) => {
                        packet
                            .net
                            .as_ref()
                            .map(|net| match net.value {
                                NetHeader::Ipv4(_) => {
                                    debug!("got icmpv6 with IPv4 header");
                                }
                                NetHeader::Ipv6(ref ip) => {
                                    let mut nothing: [u8; 0] = [];
                                    x.value
                                        .update_checksum(
                                            ip.source,
                                            ip.destination,
                                            rest.unwrap_or(&mut nothing),
                                        )
                                        .unwrap();
                                }
                            })
                            .unwrap_or_else(|| debug!("failed to update icmpv6 checksum: {x:?}"));
                    }
                });
                packet.eth.value.destination = [0xff; 6];
                packet.eth.commit().unwrap();
                packet.net.as_mut().map(|net| net.commit());
                packet.transport.as_mut().map(|transport| match transport {
                    ParsedTransportHeader::Tcp(_) => {}
                    ParsedTransportHeader::Udp(_) => {}
                    ParsedTransportHeader::Icmpv4(_) => {}
                    ParsedTransportHeader::Icmpv6(x) => {
                        x.commit().unwrap();
                    }
                });
                info!("updated packet: {packet:?}");

                // let (slice, headers) = {
                //     let packet = match LaxSlicedPacket::from_ethernet(pkt.raw_data_mut()) {
                //         Ok(packet) => packet,
                //         Err(len_err) => {
                //             error!("Failed to parse frame: {len_err:?}");
                //             continue;
                //         }
                //     };
                //     let link = packet.link.unwrap();
                //     let headers = link.to_header().unwrap();
                //     (slice, headers)
                // };
                // let (mut cursor, eth) = {
                //     let raw = &mut pkt.raw_data_mut()[..Ethernet2Header::LEN];
                //     let eth = match Ethernet2HeaderSlice::from_slice(raw) {
                //         Ok(eth) => eth.to_header(),
                //         Err(err) => {
                //             error!("Failed to parse Ethernet2HeaderSlice: {err:?}");
                //             continue;
                //         }
                //     };
                //     (std::io::Cursor::new(raw), eth)
                // };
                // let (mut cursor2, ip) = {
                //     let raw = &mut pkt.raw_data_mut()[Ethernet2Header::LEN..];
                //     let ip = match Ipv4HeaderSlice::from_slice(raw) {
                //         Ok(ip) => ip.to_header(),
                //         Err(err) => {
                //             error!("Failed to parse Ipv4HeaderSlice: {err:?}");
                //             continue;
                //         }
                //     };
                //     (std::io::Cursor::new(raw), ip)
                // };
                // eth.write(&mut cursor).unwrap();

                // let len = eth.to_header().header_len();
                // let mut sliced = LaxSlicedPacket::from_ethernet(start).unwrap();
                // let eth_start = start.as_mut_ptr();
                // let eth_end = sliced
                //     .link
                //     .unwrap()
                //     .ether_payload()
                //     .unwrap()
                //     .payload
                //     .as_ptr();
                // let eth_len = unsafe { eth_end.offset_from(eth_start) };
                // let mut eth_block = std::io::Cursor::new(unsafe {
                //     from_raw_parts_mut(eth_start, eth_len as usize)
                // });
                // sliced.link.unwrap().to_header().unwrap().write(&mut eth_block).unwrap()

                // match sliced.net.unwrap() {
                //     LaxNetSlice::Ipv4(slice) => {
                //     }
                //     LaxNetSlice::Ipv6(mut slice) => {
                //         let header = slice.header().to_header();
                //         header.write()
                //         slice.
                //     }
                // }
                // sliced.unwrap().transport.as_mut().unwrap().
                // let x: &mut LaxNetSlice = sliced.as_mut().unwrap().net.as_mut().unwrap();
                // let rest = pkt.raw_data();
                // let (eth, rest) = Ethernet2Header::from_slice(rest).unwrap();
                // match eth.ether_type {
                //     EtherType::IPV4 => {
                //         let (ipv4, rest) = Ipv4Header::from_slice(rest).unwrap();
                //         match ipv4.protocol {
                //             IpNumber::TCP => {
                //                 let (tcp, rest) = TcpHeader::from_slice(rest).unwrap();
                //             }
                //         }
                //     }
                // }
            }
            tx_queue.transmit(pkts);
        });
    });
    std::thread::sleep(std::time::Duration::from_secs(65));
}

#[derive(thiserror::Error, Debug)]
#[error("expected at least {expected} bytes, got {actual}")]
pub struct LengthError {
    expected: usize,
    actual: usize,
}

pub trait HeaderLength {
    fn header_length(&self) -> usize;
}

impl HeaderLength for Ethernet2Header {
    fn header_length(&self) -> usize {
        Ethernet2Header::LEN
    }
}

pub trait Serialize {
    type Error;
    fn serialize<'buf>(&self, slice: &'buf mut [u8])
        -> Result<Option<&'buf mut [u8]>, Self::Error>;
}

impl Serialize for Ethernet2Header {
    type Error = LengthError;
    /// TODO: checksum logic
    fn serialize<'buf>(
        &self,
        slice: &'buf mut [u8],
    ) -> Result<Option<&'buf mut [u8]>, LengthError> {
        let len = slice.len();
        let rest = self.write_to_slice(slice).map_err(|_| LengthError {
            expected: Ethernet2Header::LEN,
            actual: len,
        })?;
        if rest.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rest))
        }
    }
}

impl Serialize for Ipv4Header {
    type Error = LengthError;
    /// TODO: checksum logic
    fn serialize<'buf>(
        &self,
        slice: &'buf mut [u8],
    ) -> Result<Option<&'buf mut [u8]>, LengthError> {
        let len = slice.len();
        if len < self.header_len() {
            return Err(LengthError {
                expected: self.header_len(),
                actual: len,
            });
        }
        let (slice, rest) = slice.split_at_mut(self.header_len());
        let mut cursor = Cursor::new(slice);
        self.write(&mut cursor).map_err(|_| LengthError {
            expected: self.header_len(),
            actual: len,
        })?;

        if rest.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rest))
        }
    }
}

impl Serialize for Ipv6Header {
    type Error = LengthError;

    fn serialize<'buf>(
        &self,
        slice: &'buf mut [u8],
    ) -> Result<Option<&'buf mut [u8]>, Self::Error> {
        let len = slice.len();
        if len < self.header_len() {
            return Err(LengthError {
                expected: self.header_len(),
                actual: len,
            });
        }
        let (slice, rest) = slice.split_at_mut(self.header_len());
        let mut cursor = Cursor::new(slice);
        self.write(&mut cursor).map_err(|_| LengthError {
            expected: self.header_len(),
            actual: len,
        })?;

        if rest.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rest))
        }
    }
}

impl NetHeader {
    fn header_len(&self) -> usize {
        match self {
            NetHeader::Ipv4(header) => header.header_len(),
            NetHeader::Ipv6(header) => header.header_len(),
        }
    }

    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        match self {
            NetHeader::Ipv4(ip) => ip.write(writer),
            NetHeader::Ipv6(ip) => ip.write(writer),
        }
    }
}

impl Serialize for NetHeader {
    type Error = LengthError;

    fn serialize<'buf>(
        &self,
        slice: &'buf mut [u8],
    ) -> Result<Option<&'buf mut [u8]>, Self::Error> {
        let len = slice.len();
        if len < self.header_len() {
            return Err(LengthError {
                expected: self.header_len(),
                actual: len,
            });
        }
        let (slice, rest) = slice.split_at_mut(self.header_len());
        let mut cursor = Cursor::new(slice);
        self.write(&mut cursor).map_err(|_| LengthError {
            expected: self.header_len(),
            actual: len,
        })?;

        if rest.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rest))
        }
    }
}

impl Serialize for TcpHeader {
    type Error = LengthError;
    /// TODO: checksum logic
    fn serialize<'buf>(
        &self,
        slice: &'buf mut [u8],
    ) -> Result<Option<&'buf mut [u8]>, LengthError> {
        let len = slice.len();
        if len < self.header_len() {
            return Err(LengthError {
                expected: self.header_len(),
                actual: len,
            });
        }
        let (slice, rest) = slice.split_at_mut(self.header_len());
        let mut cursor = Cursor::new(slice);
        self.write(&mut cursor).map_err(|_| LengthError {
            expected: self.header_len(),
            actual: len,
        })?;
        if rest.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rest))
        }
    }
}

impl Serialize for Icmpv6Header {
    type Error = LengthError;

    fn serialize<'buf>(
        &self,
        slice: &'buf mut [u8],
    ) -> Result<Option<&'buf mut [u8]>, Self::Error> {
        if slice.len() < self.header_len() {
            return Err(LengthError {
                expected: self.header_len(),
                actual: slice.len(),
            });
        }
        let (slice, rest) = split(slice, self.header_len())?;
        let mut cursor = Cursor::new(slice);
        self.write(&mut cursor).unwrap();
        Ok(rest)
    }
}

#[derive(Debug)]
pub struct Parsed<'buf, T> {
    value: T,
    buf: &'buf mut [u8],
}

#[derive(Debug)]
pub enum NetHeader {
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
}

#[derive(Debug)]
pub enum ParsedTransportHeader<'buf> {
    Tcp(Parsed<'buf, TcpHeader>),
    Udp(Parsed<'buf, UdpHeader>),
    Icmpv4(Parsed<'buf, Icmpv4Header>),
    Icmpv6(Parsed<'buf, Icmpv6Header>),
}

#[derive(Debug)]
pub struct Packet<'buf> {
    pub raw: NonNull<[u8]>,
    pub eth: Parsed<'buf, Ethernet2Header>,
    pub net: Option<Parsed<'buf, NetHeader>>,
    pub transport: Option<ParsedTransportHeader<'buf>>,
}

impl<'buf> Parse<'buf> for Parsed<'buf, NetHeader> {
    type Error = Option<LaxHeaderSliceError>;

    fn parse(raw: &'buf mut [u8]) -> Result<(Self, Option<&'buf mut [u8]>), Self::Error>
    where
        Self: Sized,
    {
        let (parsed, err) = LaxIpSlice::from_slice(raw).map_err(|e| Some(e))?;
        if let Some(_) = err {
            return Err(None); // TODO: this is silly error handling
        }
        match parsed {
            LaxIpSlice::Ipv4(parsed) => {
                let parsed_len = parsed.header().slice().len();
                let header = NetHeader::Ipv4(parsed.header().to_header());
                let (buf, rest) = split(raw, parsed_len).unwrap();
                Ok((Parsed { value: header, buf }, rest))
            }
            LaxIpSlice::Ipv6(parsed) => {
                let parsed_len = parsed.header().slice().len();
                let header = NetHeader::Ipv6(parsed.header().to_header());
                let (buf, rest) = split(raw, parsed_len).unwrap();
                Ok((Parsed { value: header, buf }, rest))
            }
        }
    }
}

impl<'buf> Parse<'buf> for Packet<'buf> {
    type Error = ();

    fn parse(raw: &'buf mut [u8]) -> Result<(Self, Option<&'buf mut [u8]>), Self::Error>
    where
        Self: Sized,
    {
        let mut raw2 =
            unsafe { NonNull::new_unchecked(from_raw_parts_mut(raw.as_mut_ptr(), raw.len())) };
        let (eth, rest) =
            Parsed::<'buf, Ethernet2Header>::parse(unsafe { raw.as_mut() }).map_err(|_| ())?;
        // TODO: it is kinda silly to accept a packet which ONLY contains an eth header.
        // Consider changing this to return an error here.
        let Some(rest) = rest else {
            return Ok((
                Self {
                    raw: raw2,
                    eth,
                    net: None,
                    transport: None,
                },
                None,
            ));
        };
        let (net, rest) = Parsed::<'buf, NetHeader>::parse(rest).map_err(|_| ())?;
        let Some(rest) = rest else {
            return Ok((
                Self {
                    raw: raw2,
                    eth,
                    net: Some(net),
                    transport: None,
                },
                None,
            ));
        };
        let next_header = match &net.value {
            NetHeader::Ipv4(ip) => ip.protocol,
            NetHeader::Ipv6(ip) => ip.next_header,
        };
        let (transport, rest) = match next_header {
            IpNumber::TCP => {
                let (header, rest) = Parsed::<'buf, TcpHeader>::parse(rest).map_err(|_| ())?;
                (Some(ParsedTransportHeader::Tcp(header)), rest)
            }
            IpNumber::UDP => {
                let (header, rest) = Parsed::<'buf, UdpHeader>::parse(rest).map_err(|_| ())?;
                (Some(ParsedTransportHeader::Udp(header)), rest)
            }
            IpNumber::ICMP => {
                let (header, rest) = Parsed::<'buf, Icmpv4Header>::parse(rest).map_err(|_| ())?;
                (Some(ParsedTransportHeader::Icmpv4(header)), rest)
            }
            IpNumber::IPV6_ICMP => {
                let (header, rest) = Parsed::<'buf, Icmpv6Header>::parse(rest).map_err(|_| ())?;
                (Some(ParsedTransportHeader::Icmpv6(header)), rest)
            }
            _ => {
                debug!("Unknown transport layer: {next_header:?}",);
                (None, Some(rest))
            }
        };

        Ok((
            Self {
                raw: raw2,
                eth,
                net: Some(net),
                transport,
            },
            rest,
        ))
    }
}

// pub struct CustodyCursor<'buf, T> {
//     position: usize,
//     buf: &'buf mut [u8],
// }

pub trait Parse<'buf> {
    type Error;
    fn parse(raw: &'buf mut [u8]) -> Result<(Self, Option<&'buf mut [u8]>), Self::Error>
    where
        Self: Sized;
}

pub trait Commit {
    type Error;
    fn commit(&mut self) -> Result<(), Self::Error>;
}

fn split(slice: &mut [u8], len: usize) -> Result<(&mut [u8], Option<&mut [u8]>), LengthError> {
    if slice.len() < len {
        return Err(LengthError {
            expected: len,
            actual: slice.len(),
        });
    }
    let (slice, rest) = slice.split_at_mut(len);
    if rest.is_empty() {
        Ok((slice, None))
    } else {
        Ok((slice, Some(rest)))
    }
}

impl<'buf> Parse<'buf> for Parsed<'buf, Ethernet2Header> {
    type Error = LengthError;

    fn parse(raw: &'buf mut [u8]) -> Result<(Self, Option<&'buf mut [u8]>), Self::Error>
    where
        Self: Sized,
    {
        let (buf, rest) = split(raw, Ethernet2Header::LEN)?;
        // SAFETY: safe as we just checked that the slice has the correct length on the line above.
        let value = Ethernet2Header::from_bytes(unsafe { buf.try_into().unwrap_unchecked() });
        Ok((Parsed { value, buf }, rest))
    }
}

impl<'buf> Parse<'buf> for Parsed<'buf, Ipv4Header> {
    type Error = etherparse::err::ipv4::HeaderSliceError;

    fn parse(raw: &mut [u8]) -> Result<(Self, Option<&mut [u8]>), Self::Error>
    where
        Self: Sized,
    {
        let hslice = Ipv4HeaderSlice::from_slice(raw)?;
        let len = hslice.slice().len();
        let start = hslice.slice().as_ptr() as *mut u8;
        let buf = unsafe { from_raw_parts_mut(start, len) };
        let value = hslice.to_header();
        let rest = if raw.len() > len {
            Some(&mut raw[len..])
        } else {
            None
        };
        Ok((Parsed { value, buf }, rest))
    }
}

impl<'buf> Parse<'buf> for Parsed<'buf, Ipv6Header> {
    type Error = etherparse::err::ipv6::HeaderSliceError;

    fn parse(raw: &mut [u8]) -> Result<(Self, Option<&mut [u8]>), Self::Error>
    where
        Self: Sized,
    {
        let hslice = Ipv6HeaderSlice::from_slice(raw)?;
        let len = hslice.slice().len();
        let start = hslice.slice().as_ptr() as *mut u8;
        let buf = unsafe { from_raw_parts_mut(start, len) };
        let value = hslice.to_header();
        let rest = if raw.len() > len {
            Some(&mut raw[len..])
        } else {
            None
        };
        Ok((Parsed { value, buf }, rest))
    }
}

impl<'buf> Parse<'buf> for Parsed<'buf, TcpHeader> {
    type Error = etherparse::err::tcp::HeaderSliceError;

    fn parse(raw: &'buf mut [u8]) -> Result<(Self, Option<&'buf mut [u8]>), Self::Error>
    where
        Self: Sized,
    {
        let (value, len) = {
            let hslice = TcpHeaderSlice::from_slice(raw)?;
            let len = hslice.slice().len();
            (hslice.to_header(), len)
        };
        // SAFETY: we just read the raw buffer to at least the length of the TCP header, so
        // it is impossible that the buffer is not long enough to contain itself.
        let (buf, rest) = unsafe { split(raw, len).unwrap_unchecked() };
        Ok((Parsed { value, buf }, rest))
    }
}

impl<'buf> Parse<'buf> for Parsed<'buf, UdpHeader> {
    type Error = LenError;

    fn parse(raw: &'buf mut [u8]) -> Result<(Self, Option<&'buf mut [u8]>), LenError>
    where
        Self: Sized,
    {
        let (value, len) = {
            let hslice = UdpHeaderSlice::from_slice(raw)?;
            let len = hslice.slice().len();
            (hslice.to_header(), len)
        };
        // SAFETY: we just read the raw buffer to at least the length of the TCP header, so
        // it is impossible that the buffer is not long enough to contain itself.
        let (buf, rest) = unsafe { split(raw, len).unwrap_unchecked() };
        Ok((Parsed { value, buf }, rest))
    }
}

impl<'buf> Parse<'buf> for Parsed<'buf, Icmpv4Header> {
    type Error = LenError;

    fn parse(raw: &'buf mut [u8]) -> Result<(Self, Option<&'buf mut [u8]>), Self::Error>
    where
        Self: Sized,
    {
        let (value, len) = {
            let hslice = Icmpv4Slice::from_slice(raw)?;
            (hslice.header(), hslice.slice().len())
        };
        // SAFETY: we just read the raw buffer to at least the length of the TCP header, so
        // it is impossible that the buffer is not long enough to contain itself.
        let (buf, rest) = unsafe { split(raw, len).unwrap_unchecked() };
        Ok((Parsed { value, buf }, rest))
    }
}

impl<'buf> Parse<'buf> for Parsed<'buf, Icmpv6Header> {
    type Error = LenError;

    fn parse(raw: &'buf mut [u8]) -> Result<(Self, Option<&'buf mut [u8]>), Self::Error>
    where
        Self: Sized,
    {
        let (value, len) = {
            let hslice = Icmpv6Slice::from_slice(raw)?;
            (hslice.header(), hslice.header_len())
        };
        // SAFETY: we just read the raw buffer to at least the length of the TCP header, so
        // it is impossible that the buffer is not long enough to contain itself.
        let (buf, rest) = unsafe { split(raw, len).unwrap_unchecked() };
        Ok((Parsed { value, buf }, rest))
    }
}

impl<T> Commit for Parsed<'_, T>
where
    T: Serialize,
{
    type Error = <T as Serialize>::Error;

    fn commit(&mut self) -> Result<(), Self::Error> {
        self.value.serialize(self.buf).map(|_| ())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn tcp_builder() -> Vec<u8> {
        let builder =
            etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                .ipv4([192, 168, 32, 53], [169, 254, 32, 53], 64)
                .tcp(10, 20, 30, 40);
        let mut payload = [0; 500];
        let packet_size = builder.size(payload.len());
        let mut buffer = Vec::with_capacity(packet_size);
        builder.write(&mut buffer, &payload).unwrap();
        buffer
    }

    #[test]
    fn test_parse() {
        let mut packet = tcp_builder();
        let (parsed, Some(rest)) =
            Parsed::<'_, Ethernet2Header>::parse(packet.as_mut_slice()).unwrap()
        else {
            panic!("failed to parse rest of packet");
        };
        assert_eq!(parsed.value.ether_type, EtherType::IPV4);
        assert_eq!(parsed.value.source, [1, 2, 3, 4, 5, 6]);
        assert_eq!(parsed.value.destination, [7, 8, 9, 10, 11, 12]);
        assert_eq!(parsed.buf.len(), 14);
        let (parsed, Some(rest)) = Parsed::<'_, Ipv4Header>::parse(rest).unwrap() else {
            panic!("failed to parse rest of packet");
        };
        assert_eq!(parsed.value.source, [192, 168, 32, 53]);
        assert_eq!(parsed.value.destination, [169, 254, 32, 53]);
        assert_eq!(parsed.value.protocol, IpNumber::TCP);
        assert_eq!(parsed.value.time_to_live, 64);
        let (parsed, Some(rest)) = Parsed::<'_, TcpHeader>::parse(rest).unwrap() else {
            panic!("failed to parse rest of packet");
        };
        assert_eq!(parsed.value.source_port, 10);
        assert_eq!(parsed.value.destination_port, 20);
        assert_eq!(parsed.value.sequence_number, 30);
        assert_eq!(parsed.value.window_size, 40);
        assert_eq!(rest.len(), 500);
        assert_eq!(rest, &[0; 500]);
    }

    #[test]
    fn test_commit() {
        let mut packet = tcp_builder();
        let (mut eth, Some(rest)) =
            Parsed::<'_, Ethernet2Header>::parse(packet.as_mut_slice()).unwrap()
        else {
            panic!("failed to parse rest of packet");
        };
        assert_eq!(eth.value.ether_type, EtherType::IPV4);
        assert_eq!(eth.value.source, [1, 2, 3, 4, 5, 6]);
        assert_eq!(eth.value.destination, [7, 8, 9, 10, 11, 12]);
        assert_eq!(eth.buf.len(), 14);
        let (mut ip, Some(rest)) = Parsed::<'_, Ipv4Header>::parse(rest).unwrap() else {
            panic!("failed to parse rest of packet");
        };
        assert_eq!(ip.value.source, [192, 168, 32, 53]);
        assert_eq!(ip.value.destination, [169, 254, 32, 53]);
        assert_eq!(ip.value.protocol, IpNumber::TCP);
        assert_eq!(ip.value.time_to_live, 64);
        let (mut tcp, Some(rest)) = Parsed::<'_, TcpHeader>::parse(rest).unwrap() else {
            panic!("failed to parse rest of packet");
        };
        assert_eq!(tcp.value.source_port, 10);
        assert_eq!(tcp.value.destination_port, 20);
        assert_eq!(tcp.value.sequence_number, 30);
        assert_eq!(tcp.value.window_size, 40);
        assert_eq!(rest.len(), 500);
        assert_eq!(rest, &[0; 500]);
        eth.value.source = [6, 5, 4, 3, 2, 1];
        eth.value.destination = [10, 9, 8, 7, 6, 5];
        ip.value.source = [10, 9, 8, 7];
        ip.value.destination = [7, 8, 9, 10];
        ip.value.time_to_live -= 1;
        tcp.value.sequence_number += 1;
        tcp.value.source_port = 90;
        tcp.value.destination_port = 100;
        eth.commit().unwrap();
        ip.commit().unwrap();
        tcp.commit().unwrap();
        let (mut eth, Some(rest)) =
            Parsed::<'_, Ethernet2Header>::parse(packet.as_mut_slice()).unwrap()
        else {
            panic!("failed to parse rest of packet");
        };
        assert_eq!(eth.value.ether_type, EtherType::IPV4);
        assert_eq!(eth.value.source, [6, 5, 4, 3, 2, 1]);
        assert_eq!(eth.value.destination, [10, 9, 8, 7, 6, 5]);
        assert_eq!(eth.buf.len(), 14);
        let (mut ip, Some(rest)) = Parsed::<'_, Ipv4Header>::parse(rest).unwrap() else {
            panic!("failed to parse rest of packet");
        };
        assert_eq!(ip.value.source, [10, 9, 8, 7]);
        assert_eq!(ip.value.destination, [7, 8, 9, 10]);
        assert_eq!(ip.value.protocol, IpNumber::TCP);
        assert_eq!(ip.value.time_to_live, 63);
        let (mut tcp, Some(rest)) = Parsed::<'_, TcpHeader>::parse(rest).unwrap() else {
            panic!("failed to parse rest of packet");
        };
        assert_eq!(tcp.value.source_port, 90);
        assert_eq!(tcp.value.destination_port, 100);
        assert_eq!(tcp.value.sequence_number, 31);
        assert_eq!(tcp.value.window_size, 40);
        assert_eq!(rest.len(), 500);
        assert_eq!(rest, &[0; 500]);
    }
}
