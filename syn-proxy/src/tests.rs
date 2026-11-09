// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Connections through the SYN proxy stages, with the flow lookup and flow tracking stages around
//! them, as in the gateway's pipeline.

use crate::{SynCookieChecker, SynProxy, SynProxyControl, SynProxyMode};
use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicBool, Ordering};
use flow_entry::flow_table::{FlowLookup, FlowTable, WorkerFlowTable};
use nat::FlowTracker;
use net::buffer::{PacketBufferMut, TestBuffer};
use net::headers::builder::HeaderStack;
use net::headers::{TryIpv4Mut, TryTcp};
use net::packet::test_utils::assert_checksum_current_or_refresh_requested;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::tcp::{Tcp, TcpFlags, TcpMss, TcpOption};
use net::vxlan::Vni;
use pipeline::{DynPipeline, NetworkFunction};

const CLIENT: &str = "10.0.0.1";
const SERVER: &str = "10.1.0.2";
const CLIENT_PORT: u16 = 40000;
const SERVER_PORT: u16 = 80;
const CLIENT_ISN: u32 = 1000;
const SERVER_ISN: u32 = 0xffff_fff0; // wraps around while the server sends
const MSS: u16 = 1460;

fn vpcd(vni: u32) -> VpcDiscriminant {
    VpcDiscriminant::from_vni(Vni::new_checked(vni).unwrap())
}

fn client_vpcd() -> VpcDiscriminant {
    vpcd(100)
}

fn server_vpcd() -> VpcDiscriminant {
    vpcd(200)
}

// Stand-in for the flow filter: route packets of the client to the server's VPC and back.
struct Peering;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Peering {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        for packet in burst.iter_mut() {
            let meta = packet.meta_mut();
            if meta.dst_vpcd.is_none() {
                meta.dst_vpcd = if meta.src_vpcd == Some(client_vpcd()) {
                    Some(server_vpcd())
                } else {
                    Some(client_vpcd())
                };
            }
        }
    }
}

// Stand-in for the ACL stage, between the two stages of the proxy: drop all packets if told so.
struct Acl {
    drops: Arc<AtomicBool>,
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Acl {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        if self.drops.load(Ordering::Relaxed) {
            for packet in burst.iter_mut() {
                packet.done(DoneReason::AclDropped);
            }
        }
    }
}

struct Gateway {
    proxy: SynProxyControl,
    table: Arc<FlowTable>,
    acl_drops: Arc<AtomicBool>,
    pipeline: DynPipeline<'static, TestBuffer>,
}

impl Gateway {
    fn new() -> Self {
        let proxy = SynProxyControl::new();
        proxy.set_mode(SynProxyMode::On);
        let table = Arc::new(FlowTable::default());
        let acl_drops = Arc::new(AtomicBool::new(false));
        let pipeline = DynPipeline::new()
            .add_stage(FlowLookup::new("flow-lookup", table.clone()))
            .add_stage(Peering)
            .add_stage(SynCookieChecker::new("syn-cookie-checker", proxy.clone()))
            .add_stage(Acl {
                drops: acl_drops.clone(),
            })
            .add_stage(SynProxy::new("syn-proxy", proxy.clone()))
            .add_stage(FlowTracker::new(
                "flow-tracker",
                WorkerFlowTable::new(table.clone()),
            ));
        Self {
            proxy,
            table,
            acl_drops,
            pipeline,
        }
    }

    // Process a packet, and return what the gateway sends, without dropped packets.
    fn process(&mut self, packet: Packet<TestBuffer>) -> Vec<Packet<TestBuffer>> {
        let out: Vec<_> = self.pipeline.process([packet]).collect();
        for packet in &out {
            assert_checksum_current_or_refresh_requested(packet);
        }
        out.into_iter()
            .filter(|packet| {
                packet.get_done().is_none() || packet.get_done() == Some(DoneReason::Delivered)
            })
            .collect()
    }

    // Process a packet, and return the single packet the gateway sends.
    fn process_one(&mut self, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        let mut out = self.process(packet);
        assert_eq!(out.len(), 1, "expected one packet, got {out:?}");
        out.remove(0)
    }

    fn flows(&self) -> usize {
        self.table.len().unwrap()
    }
}

fn segment(
    from_client: bool,
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    window: u16,
    options: &[TcpOption],
    data: &[u8],
) -> Packet<TestBuffer> {
    let (src, dst, sport, dport, vpcd) = if from_client {
        (CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, client_vpcd())
    } else {
        (SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, server_vpcd())
    };
    let mut packet = HeaderStack::new()
        .eth_macs([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4_addrs(src, dst)
        .tcp_ports(sport, dport)
        .with(|tcp| {
            tcp.set_flags(flags)
                .set_sequence_number(seq)
                .set_ack_number(ack)
                .set_window_size(window)
                .set_options(options)
                .unwrap();
        })
        .build_packet_with_payload(data)
        .unwrap();
    packet.meta_mut().src_vpcd = Some(vpcd);
    packet.meta_mut().set_overlay(true);
    packet
}

fn client_syn() -> Packet<TestBuffer> {
    let options = [
        TcpOption::Mss(TcpMss::new(MSS).unwrap()),
        TcpOption::SackPermitted,
        TcpOption::WindowScale(7),
    ];
    segment(true, TcpFlags::SYN, CLIENT_ISN, 0, 64000, &options, &[])
}

fn tcp(packet: &Packet<TestBuffer>) -> &Tcp {
    packet.try_tcp().unwrap()
}

fn assert_segment(
    packet: &Packet<TestBuffer>,
    to_client: bool,
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    window: u16,
) {
    let (src, dst, vpcd) = if to_client {
        (SERVER, CLIENT, client_vpcd())
    } else {
        (CLIENT, SERVER, server_vpcd())
    };
    assert_eq!(packet.ip_source(), Some(src.parse().unwrap()));
    assert_eq!(packet.ip_destination(), Some(dst.parse().unwrap()));
    assert_eq!(packet.meta().dst_vpcd, Some(vpcd));
    let tcp = tcp(packet);
    assert_eq!(tcp.flags(), flags, "{tcp:?}");
    assert_eq!(tcp.sequence_number(), seq, "{tcp:?}");
    assert_eq!(tcp.ack_number(), ack, "{tcp:?}");
    assert_eq!(tcp.window_size(), window, "{tcp:?}");
}

// The ACK with which the client echoes the cookie.
fn client_ack(cookie: u32) -> Packet<TestBuffer> {
    segment(
        true,
        TcpFlags::ACK,
        CLIENT_ISN + 1,
        cookie + 1,
        512,
        &[],
        &[],
    )
}

// The proxy answers the SYN with a cookie, and creates no flow. Return the cookie.
fn handshake_with_client(gw: &mut Gateway) -> u32 {
    let syn_ack = gw.process_one(client_syn());
    let cookie = tcp(&syn_ack).sequence_number();
    let ack = CLIENT_ISN + 1;
    assert_segment(
        &syn_ack,
        true,
        TcpFlags::SYN | TcpFlags::ACK,
        cookie,
        ack,
        0,
    );
    assert_eq!(tcp(&syn_ack).mss(), Some(TcpMss::new(MSS).unwrap()));
    assert!(syn_ack.meta().flow_info.is_none());
    assert_eq!(gw.flows(), 0);
    cookie
}

// The client echoes the cookie, and the proxy sends the SYN to the server, with flows.
fn handshake_with_server(gw: &mut Gateway, cookie: u32) {
    let syn = gw.process_one(client_ack(cookie));
    assert_segment(&syn, false, TcpFlags::SYN, CLIENT_ISN, 0, 512);
    assert_eq!(tcp(&syn).mss(), Some(TcpMss::new(MSS).unwrap()));
    assert_eq!(gw.flows(), 2);
}

#[tokio::test]
async fn connection_through_the_proxy() {
    let mut gw = Gateway::new();
    let cookie = handshake_with_client(&mut gw);
    handshake_with_server(&mut gw, cookie);

    // The server accepts: the proxy acknowledges its SYN-ACK, and gives its window to the client
    let syn_ack = segment(
        false,
        TcpFlags::SYN | TcpFlags::ACK,
        SERVER_ISN,
        CLIENT_ISN + 1,
        30000,
        &[TcpOption::Mss(TcpMss::new(MSS).unwrap())],
        &[],
    );
    let out = gw.process(syn_ack);
    assert_eq!(out.len(), 2, "{out:?}");
    let ack = CLIENT_ISN + 1;
    assert_segment(&out[0], true, TcpFlags::ACK, cookie + 1, ack, 30000);
    let server_ack = SERVER_ISN.wrapping_add(1);
    assert_segment(&out[1], false, TcpFlags::ACK, ack, server_ack, 512);
    assert_eq!(gw.proxy.counters().connections.load(Ordering::Relaxed), 1);

    // Data from the client: its acknowledgment number moves to the server's sequence space
    let data = segment(true, TcpFlags::ACK, ack, cookie + 1, 512, &[], b"GET /");
    let out = gw.process_one(data);
    assert_segment(&out, false, TcpFlags::ACK, ack, server_ack, 512);
    assert_eq!(out.payload_len(), 5);

    // Data from the server: its sequence number moves to the client's sequence space
    let flags = TcpFlags::ACK | TcpFlags::PSH;
    let data = segment(
        false,
        flags,
        server_ack,
        ack + 5,
        30000,
        &[],
        b"200 OK, and more",
    );
    let out = gw.process_one(data);
    assert_segment(&out, true, flags, cookie + 1, ack + 5, 30000);
    let data = segment(
        false,
        flags,
        server_ack.wrapping_add(16),
        ack + 5,
        30000,
        &[],
        b"!",
    );
    let out = gw.process_one(data);
    assert_segment(&out, true, flags, cookie + 17, ack + 5, 30000);

    // Our ACK to the server got lost: the server sends its SYN-ACK again, and we answer again
    let syn_ack = segment(
        false,
        TcpFlags::SYN | TcpFlags::ACK,
        SERVER_ISN,
        CLIENT_ISN + 1,
        30000,
        &[],
        &[],
    );
    let out = gw.process_one(syn_ack);
    assert_segment(&out, false, TcpFlags::ACK, ack, server_ack, 512);
}

#[tokio::test]
async fn server_refuses_connection() {
    let mut gw = Gateway::new();
    let cookie = handshake_with_client(&mut gw);
    handshake_with_server(&mut gw, cookie);

    let flags = TcpFlags::RST | TcpFlags::ACK;
    let rst = segment(false, flags, 0, CLIENT_ISN + 1, 0, &[], &[]);
    let rst = gw.process_one(rst);
    assert_segment(&rst, true, TcpFlags::RST, cookie + 1, 0, 0);
    let refused = &gw.proxy.counters().connections_refused;
    assert_eq!(refused.load(Ordering::Relaxed), 1);
}

// While the server has not answered, packets from the client make the proxy send the SYN again,
// and unexpected packets from the server go nowhere.
#[tokio::test]
async fn pending_connection() {
    let mut gw = Gateway::new();
    let cookie = handshake_with_client(&mut gw);
    handshake_with_server(&mut gw, cookie);

    let probe = segment(true, TcpFlags::ACK, CLIENT_ISN, cookie + 1, 512, &[], &[]);
    let syn = gw.process_one(probe);
    assert_segment(&syn, false, TcpFlags::SYN, CLIENT_ISN, 0, 512);

    let stray = segment(
        false,
        TcpFlags::ACK,
        SERVER_ISN,
        CLIENT_ISN + 1,
        0,
        &[],
        &[],
    );
    assert!(gw.process(stray).is_empty());
    let wrong_ack = segment(
        false,
        TcpFlags::SYN | TcpFlags::ACK,
        SERVER_ISN,
        CLIENT_ISN + 2,
        0,
        &[],
        &[],
    );
    assert!(gw.process(wrong_ack).is_empty());
}

// An ACK without a valid cookie is none of the proxy's business: it may belong to a connection
// that nothing tracks. The proxy lets it through, unchanged, and creates no flow.
#[tokio::test]
async fn ack_without_cookie() {
    let mut gw = Gateway::new();
    let cookie = handshake_with_client(&mut gw);
    let ack = segment(
        true,
        TcpFlags::ACK,
        CLIENT_ISN + 1,
        cookie + 2,
        512,
        &[],
        b"x",
    );
    let out = gw.process_one(ack);
    assert_segment(&out, false, TcpFlags::ACK, CLIENT_ISN + 1, cookie + 2, 512);
    assert_eq!(out.payload_len(), 1);
    assert_eq!(gw.flows(), 0);
}

// With the proxy off, SYNs go through. Cookies sent before remain valid for a while.
#[tokio::test]
async fn proxy_off() {
    let mut gw = Gateway::new();
    let cookie = handshake_with_client(&mut gw);
    gw.proxy.set_mode(SynProxyMode::Off);

    let syn = gw.process_one(client_syn());
    assert_segment(&syn, false, TcpFlags::SYN, CLIENT_ISN, 0, 64000);

    handshake_with_server(&mut gw, cookie);
}

// Cookies count as accepted only once the ACL and rate-limit stages let the connection through.
#[tokio::test]
async fn cookie_dropped_by_acl() {
    let mut gw = Gateway::new();
    let proxy = gw.proxy.clone();
    let accepted = || proxy.counters().cookies_accepted.load(Ordering::Relaxed);
    let cookie = handshake_with_client(&mut gw);
    gw.acl_drops.store(true, Ordering::Relaxed);
    assert!(gw.process(client_ack(cookie)).is_empty());
    assert_eq!(accepted(), 0);
    assert_eq!(gw.flows(), 0);

    gw.acl_drops.store(false, Ordering::Relaxed);
    handshake_with_server(&mut gw, cookie);
    assert_eq!(accepted(), 1);
}

// The proxy cannot answer a SYN in a fragment, it lets it through.
#[tokio::test]
async fn fragmented_syn() {
    let mut gw = Gateway::new();
    let mut syn = client_syn();
    syn.try_ipv4_mut().unwrap().set_more_fragments(true);
    let syn = gw.process_one(syn);
    assert_segment(&syn, false, TcpFlags::SYN, CLIENT_ISN, 0, 64000);
    let sent = gw.proxy.counters().cookies_sent.load(Ordering::Relaxed);
    assert_eq!(sent, 0);
}
