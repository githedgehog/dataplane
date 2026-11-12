// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The pipeline stages of the SYN proxy.
//!
//! The proxy works in two stages:
//!
//! - [`SynCookieChecker`] runs before the ACL stage. It turns the client's ACK that echoes a valid
//!   cookie into the SYN to send to the server. The ACL, rate-limit and NAT stages then see this
//!   SYN as they would have seen the client's, and the NAT or flow-tracking stages create its
//!   flows. The ACL stage could match the ACK with other rules than the SYN, for example rules on
//!   TCP flags.
//!
//! - [`SynProxy`] runs after the ACL and rate-limit stages, so that the proxy never answers
//!   SYNs that the gateway would drop, and before NAT. It answers the SYNs of new connections with
//!   cookies, completes the handshake with the server, and then translates sequence numbers for
//!   the connections it set up.
//!
//! The proxy builds the segments it sends from the packets that trigger them. Before NAT, the
//! packets from the client carry the addresses that the client uses, and the packets from the
//! server carry the addresses that the server uses: to answer either of them, the proxy swaps
//! source and destination, and the answer needs no NAT.

use crate::SynProxyControl;
use concurrency::sync::Arc;
use concurrency::sync::atomic::Ordering;
use net::FlowKey;
use net::buffer::{DeepCopy, PacketBufferMut};
use net::flows::conn_tracking::{FlowSide, SynProxyState};
use net::flows::{ConnState, FlowInfo};
use net::headers::{Transport, TryTcp, TryTcpMut, TryTransportMut};
use net::packet::{DoneReason, Packet};
use net::tcp::{Tcp, TcpFlags, TcpOption};
use pipeline::NetworkFunction;
use tracectl::trace_target;
use tracing::debug;

trace_target!("syn-proxy", LevelFilter::INFO, &["pipeline"]);

// The fields of a TCP header that the proxy looks at.
#[derive(Clone, Copy)]
struct Segment {
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
}

impl From<&Tcp> for Segment {
    fn from(tcp: &Tcp) -> Self {
        Self {
            seq: tcp.sequence_number(),
            ack: tcp.ack_number(),
            flags: tcp.flags(),
            window: tcp.window_size(),
        }
    }
}

// Set the control bits, numbers and window of the TCP header of a packet, and make it a segment
// without data, with `options`.
fn make_segment<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    window: u16,
    options: &[TcpOption],
) -> Result<(), DoneReason> {
    let Some(tcp) = packet.try_tcp_mut() else {
        return Err(DoneReason::InternalFailure);
    };
    tcp.set_flags(flags)
        .set_sequence_number(seq)
        .set_ack_number(ack)
        .set_window_size(window)
        .set_urgent_pointer(0);
    packet
        .make_tcp_control_segment(options)
        .map_err(|_| DoneReason::Malformed)
}

// Prepare the metadata of a packet that the proxy sends back to where it came from. The packet
// goes back to its source VPC, and no NAT or flow tracking applies to it.
fn send_back<Buf: PacketBufferMut>(packet: &mut Packet<Buf>) -> Result<(), DoneReason> {
    packet.reflect_tcp().map_err(|_| DoneReason::Malformed)?;
    let meta = packet.meta_mut();
    meta.dst_vpcd = meta.src_vpcd;
    meta.clear_flow_state();
    Ok(())
}

// Set the sequence and acknowledgment numbers of a TCP packet we forward, and fold the change in
// the checksum.
fn set_seq_ack<Buf: PacketBufferMut>(packet: &mut Packet<Buf>, seq: u32, ack: u32) {
    let Some(transport) = packet.try_transport_mut() else {
        return;
    };
    let Transport::Tcp(tcp) = transport else {
        return;
    };
    let (old_seq, old_ack) = (tcp.sequence_number(), tcp.ack_number());
    tcp.set_sequence_number(seq).set_ack_number(ack);
    // Incremental updates only fail for ICMPv4
    #[allow(clippy::cast_possible_truncation)] // split each number into two 16-bit words
    for (old, new) in [(old_seq, seq), (old_ack, ack)] {
        let _ = transport.increment_checksum_for_u16((old >> 16) as u16, (new >> 16) as u16);
        let _ = transport.increment_checksum_for_u16(old as u16, new as u16);
    }
}

// Turn a SYN-ACK of the server into the ACK that completes the handshake with the server.
fn ack_server<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    state: &SynProxyState,
    server_isn: u32,
) -> Result<(), DoneReason> {
    send_back(packet)?;
    let seq = state.client_isn().wrapping_add(1);
    let ack = server_isn.wrapping_add(1);
    make_segment(packet, TcpFlags::ACK, seq, ack, state.window(), &[])
}

/// The stage of the SYN proxy that turns the client's ACK echoing a cookie into a SYN for the
/// server.
pub struct SynCookieChecker {
    name: String,
    proxy: SynProxyControl,
}

impl SynCookieChecker {
    /// Create the stage, with the switch of the proxy.
    #[must_use]
    pub fn new(name: &str, proxy: SynProxyControl) -> Self {
        Self {
            name: name.to_string(),
            proxy,
        }
    }

    fn process_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>, now: clock::Instant) {
        let Some(tcp) = packet.try_tcp() else {
            return;
        };
        if tcp.flags() & (TcpFlags::SYN | TcpFlags::RST | TcpFlags::FIN | TcpFlags::ACK)
            != TcpFlags::ACK
        {
            return;
        }
        let (seq, cookie, window) = (
            tcp.sequence_number(),
            tcp.ack_number().wrapping_sub(1),
            tcp.window_size(),
        );
        let Ok(conn) = FlowKey::try_from(&*packet) else {
            return;
        };
        // The ACK of the handshake follows the client's initial sequence number. A zero-window
        // probe from Linux, after the ACK was lost, reuses it.
        let key = self.proxy.key();
        let Some((client_isn, mss)) = [seq.wrapping_sub(1), seq]
            .into_iter()
            .find_map(|isn| Some((isn, key.check(&conn, isn, cookie, now)?)))
        else {
            // Most likely an ACK from a connection that has no flow because nothing tracks it
            return;
        };

        debug!("{}: Valid cookie, opening connection {conn}", self.name);
        let options = [TcpOption::Mss(mss)];
        if let Err(reason) = make_segment(packet, TcpFlags::SYN, client_isn, 0, window, &options) {
            packet.done(reason);
            return;
        }
        let state = SynProxyState::new(client_isn, cookie, mss, window);
        packet.meta_mut().syn_proxy = Some(Arc::new(state));
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for SynCookieChecker {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        let now = clock::now();
        if !self.proxy.may_accept_cookies(now) {
            return;
        }
        for packet in burst.iter_mut() {
            if !packet.is_done()
                && packet.meta().is_overlay()
                && packet.active_flow_info().is_none()
                && self.proxy.accepts_cookies(packet, now)
            {
                self.process_packet(packet, now);
            }
        }
    }
}

/// The stage of the SYN proxy that answers SYNs with cookies, completes the handshake with the
/// server, and translates the sequence numbers of the connections it set up.
pub struct SynProxy {
    name: String,
    proxy: SynProxyControl,
}

impl SynProxy {
    /// Create the stage, with the switch of the proxy.
    #[must_use]
    pub fn new(name: &str, proxy: SynProxyControl) -> Self {
        Self {
            name: name.to_string(),
            proxy,
        }
    }

    // Answer the SYN of a new connection with a SYN-ACK carrying a cookie. The SYN-ACK advertises
    // a zero window, so that the client sends no data before the server accepts the connection.
    //
    // We advertise the MSS of the client, as the cookie records it, on behalf of the server: we
    // cannot know the server's before it answers, and we assume that the hosts of the fabric share
    // their MTU. We negotiate no other option, so that the proxy only has to translate sequence
    // numbers.
    fn answer_syn<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        segment: Segment,
        now: clock::Instant,
    ) -> Result<(), DoneReason> {
        let client_isn = segment.seq;
        let mss = packet.try_tcp().and_then(Tcp::mss);
        let Ok(conn) = FlowKey::try_from(&*packet) else {
            return Ok(());
        };
        let (cookie, mss) = self.proxy.key().make(&conn, client_isn, mss, now);

        send_back(packet)?;
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        let ack = client_isn.wrapping_add(1);
        make_segment(packet, flags, cookie, ack, 0, &[TcpOption::Mss(mss)])?;
        self.proxy
            .counters()
            .cookies_sent
            .fetch_add(1, Ordering::Relaxed);
        debug!("{}: Answered SYN of {conn} with a cookie", self.name);
        Ok(())
    }

    // A packet from the client, on a connection that the proxy set up.
    fn client_packet<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        segment: Segment,
        state: &SynProxyState,
    ) -> Result<(), DoneReason> {
        let Segment {
            seq, ack, flags, ..
        } = segment;
        if let Some(offset) = state.offset() {
            if flags.contains(TcpFlags::ACK) {
                set_seq_ack(packet, seq, offset.client_to_server(ack));
            }
            return Ok(());
        }
        // The server has not answered yet. Let a reset through, the server can match it with the
        // SYN. Take anything else, such as window probes, as a sign that the SYN to the server
        // or its answer got lost, and send the SYN again.
        if flags.contains(TcpFlags::RST) {
            return Ok(());
        }
        let options = [TcpOption::Mss(state.mss())];
        let (isn, window) = (state.client_isn(), state.window());
        make_segment(packet, TcpFlags::SYN, isn, 0, window, &options)
    }

    // A packet from the server, on a connection that the proxy set up. The proxy may add a packet
    // to `extra`.
    fn server_packet<Buf: PacketBufferMut + DeepCopy>(
        &self,
        packet: &mut Packet<Buf>,
        segment: Segment,
        flow: &FlowInfo,
        state: &SynProxyState,
        extra: &mut Vec<Packet<Buf>>,
    ) -> Result<(), DoneReason> {
        let Segment {
            seq,
            ack,
            flags,
            window,
        } = segment;
        let rst = flags.contains(TcpFlags::RST);
        let syn_ack = !rst && flags.contains(TcpFlags::SYN | TcpFlags::ACK);
        let expected_ack = state.client_isn().wrapping_add(1);

        match state.offset() {
            // Our ACK got lost, and the server sends its SYN-ACK again: acknowledge it again
            Some(_) if syn_ack => ack_server(packet, state, seq),
            Some(offset) => {
                set_seq_ack(packet, offset.server_to_client(seq), ack);
                Ok(())
            }
            None if syn_ack && ack == expected_ack => {
                let offset = state.set_server_isn(seq);
                // The ACK to the server is a copy of its SYN-ACK, sent back
                let mut copy = packet
                    .deep_copy()
                    .map_err(|_| DoneReason::InternalFailure)?;
                ack_server(&mut copy, state, seq)?;
                extra.push(copy);

                // The client got a SYN-ACK already: tell it the window of the server instead. The
                // NAT stages see an ACK where the connection tracking expects a SYN-ACK, so move
                // the connection forward here.
                let seq = offset.server_to_client(seq.wrapping_add(1));
                make_segment(packet, TcpFlags::ACK, seq, ack, window, &[])?;
                if let Some(conn_state) = flow.conn_state() {
                    conn_state.store(ConnState::TwoWay);
                }
                self.proxy
                    .counters()
                    .connections
                    .fetch_add(1, Ordering::Relaxed);
                debug!("{}: Server accepted {}", self.name, flow.flowkey());
                Ok(())
            }
            // The server refused the connection: reset it for the client
            None if rst && ack == expected_ack => {
                let seq = state.cookie().wrapping_add(1);
                self.proxy
                    .counters()
                    .connections_refused
                    .fetch_add(1, Ordering::Relaxed);
                make_segment(packet, TcpFlags::RST, seq, 0, 0, &[])
            }
            None => Err(DoneReason::Filtered),
        }
    }

    fn process_packet<Buf: PacketBufferMut + DeepCopy>(
        &self,
        packet: &mut Packet<Buf>,
        segment: Segment,
        now: clock::Instant,
        extra: &mut Vec<Packet<Buf>>,
    ) -> Result<(), DoneReason> {
        // The SYN that the cookie stage built from the client's ACK. The proxy only answers SYNs
        // of connections that get flows, but the configuration may have changed since: make sure
        // this one gets flows, or we cannot translate its sequence numbers later.
        if packet.meta().syn_proxy.is_some() {
            let meta = packet.meta_mut();
            if !meta.gets_flows() {
                meta.set_forced_flow_tracking(true);
            }
            self.proxy
                .counters()
                .cookies_accepted
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        if let Some(flow) = packet.active_flow_info() {
            let Some(state) = flow.syn_proxy() else {
                return Ok(());
            };
            let (flow, state) = (flow.clone(), state.clone());
            return match FlowSide::from(flow.get_flags()) {
                FlowSide::Initiator => Self::client_packet(packet, segment, &state),
                FlowSide::Responder => self.server_packet(packet, segment, &flow, &state, extra),
            };
        }

        if packet.try_tcp().is_some_and(Tcp::is_first_segment) && self.proxy.answers_syns(packet) {
            return self.answer_syn(packet, segment, now);
        }
        Ok(())
    }
}

impl<Buf: PacketBufferMut + DeepCopy> NetworkFunction<Buf> for SynProxy {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        let now = clock::now();
        let mut extra = Vec::new();
        for packet in burst.iter_mut() {
            if packet.is_done() || !packet.meta().is_overlay() {
                continue;
            }
            let Some(segment) = packet.try_tcp().map(Segment::from) else {
                continue;
            };
            if let Err(reason) = self.process_packet(packet, segment, now, &mut extra) {
                debug!("{}: Dropping packet: {reason:?}", self.name);
                packet.done(reason);
            }
        }
        burst.extend(extra);
    }
}
