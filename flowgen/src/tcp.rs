// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Real TCP, from [smoltcp]: hosts that open connections, carry data both ways and close them,
//! through a gateway that has to keep every one of them straight.
//!
//! A [`Host`] is an [`Agent`]: one smoltcp interface with its own address, speaking IPv4 in frames
//! of its own -- plain Ethernet to a next hop, or Ethernet inside VXLAN from a VTEP -- so that a host
//! can stand in a VPC behind the gateway as easily as on its underlay. A [`Role`] says what it does:
//! serve, echoing everything back; open connections and check that what comes back is exactly
//! what went out; or keep a [`heartbeat`] going over one connection, as a BGP session would.
//!
//! What a host reports is per connection summed: how many were established, closed cleanly by
//! both ends or reset, how long establishing took, and bytes sent, received and received wrong -- a byte that
//! comes back differently from how it went is a byte the gateway mangled.
//!
//! [smoltcp]: https://docs.rs/smoltcp

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use flowgen_report::Sample;
use serde::{Deserialize, Serialize};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr};

use crate::drive::Agent;
use crate::frame::{self, Mac, Vxlan};
use crate::heartbeat;

/// The largest IP packet a host sends: room left for VXLAN within a 1500-byte underlay.
const MTU: usize = 1400;

/// Bytes in each direction of a connection's socket buffers.
const BUFFER: usize = 64 * 1024;

/// How a host's IP packets travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encap {
    /// In Ethernet, from the host's MAC to its next hop's.
    Ethernet {
        /// The host's MAC.
        mac: Mac,
        /// The next hop's MAC.
        next_hop: Mac,
    },
    /// In Ethernet inside VXLAN through `tunnel`, the inner frame from the host's MAC to the next
    /// hop's; frames back are taken by the tunnel's VNI.
    Vxlan {
        /// The tunnel.
        tunnel: Vxlan,
        /// The host's MAC, inside the tunnel.
        mac: Mac,
        /// The next hop's MAC, inside the tunnel.
        next_hop: Mac,
    },
}

/// A host's address, and the way out of its subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addressing {
    /// The host's address.
    pub address: Ipv4Addr,
    /// Its prefix length.
    pub prefix: u8,
    /// The router everything off the subnet goes through: only a name to smoltcp, since frames go
    /// to `next_hop` whatever their destination.
    pub gateway: Ipv4Addr,
}

/// What a host does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Accept `connections` connections on `port` and echo whatever arrives on each.
    Echo {
        /// The port.
        port: u16,
        /// How many connections it takes at once.
        connections: usize,
    },
    /// Open `connections` connections to `server`, from ports counting up from `first_port`;
    /// send `bytes` on each, read them back, and close.
    Client {
        /// Where to connect.
        server: (Ipv4Addr, u16),
        /// How many connections.
        connections: usize,
        /// The first local port.
        first_port: u16,
        /// Bytes each connection sends and expects back.
        bytes: usize,
    },
    /// Keep a heartbeat going over one connection at a time: to `peer`'s `port` from ports
    /// counting up from `first_port`, reconnecting a second after each connection ends, or, with
    /// no `peer`, listening on `port`. The port is BGP's unless said otherwise, so the gateway
    /// takes the connection for a BGP session.
    Heartbeat {
        /// The heartbeat's configuration.
        config: heartbeat::Config,
        /// Whom to connect to; `None` to listen instead.
        peer: Option<Ipv4Addr>,
        /// The port connected to, or listened on.
        #[serde(default = "heartbeat::default_port")]
        port: u16,
        /// The first local port, for connecting.
        first_port: u16,
    },
}

/// How long a heartbeat waits after a connection ends before trying again.
const CONNECT_RETRY_NS: u64 = 1_000_000_000;

/// A host's heartbeat and its connection.
struct Pulse {
    session: heartbeat::Session,
    /// The session has been told of the current connection.
    live: bool,
    /// Connections attempted, which pick the next local port.
    attempts: u16,
    /// When the next connection may be attempted.
    retry_at_ns: u64,
}

/// One connection a client opens, and how it is getting on.
#[derive(Debug, Clone, Default)]
struct Connection {
    /// Its number, which seeds its byte pattern.
    number: usize,
    sent: usize,
    received: usize,
    mismatched: usize,
    opened_ns: u64,
    established_ns: Option<u64>,
    /// This end has closed its side.
    closing: bool,
    /// Both sides have closed: the socket reached `TimeWait` or `Closed` after this end closed.
    closed: bool,
    reset: bool,
}

/// The byte a connection sends at `offset`: a pattern particular to the connection, so a byte that
/// crossed into another connection is caught too.
#[allow(clippy::cast_possible_truncation)] // the pattern is the low byte of the sum
fn pattern(number: usize, offset: usize) -> u8 {
    (number.wrapping_mul(131).wrapping_add(offset) % 251) as u8
}

/// What a host counts.
#[derive(Debug, Clone, Copy, Default)]
struct Tally {
    established: u64,
    closed: u64,
    reset: u64,
    bytes_sent: u64,
    bytes_received: u64,
    bytes_mismatched: u64,
    max_connect_ns: u64,
    frames_in: u64,
    frames_out: u64,
}

/// IP packets between a host's interface and its frames.
#[derive(Debug, Default)]
struct Pipe {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let r = f(&mut packet);
        self.0.push_back(packet);
        r
    }
}

impl phy::Device for Pipe {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

/// A smoltcp host as an [`Agent`]. See the [module documentation](self).
pub struct Host {
    name: String,
    wire: usize,
    addressing: Addressing,
    encap: Encap,
    role: Role,
    iface: Interface,
    pipe: Pipe,
    sockets: SocketSet<'static>,
    handles: Vec<SocketHandle>,
    connections: Vec<Connection>,
    tally: Tally,
    started: bool,
    pulse: Option<Pulse>,
}

fn now(ns: u64) -> Instant {
    Instant::from_micros(i64::try_from(ns / 1_000).unwrap_or(i64::MAX))
}

fn socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUFFER]),
        tcp::SocketBuffer::new(vec![0; BUFFER]),
    )
}

impl Host {
    /// A host called `name` -- reported under `tcp.<name>.` -- on wire `wire`, playing `role`.
    ///
    /// # Panics
    ///
    /// If `addressing` is not a usable IPv4 address and prefix.
    #[must_use]
    pub fn new(
        name: &str,
        wire: usize,
        addressing: Addressing,
        encap: Encap,
        role: Role,
        now_ns: u64,
    ) -> Host {
        let mut pipe = Pipe::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = u64::from(u32::from(addressing.address));
        let mut iface = Interface::new(config, &mut pipe, now(now_ns));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(addressing.address.into(), addressing.prefix))
                .unwrap_or_else(|_| unreachable!("a new interface has room for one address"));
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(addressing.gateway)
            .unwrap_or_else(|_| unreachable!("a new interface has room for one route"));
        let count = match role {
            Role::Echo { connections, .. } | Role::Client { connections, .. } => connections,
            Role::Heartbeat { .. } => 1,
        };
        let pulse = match role {
            Role::Heartbeat { config, .. } => Some(Pulse {
                session: heartbeat::Session::new(config),
                live: false,
                attempts: 0,
                retry_at_ns: now_ns,
            }),
            _ => None,
        };
        let mut sockets = SocketSet::new(Vec::new());
        let handles = (0..count).map(|_| sockets.add(socket())).collect();
        Host {
            name: name.to_string(),
            wire,
            addressing,
            encap,
            role,
            iface,
            pipe,
            sockets,
            handles,
            connections: (0..count)
                .map(|number| Connection {
                    number,
                    ..Connection::default()
                })
                .collect(),
            tally: Tally::default(),
            started: false,
            pulse,
        }
    }

    /// Open the connections, or start listening, the first time the host runs.
    fn start(&mut self, now_ns: u64) {
        if std::mem::replace(&mut self.started, true) {
            return;
        }
        match self.role {
            Role::Echo { port, .. } => {
                for handle in &self.handles {
                    let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
                    // A fresh socket always takes a listen on a nonzero port.
                    let _ = socket.listen(port);
                }
            }
            Role::Client {
                server, first_port, ..
            } => {
                for (n, handle) in self.handles.iter().enumerate() {
                    let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
                    let port = first_port.wrapping_add(u16::try_from(n).unwrap_or(u16::MAX));
                    let _ = socket.connect(self.iface.context(), server, port);
                    self.connections[n].opened_ns = now_ns;
                }
            }
            // A heartbeat connects, and reconnects, as it goes.
            Role::Heartbeat { .. } => {}
        }
    }

    /// Carry the heartbeat over the host's one socket: (re)connect or listen when there is no
    /// connection, tell the session when one comes up or goes down, and move its bytes.
    fn beat(&mut self, now_ns: u64) {
        let Role::Heartbeat {
            peer,
            port,
            first_port,
            ..
        } = self.role
        else {
            return;
        };
        let Some(pulse) = self.pulse.as_mut() else {
            return;
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(self.handles[0]);
        match socket.state() {
            tcp::State::Closed => {
                if pulse.live {
                    pulse.live = false;
                    pulse.session.disconnected(now_ns);
                    pulse.retry_at_ns = now_ns + CONNECT_RETRY_NS;
                }
                if now_ns >= pulse.retry_at_ns {
                    match peer {
                        Some(peer) => {
                            let local = first_port.wrapping_add(pulse.attempts);
                            pulse.attempts = pulse.attempts.wrapping_add(1);
                            let _ = socket.connect(self.iface.context(), (peer, port), local);
                        }
                        None => {
                            let _ = socket.listen(port);
                        }
                    }
                }
                return;
            }
            tcp::State::Established if !pulse.live => {
                pulse.live = true;
                pulse.session.connected(now_ns);
                self.tally.established += 1;
            }
            // The far end is closing the connection: it is over, and the socket is freed for the
            // next.
            tcp::State::CloseWait | tcp::State::TimeWait if pulse.live => {
                pulse.live = false;
                pulse.session.disconnected(now_ns);
                pulse.retry_at_ns = now_ns + CONNECT_RETRY_NS;
                socket.abort();
                return;
            }
            _ => {}
        }
        if !pulse.live {
            return;
        }
        let mut buf = [0u8; 4096];
        while socket.can_recv() {
            match socket.recv_slice(&mut buf) {
                Ok(got) if got > 0 => {
                    self.tally.bytes_received += got as u64;
                    pulse.session.receive(&buf[..got], now_ns);
                }
                _ => break,
            }
        }
        if let Some(bytes) = pulse.session.transmit(now_ns) {
            let sent = socket.send_slice(&bytes).unwrap_or(0);
            self.tally.bytes_sent += sent as u64;
        }
        // Given up, for silence or a mangled stream: reset, as a BGP speaker's NOTIFICATION and
        // close would end it at once for the far end too.
        if pulse.session.wants_close() {
            pulse.live = false;
            pulse.session.disconnected(now_ns);
            pulse.retry_at_ns = now_ns + CONNECT_RETRY_NS;
            socket.abort();
        }
    }

    /// Do what the role says with every socket, and follow each connection's life.
    fn serve(&mut self, now_ns: u64) {
        if self.pulse.is_some() {
            self.beat(now_ns);
            return;
        }
        let role = self.role.clone();
        for (n, handle) in self.handles.iter().enumerate() {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            let connection = &mut self.connections[n];
            if connection.closed || connection.reset {
                continue;
            }
            let state = socket.state();
            if state == tcp::State::Established && connection.established_ns.is_none() {
                connection.established_ns = Some(now_ns);
                self.tally.established += 1;
                if matches!(role, Role::Client { .. }) {
                    let took = now_ns.saturating_sub(connection.opened_ns);
                    self.tally.max_connect_ns = self.tally.max_connect_ns.max(took);
                }
            }
            match (connection.closing, state) {
                (true, tcp::State::TimeWait | tcp::State::Closed) => {
                    connection.closed = true;
                    self.tally.closed += 1;
                    continue;
                }
                // Closed without this end closing, once open: reset by the far end.
                (false, tcp::State::Closed) if connection.established_ns.is_some() => {
                    connection.reset = true;
                    self.tally.reset += 1;
                    continue;
                }
                _ => {}
            }
            match role {
                Role::Echo { .. } => echo(socket, connection, &mut self.tally),
                Role::Client { bytes, .. } => client(socket, connection, bytes, &mut self.tally),
                Role::Heartbeat { .. } => {}
            }
        }
    }
}

/// Echo whatever a server socket has received; close when the client has and all is echoed.
fn echo(socket: &mut tcp::Socket<'_>, connection: &mut Connection, tally: &mut Tally) {
    let mut buf = [0u8; 4096];
    while socket.can_recv() && socket.can_send() {
        let room = socket.send_capacity() - socket.send_queue();
        let take = room.min(buf.len());
        if take == 0 {
            break;
        }
        let Ok(got) = socket.recv_slice(&mut buf[..take]) else {
            break;
        };
        if got == 0 {
            break;
        }
        tally.bytes_received += got as u64;
        let _ = socket.send_slice(&buf[..got]);
        tally.bytes_sent += got as u64;
    }
    if !connection.closing && socket.state() == tcp::State::CloseWait && socket.send_queue() == 0 {
        socket.close();
        connection.closing = true;
    }
}

/// Send a client connection's bytes, check what comes back, and close once it is all back.
fn client(
    socket: &mut tcp::Socket<'_>,
    connection: &mut Connection,
    bytes: usize,
    tally: &mut Tally,
) {
    if connection.closing {
        return;
    }
    let mut buf = [0u8; 4096];
    while socket.can_send() && connection.sent < bytes {
        let n = (bytes - connection.sent).min(buf.len());
        for (i, byte) in buf[..n].iter_mut().enumerate() {
            *byte = pattern(connection.number, connection.sent + i);
        }
        let Ok(sent) = socket.send_slice(&buf[..n]) else {
            break;
        };
        if sent == 0 {
            break;
        }
        connection.sent += sent;
        tally.bytes_sent += sent as u64;
    }
    while socket.can_recv() {
        let Ok(got) = socket.recv_slice(&mut buf) else {
            break;
        };
        if got == 0 {
            break;
        }
        for (i, byte) in buf[..got].iter().enumerate() {
            if *byte != pattern(connection.number, connection.received + i) {
                connection.mismatched += 1;
                tally.bytes_mismatched += 1;
            }
        }
        connection.received += got;
        tally.bytes_received += got as u64;
    }
    if connection.received >= bytes {
        socket.close();
        connection.closing = true;
    }
}

impl Host {
    /// When the host next has something to do on its own -- a retransmission, a timer -- in
    /// nanoseconds, if anything; for a driver with a clock of its own to skip ahead to.
    pub fn next_poll_ns(&mut self, now_ns: u64) -> Option<u64> {
        let iface = self
            .iface
            .poll_at(now(now_ns), &self.sockets)
            .and_then(|at| u64::try_from(at.total_micros()).ok())
            .map(|us| us * 1_000);
        let pulse = self.pulse.as_ref().map(|pulse| {
            if pulse.live {
                pulse.session.next_deadline_ns()
            } else {
                pulse.retry_at_ns
            }
        });
        [iface, pulse].into_iter().flatten().min()
    }
}

impl Agent for Host {
    fn wire(&self) -> usize {
        self.wire
    }

    fn transmit(&mut self, now_ns: u64) -> Option<Vec<u8>> {
        if self.pipe.tx.is_empty() {
            self.start(now_ns);
            self.iface
                .poll(now(now_ns), &mut self.pipe, &mut self.sockets);
            self.serve(now_ns);
            self.iface
                .poll(now(now_ns), &mut self.pipe, &mut self.sockets);
        }
        let packet = self.pipe.tx.pop_front()?;
        self.tally.frames_out += 1;
        Some(match self.encap {
            Encap::Ethernet { mac, next_hop } => frame::ethernet_ipv4(next_hop, mac, &packet),
            Encap::Vxlan {
                tunnel,
                mac,
                next_hop,
            } => {
                let inner = frame::ethernet_ipv4(next_hop, mac, &packet);
                // Entropy from the connection's ports, as a VTEP would take it.
                let entropy = packet.get(20..24).map_or(0, |ports| {
                    u16::from_be_bytes([ports[0] ^ ports[2], ports[1] ^ ports[3]])
                });
                frame::vxlan(&tunnel, entropy, &inner)
            }
        })
    }

    fn receive(&mut self, frame: &[u8], _now_ns: u64) -> bool {
        let inner = match self.encap {
            Encap::Ethernet { .. } => Some(frame),
            Encap::Vxlan { tunnel, .. } => match frame::decapsulate(frame) {
                Some((vni, inner)) if vni == tunnel.vni => Some(inner),
                _ => None,
            },
        };
        let Some((_, packet)) = inner.and_then(frame::ipv4_packet) else {
            return false;
        };
        let to_us = packet.get(16..20).is_some_and(|dst| {
            Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]) == self.addressing.address
        });
        if to_us {
            self.tally.frames_in += 1;
            self.pipe.rx.push_back(packet.to_vec());
        }
        to_us
    }

    fn sample(&self, now_ns: u64, sample: Sample) -> Sample {
        let path = |what: &str| format!("tcp.{}.{what}", self.name);
        let t = self.tally;
        let sample = [
            ("connections", self.handles.len() as u64),
            ("established", t.established),
            ("closed", t.closed),
            ("reset", t.reset),
            ("bytes_sent", t.bytes_sent),
            ("bytes_received", t.bytes_received),
            ("bytes_mismatched", t.bytes_mismatched),
            ("frames_in", t.frames_in),
            ("frames_out", t.frames_out),
        ]
        .into_iter()
        .fold(sample, |sample, (what, n)| sample.counter(path(what), n))
        .gauge(path("max_connect_ns"), t.max_connect_ns);
        match &self.pulse {
            Some(pulse) => pulse.session.sample(&self.name, now_ns, sample),
            None => sample,
        }
    }

    fn finished(&self) -> bool {
        match self.role {
            Role::Echo { .. } | Role::Heartbeat { .. } => true,
            Role::Client { .. } => self.connections.iter().all(|c| c.closed || c.reset),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const MS: u64 = 1_000_000;

    fn host(name: &str, address: [u8; 4], mac: u8, peer: u8, role: Role) -> Host {
        Host::new(
            name,
            0,
            Addressing {
                address: Ipv4Addr::from(address),
                prefix: 24,
                gateway: Ipv4Addr::new(address[0], address[1], address[2], 254),
            },
            Encap::Ethernet {
                mac: [2, 0, 0, 0, 0, mac],
                next_hop: [2, 0, 0, 0, 0, peer],
            },
            role,
            0,
        )
    }

    /// Run two hosts on a link that loses the frames `lose` says to, by their order, until the
    /// client finishes or `until`.
    fn run(a: &mut Host, b: &mut Host, until: u64, lose: &mut dyn FnMut(u64) -> bool) -> u64 {
        let mut now = 0;
        let mut n = 0;
        while now < until && !a.finished() {
            let moved = n;
            for a_to_b in [true, false] {
                let (from, to) = if a_to_b {
                    (&mut *a, &mut *b)
                } else {
                    (&mut *b, &mut *a)
                };
                while let Some(frame) = from.transmit(now) {
                    n += 1;
                    if !lose(n) {
                        assert!(to.receive(&frame, now), "a frame for the other host");
                    }
                }
            }
            // While frames move, step a millisecond; when the link falls quiet, skip ahead to
            // whatever either host does next -- a retransmission, say.
            let next = if n > moved {
                now + MS
            } else {
                [a.next_poll_ns(now), b.next_poll_ns(now)]
                    .into_iter()
                    .flatten()
                    .min()
                    .unwrap_or(until)
            };
            now = next.max(now + MS);
        }
        now
    }

    #[test]
    fn connections_carry_every_byte_both_ways() {
        let mut client = host(
            "client",
            [10, 0, 0, 1],
            1,
            2,
            Role::Client {
                server: (Ipv4Addr::new(10, 0, 0, 2), 80),
                connections: 4,
                first_port: 50000,
                bytes: 200_000,
            },
        );
        let mut server = host(
            "server",
            [10, 0, 0, 2],
            2,
            1,
            Role::Echo {
                port: 80,
                connections: 4,
            },
        );
        let took = run(&mut client, &mut server, 20_000 * MS, &mut |_| false);
        assert!(client.finished(), "not done after {took} ns");
        let sample = client.sample(took, Sample::new());
        let counter = |what: &str| sample.counters[&format!("tcp.client.{what}")];
        assert_eq!(counter("established"), 4);
        assert_eq!(counter("closed"), 4);
        assert_eq!(counter("bytes_sent"), 800_000);
        assert_eq!(counter("bytes_received"), 800_000);
        assert_eq!(counter("bytes_mismatched"), 0);
    }

    /// TCP recovers what the link loses: with up to a fifth of frames lost at random, every byte
    /// arrives, in order, unmangled.
    #[test]
    fn lost_frames_are_recovered() {
        bolero::check!()
            .with_type::<(u8, u64)>()
            .for_each(|&(rate, seed)| {
                let percent = u64::from(rate % 21);
                let lose = move |n: u64| {
                    // SplitMix64 of the frame's number: a loss pattern with no period to resonate
                    // with retransmission.
                    let mut z = (n ^ seed).wrapping_add(0x9e37_79b9_7f4a_7c15);
                    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                    (z ^ (z >> 31)) % 100 < percent
                };
                let mut client = host(
                    "client",
                    [10, 0, 0, 1],
                    1,
                    2,
                    Role::Client {
                        server: (Ipv4Addr::new(10, 0, 0, 2), 80),
                        connections: 2,
                        first_port: 50000,
                        bytes: 20_000,
                    },
                );
                let mut server = host(
                    "server",
                    [10, 0, 0, 2],
                    2,
                    1,
                    Role::Echo {
                        port: 80,
                        connections: 2,
                    },
                );
                // Long enough for retransmission back-off through several losses in a row.
                let took = run(&mut client, &mut server, 1_000_000 * MS, &mut { lose });
                assert!(
                    client.finished(),
                    "not done after {took} ns losing {percent}% of frames"
                );
                let sample = client.sample(took, Sample::new());
                let counter = |what: &str| sample.counters[&format!("tcp.client.{what}")];
                assert_eq!(counter("bytes_received"), 40_000);
                assert_eq!(counter("bytes_mismatched"), 0);
            });
    }

    fn pulse(name: &str, address: [u8; 4], mac: u8, peer: u8, connect: Option<[u8; 4]>) -> Host {
        host(
            name,
            address,
            mac,
            peer,
            Role::Heartbeat {
                config: heartbeat::Config {
                    interval_ms: 100,
                    hold_ms: 1_000,
                },
                peer: connect.map(Ipv4Addr::from),
                port: heartbeat::PORT,
                first_port: 40000,
            },
        )
    }

    /// Run two hosts for `span` from `from`, losing every frame while `dead` says the link is down.
    fn run_for(a: &mut Host, b: &mut Host, from: u64, span: u64, dead: bool) -> u64 {
        let mut now = from;
        while now < from + span {
            let mut moved = false;
            for a_to_b in [true, false] {
                let (from, to) = if a_to_b {
                    (&mut *a, &mut *b)
                } else {
                    (&mut *b, &mut *a)
                };
                while let Some(frame) = from.transmit(now) {
                    moved = true;
                    if !dead {
                        to.receive(&frame, now);
                    }
                }
            }
            let next = if moved {
                now + MS
            } else {
                [a.next_poll_ns(now), b.next_poll_ns(now)]
                    .into_iter()
                    .flatten()
                    .min()
                    .unwrap_or(from + span)
            };
            now = next.max(now + MS).min(from + span);
        }
        now
    }

    fn beats(host: &Host, now: u64) -> Sample {
        host.sample(now, Sample::new())
    }

    fn counter(host: &Host, now: u64, what: &str) -> u64 {
        beats(host, now).counters[&format!("heartbeat.{}.{what}", host.name)]
    }

    fn is_up(host: &Host, now: u64) -> bool {
        beats(host, now).gauges[&format!("heartbeat.{}.is_up", host.name)] == 1
    }

    /// A heartbeat over smoltcp, on BGP's port: it comes up and keeps time, and when the link dies
    /// for longer than the hold time, both ends give the connection up, and they come back once
    /// it is back.
    #[test]
    fn a_heartbeat_holds_and_recovers() {
        let mut active = pulse("active", [10, 0, 0, 1], 1, 2, Some([10, 0, 0, 2]));
        let mut passive = pulse("passive", [10, 0, 0, 2], 2, 1, None);
        let now = run_for(&mut active, &mut passive, 0, 10_000 * MS, false);
        for host in [&active, &passive] {
            assert!(is_up(host, now), "{}", host.name);
            assert_eq!(counter(host, now, "up"), 1);
            assert_eq!(counter(host, now, "down"), 0);
            assert_eq!(counter(host, now, "late"), 0);
            assert!(counter(host, now, "beats_received") >= 95);
        }
        // Three seconds dead: more than the one-second hold time.
        let now = run_for(&mut active, &mut passive, now, 3_000 * MS, true);
        for host in [&active, &passive] {
            assert_eq!(counter(host, now, "expiries"), 1, "{}", host.name);
            assert_eq!(counter(host, now, "down"), 1);
        }
        let now = run_for(&mut active, &mut passive, now, 30_000 * MS, false);
        for host in [&active, &passive] {
            assert!(is_up(host, now), "{} never came back", host.name);
            assert_eq!(counter(host, now, "up"), 2);
            assert_eq!(counter(host, now, "mangled"), 0);
        }
    }
}
