// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// All items in this module are pub(crate) for consumption by the harness
// (Phase 2+). Suppress dead-code warnings until those consumers land.
#![allow(dead_code)]

//! Endpoint: wraps a smoltcp `Interface` + `SocketSet` + `CaptureDevice`.
//!
//! Each [`Endpoint`] represents one side of a simulated network connection
//! (e.g. "client" or "server").  It owns a smoltcp TCP/IP stack backed by a
//! [`CaptureDevice`] and provides helpers for creating and managing TCP
//! sockets.
//!
//! This module is `pub(crate)` — the public harness API hides these details.
//!
//! [`CaptureDevice`]: crate::device::CaptureDevice

use crate::device::CaptureDevice;
use crate::time::SimClock;

use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tracing::trace;

/// Default TCP socket receive buffer size in bytes.
///
/// 65 535 bytes matches a full TCP window and is large enough for any
/// realistic test payload.
const TCP_RX_BUFFER_SIZE: usize = 65_535;

/// Default TCP socket transmit buffer size in bytes.
const TCP_TX_BUFFER_SIZE: usize = 65_535;

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// One side of a simulated network connection.
///
/// Wraps a smoltcp [`Interface`], [`SocketSet`], and [`CaptureDevice`] into a
/// single unit that can be polled, have frames injected/drained, and have TCP
/// sockets created on it.
pub(crate) struct Endpoint {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: CaptureDevice,
}

impl Endpoint {
    /// Create a new endpoint with the given network configuration.
    ///
    /// # Parameters
    ///
    /// - `mac`: Ethernet hardware address for the endpoint's interface.
    /// - `ip`: IPv4 address assigned to the interface.
    /// - `prefix_len`: Subnet prefix length (e.g. 24 for a /24 subnet).
    /// - `gateway`: Optional default IPv4 gateway.  Required when the peer is
    ///   on a different subnet (e.g. for NAT tests).
    /// - `clock`: Simulated clock providing the initial timestamp.
    pub(crate) fn new(
        mac: EthernetAddress,
        ip: Ipv4Address,
        prefix_len: u8,
        gateway: Option<Ipv4Address>,
        clock: &SimClock,
    ) -> Self {
        let mut device = CaptureDevice::new();

        // Derive a deterministic random seed from the MAC address so that
        // each endpoint generates unique but reproducible TCP initial
        // sequence numbers.
        let mut config = Config::new(mac.into());
        config.random_seed = u64::from_le_bytes([
            mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5], 0xCA, 0xFE,
        ]);

        let mut iface = Interface::new(config, &mut device, clock.now());

        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::from(ip), prefix_len))
                .unwrap_or_else(|_| unreachable!("fresh interface has capacity for one IP"));
        });

        if let Some(gw) = gateway {
            iface
                .routes_mut()
                .add_default_ipv4_route(gw)
                .unwrap_or_else(|_| unreachable!("fresh route table has capacity for one route"));
        }

        let sockets = SocketSet::new(vec![]);

        trace!(%ip, ?mac, "endpoint created");

        Self {
            iface,
            sockets,
            device,
        }
    }

    // ----- smoltcp polling -------------------------------------------------

    /// Drive the smoltcp stack: process pending ingress and egress.
    ///
    /// Returns [`PollResult::SocketStateChanged`] if any socket's state was
    /// affected by the poll.
    pub(crate) fn poll(&mut self, clock: &SimClock) -> PollResult {
        self.iface
            .poll(clock.now(), &mut self.device, &mut self.sockets)
    }

    // ----- device access (frame exchange) ----------------------------------

    /// Drain all frames transmitted by this endpoint's smoltcp stack since
    /// the last drain.
    pub(crate) fn drain_tx(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.device.drain_tx()
    }

    /// Inject a raw Ethernet frame into this endpoint's receive queue.
    ///
    /// The frame will be delivered to the smoltcp stack on the next
    /// [`poll`](Self::poll).
    pub(crate) fn inject_rx(&mut self, frame: Vec<u8>) {
        self.device.inject_rx(frame);
    }

    /// Number of frames waiting in the transmit queue.
    pub(crate) fn tx_pending(&self) -> usize {
        self.device.tx_pending()
    }

    /// Number of frames waiting in the receive queue.
    pub(crate) fn rx_pending(&self) -> usize {
        self.device.rx_pending()
    }

    // ----- TCP socket management -------------------------------------------

    /// Create a TCP socket with default buffer sizes and add it to the
    /// socket set.
    ///
    /// Returns the [`SocketHandle`] that can be used to access the socket
    /// later via [`tcp_socket`](Self::tcp_socket) or
    /// [`tcp_socket_mut`](Self::tcp_socket_mut).
    fn add_tcp_socket(&mut self) -> SocketHandle {
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER_SIZE]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER_SIZE]);
        let socket = tcp::Socket::new(rx_buf, tx_buf);
        self.sockets.add(socket)
    }

    /// Create a TCP socket and begin listening on `port`.
    ///
    /// Returns the socket handle for later access.
    pub(crate) fn listen_tcp(&mut self, port: u16) -> SocketHandle {
        let handle = self.add_tcp_socket();
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket
            .listen(port)
            .unwrap_or_else(|e| unreachable!("listen on fresh socket should not fail: {e:?}"));
        trace!(port, "TCP socket listening");
        handle
    }

    /// Create a TCP socket and initiate a connection to `remote` from
    /// `local_port`.
    ///
    /// The actual SYN packet is transmitted on the next [`poll`](Self::poll).
    /// Returns the socket handle for later access.
    pub(crate) fn connect_tcp(
        &mut self,
        remote: IpEndpoint,
        local_port: u16,
    ) -> SocketHandle {
        let handle = self.add_tcp_socket();

        // Borrow `iface` and `sockets` as disjoint fields so we can pass
        // the interface context to `tcp::Socket::connect`.
        let cx = self.iface.context();
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket
            .connect(cx, remote, local_port)
            .unwrap_or_else(|e| unreachable!("connect on fresh socket should not fail: {e:?}"));

        trace!(?remote, local_port, "TCP socket connecting");
        handle
    }

    /// Get a shared reference to a TCP socket by handle.
    pub(crate) fn tcp_socket(&self, handle: SocketHandle) -> &tcp::Socket<'static> {
        self.sockets.get::<tcp::Socket<'static>>(handle)
    }

    /// Get a mutable reference to a TCP socket by handle.
    pub(crate) fn tcp_socket_mut(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket<'static>>(handle)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const TEST_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
    const PREFIX_LEN: u8 = 24;

    fn make_endpoint(clock: &SimClock) -> Endpoint {
        Endpoint::new(TEST_MAC, TEST_IP, PREFIX_LEN, None, clock)
    }

    #[test]
    fn new_endpoint_has_empty_queues() {
        let clock = SimClock::new();
        let ep = make_endpoint(&clock);
        assert_eq!(ep.tx_pending(), 0);
        assert_eq!(ep.rx_pending(), 0);
    }

    #[test]
    fn poll_on_idle_endpoint_succeeds() {
        let clock = SimClock::new();
        let mut ep = make_endpoint(&clock);
        let _ = ep.poll(&clock);
    }

    #[test]
    fn listen_tcp_enters_listen_state() {
        let clock = SimClock::new();
        let mut ep = make_endpoint(&clock);
        let handle = ep.listen_tcp(80);
        assert_eq!(ep.tcp_socket(handle).state(), tcp::State::Listen);
    }

    #[test]
    fn connect_tcp_enters_syn_sent_state() {
        let clock = SimClock::new();
        let mut ep = make_endpoint(&clock);
        let remote = IpEndpoint::new(IpAddress::v4(10, 0, 0, 2), 80);
        let handle = ep.connect_tcp(remote, 49152);
        assert_eq!(ep.tcp_socket(handle).state(), tcp::State::SynSent);
    }

    #[test]
    fn poll_after_connect_produces_tx_frames() {
        let clock = SimClock::new();
        let mut ep = make_endpoint(&clock);
        let remote = IpEndpoint::new(IpAddress::v4(10, 0, 0, 2), 80);
        let _handle = ep.connect_tcp(remote, 49152);

        // First poll should produce an ARP request (peer MAC is unknown).
        let _ = ep.poll(&clock);
        assert!(
            ep.tx_pending() > 0,
            "expected at least one TX frame (ARP request) after connect + poll"
        );
    }

    #[test]
    fn endpoint_with_gateway_creates_successfully() {
        let clock = SimClock::new();
        let gateway = Ipv4Address::new(10, 0, 0, 254);
        let _ep = Endpoint::new(TEST_MAC, TEST_IP, PREFIX_LEN, Some(gateway), &clock);
    }

    #[test]
    fn multiple_tcp_sockets_coexist() {
        let clock = SimClock::new();
        let mut ep = make_endpoint(&clock);

        let h1 = ep.listen_tcp(80);
        let h2 = ep.listen_tcp(443);

        assert_eq!(ep.tcp_socket(h1).state(), tcp::State::Listen);
        assert_eq!(ep.tcp_socket(h2).state(), tcp::State::Listen);

        // Handles are distinct.
        assert_ne!(h1, h2);
    }
}
