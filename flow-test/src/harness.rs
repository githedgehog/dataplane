// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// Accessor methods are pub(crate) for consumption by higher-level APIs
// (Phase 3+). Suppress dead-code warnings until those consumers land.
#![allow(dead_code)]

//! Central test harness orchestrating two endpoints through pipe closures.
//!
//! [`FlowHarness`] connects a **client** and a **server** endpoint, each
//! running their own smoltcp TCP/IP stack, through a pair of user-supplied
//! packet-processing closures (`forward_pipe` and `reverse_pipe`).
//!
//! On every [`step`](FlowHarness::step):
//!
//! 1. The client's smoltcp stack is polled.
//! 2. Frames transmitted by the client are converted to [`Packet<Buf>`],
//!    passed through the `forward_pipe`, serialized back to frames, and
//!    injected into the server's receive queue.
//! 3. The server's smoltcp stack is polled.
//! 4. Frames transmitted by the server follow the same path in reverse
//!    through the `reverse_pipe` back into the client.
//!
//! Frames that do not parse as valid Ethernet+IP packets (e.g. ARP) are
//! forwarded as raw bytes without going through the pipe closure.
//! This lets ARP resolution work naturally while the pipe only sees IP
//! traffic it can meaningfully process.
//!
//! [`Packet<Buf>`]: net::packet::Packet

use std::time::Duration;

use net::buffer::FrameBuffer;
use net::packet::Packet;
use smoltcp::wire::{EthernetAddress, IpAddress, IpEndpoint, Ipv4Address};

/// The default server endpoint address for use in
/// [`Endpoint::connect_tcp`] calls.
///
/// This is a free function rather than an associated method on
/// [`FlowHarness`] so that callers do not need to fully qualify the
/// harness's closure type parameters.
#[must_use]
pub fn server_endpoint(port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::from(SERVER_IP), port)
}
use tracing::trace;

use crate::bridge::{frame_to_packet, packet_to_frame};
use crate::endpoint::Endpoint;
#[cfg(feature = "pcap")]
use crate::pcap::{Direction, PcapCapture, Stage};
use crate::time::SimClock;

/// Default maximum number of steps before [`run_until_idle`] or [`run_until`]
/// gives up.
///
/// This prevents infinite loops when the simulation never quiesces.
///
/// [`run_until_idle`]: FlowHarness::run_until_idle
/// [`run_until`]: FlowHarness::run_until
const MAX_STEPS: usize = 1_000;

// ---------------------------------------------------------------------------
// Network configuration defaults
// ---------------------------------------------------------------------------

/// Default client MAC address.
const CLIENT_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
/// Default server MAC address.
const SERVER_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
/// Default client IPv4 address.
const CLIENT_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
/// Default server IPv4 address.
const SERVER_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);
/// Subnet prefix length for both endpoints.
const PREFIX_LEN: u8 = 24;

// ---------------------------------------------------------------------------
// NetworkConfig
// ---------------------------------------------------------------------------

/// Network topology configuration for a [`FlowHarness`].
///
/// Controls the MAC addresses, IP addresses, subnet prefix lengths, and
/// optional gateways assigned to the client and server endpoints.
///
/// The [`Default`] implementation places both endpoints on a single `/24`
/// subnet with no gateways:
///
/// | Endpoint | MAC                 | IPv4        |
/// |----------|---------------------|-------------|
/// | Client   | `02:00:00:00:00:01` | `10.0.0.1`  |
/// | Server   | `02:00:00:00:00:02` | `10.0.0.2`  |
///
/// For NAT tests that require custom addressing (e.g. VPC-specific subnets
/// or different-subnet endpoints with gateways), construct a `NetworkConfig`
/// with the desired values and pass it to [`FlowHarness::with_config`].
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Client endpoint MAC address.
    pub client_mac: EthernetAddress,
    /// Server endpoint MAC address.
    pub server_mac: EthernetAddress,
    /// Client endpoint IPv4 address.
    pub client_ip: Ipv4Address,
    /// Server endpoint IPv4 address.
    pub server_ip: Ipv4Address,
    /// Client subnet prefix length.
    pub client_prefix_len: u8,
    /// Server subnet prefix length.
    pub server_prefix_len: u8,
    /// Optional default gateway for the client endpoint.
    ///
    /// Required when the server is on a different subnet or when
    /// NAT rewrites addresses outside the client's local subnet.
    pub client_gateway: Option<Ipv4Address>,
    /// Optional default gateway for the server endpoint.
    ///
    /// Required when the client is on a different subnet or when
    /// NAT rewrites addresses outside the server's local subnet.
    pub server_gateway: Option<Ipv4Address>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            client_mac: CLIENT_MAC,
            server_mac: SERVER_MAC,
            client_ip: CLIENT_IP,
            server_ip: SERVER_IP,
            client_prefix_len: PREFIX_LEN,
            server_prefix_len: PREFIX_LEN,
            client_gateway: None,
            server_gateway: None,
        }
    }
}

impl NetworkConfig {
    /// Build an [`IpEndpoint`] targeting the **server** at `port`.
    ///
    /// Convenience method so callers don't need to extract the raw IP.
    #[must_use]
    pub fn server_endpoint(&self, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::from(self.server_ip), port)
    }

    /// Build an [`IpEndpoint`] targeting the **client** at `port`.
    #[must_use]
    pub fn client_endpoint(&self, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::from(self.client_ip), port)
    }
}

// ---------------------------------------------------------------------------
// FlowHarness
// ---------------------------------------------------------------------------

/// Test harness that connects two smoltcp endpoints through packet-processing
/// pipe closures.
///
/// The harness is generic over:
///
/// - `Buf`: The buffer type (must implement [`FrameBuffer`]).
/// - `FwdPipe`: Closure processing packets from client → server.
/// - `RevPipe`: Closure processing packets from server → client.
///
/// # Example
///
/// ```ignore
/// use net::buffer::TestBuffer;
///
/// let mut harness = FlowHarness::<TestBuffer, _, _>::new(
///     |pkt| Some(pkt),  // forward: identity
///     |pkt| Some(pkt),  // reverse: identity
/// );
/// ```
pub struct FlowHarness<Buf, FwdPipe, RevPipe>
where
    Buf: FrameBuffer,
    FwdPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
    RevPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
{
    /// Network topology used to create the endpoints.
    config: NetworkConfig,
    /// The client-side endpoint.
    client: Endpoint,
    /// The server-side endpoint.
    server: Endpoint,
    /// Closure processing client → server packets.
    forward_pipe: FwdPipe,
    /// Closure processing server → client packets.
    reverse_pipe: RevPipe,
    /// Deterministic simulated clock.
    clock: SimClock,
    /// Total number of IP packets that have traversed the forward pipe.
    forward_count: usize,
    /// Total number of IP packets that have traversed the reverse pipe.
    reverse_count: usize,
    /// Optional pcap capture buffer for recording frame exchanges.
    ///
    /// When enabled via [`enable_pcap`](Self::enable_pcap), every frame
    /// that transits the harness is recorded with its simulated
    /// timestamp, direction, and processing stage.
    #[cfg(feature = "pcap")]
    capture: Option<PcapCapture>,
    /// Marker to bind the `Buf` type parameter.
    _buf: std::marker::PhantomData<Buf>,
}

impl<Buf, FwdPipe, RevPipe> FlowHarness<Buf, FwdPipe, RevPipe>
where
    Buf: FrameBuffer,
    FwdPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
    RevPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
{
    /// Create a harness with separate forward and reverse pipe closures.
    ///
    /// Both endpoints are placed on the same /24 subnet with default
    /// addresses so that ARP resolution works naturally.  See
    /// [`NetworkConfig::default`] for the default topology.
    ///
    /// Use [`with_config`](Self::with_config) when you need custom
    /// addresses, prefix lengths, or gateways (e.g. for NAT tests).
    pub fn new(forward_pipe: FwdPipe, reverse_pipe: RevPipe) -> Self {
        Self::with_config(NetworkConfig::default(), forward_pipe, reverse_pipe)
    }

    /// Create a harness with a custom network topology.
    ///
    /// This is the general-purpose constructor.  [`new`](Self::new) is a
    /// convenience wrapper that uses [`NetworkConfig::default`].
    pub fn with_config(
        config: NetworkConfig,
        forward_pipe: FwdPipe,
        reverse_pipe: RevPipe,
    ) -> Self {
        let clock = SimClock::new();
        let client = Endpoint::new(
            config.client_mac,
            config.client_ip,
            config.client_prefix_len,
            config.client_gateway,
            &clock,
        );
        let server = Endpoint::new(
            config.server_mac,
            config.server_ip,
            config.server_prefix_len,
            config.server_gateway,
            &clock,
        );

        Self {
            config,
            client,
            server,
            forward_pipe,
            reverse_pipe,
            clock,
            forward_count: 0,
            reverse_count: 0,
            #[cfg(feature = "pcap")]
            capture: None,
            _buf: std::marker::PhantomData,
        }
    }

    /// Advance the simulation by one tick.
    ///
    /// 1. Poll the client smoltcp stack.
    /// 2. Drain client TX → `frame_to_packet` → `forward_pipe` →
    ///    `packet_to_frame` → inject into server RX.
    ///    (Non-IP frames bypass the pipe and are forwarded as-is.)
    /// 3. Poll the server smoltcp stack.
    /// 4. Drain server TX → `frame_to_packet` → `reverse_pipe` →
    ///    `packet_to_frame` → inject into client RX.
    ///    (Non-IP frames bypass the pipe and are forwarded as-is.)
    /// 5. Advance the simulated clock by one tick.
    ///
    /// Returns the total number of frames exchanged in both directions
    /// during this step.
    pub fn step(&mut self) -> usize {
        let mut exchanged = 0;

        // --- client → server -----------------------------------------------
        self.client.poll(&self.clock);
        let client_frames: Vec<Vec<u8>> = self.client.drain_tx().collect();
        for frame in client_frames {
            exchanged += 1;
            self.forward_one_frame(&frame);
        }

        // --- server → client -----------------------------------------------
        self.server.poll(&self.clock);
        let server_frames: Vec<Vec<u8>> = self.server.drain_tx().collect();
        for frame in server_frames {
            exchanged += 1;
            self.reverse_one_frame(&frame);
        }

        // --- advance time ---------------------------------------------------
        self.clock.tick();

        trace!(exchanged, elapsed = ?self.clock.elapsed(), "step complete");
        exchanged
    }

    /// Run steps until no packets are exchanged (quiescent) or
    /// [`MAX_STEPS`] is reached.
    ///
    /// Returns the total number of steps executed.
    pub fn run_until_idle(&mut self) -> usize {
        self.run_until_idle_with_limit(MAX_STEPS)
    }

    /// Like [`run_until_idle`](Self::run_until_idle) but with a custom step
    /// limit.
    pub fn run_until_idle_with_limit(&mut self, max_steps: usize) -> usize {
        let mut total_steps = 0;
        for _ in 0..max_steps {
            total_steps += 1;
            if self.step() == 0 {
                break;
            }
        }
        trace!(total_steps, "run_until_idle complete");
        total_steps
    }

    /// Run steps until `pred` returns `true` or [`MAX_STEPS`] is reached.
    ///
    /// Returns the total number of steps executed.
    pub fn run_until(&mut self, mut pred: impl FnMut(&Self) -> bool) -> usize {
        self.run_until_with_limit(MAX_STEPS, &mut pred)
    }

    /// Like [`run_until`](Self::run_until) but with a custom step limit.
    pub fn run_until_with_limit(
        &mut self,
        max_steps: usize,
        pred: &mut impl FnMut(&Self) -> bool,
    ) -> usize {
        let mut total_steps = 0;
        for _ in 0..max_steps {
            if pred(self) {
                break;
            }
            self.step();
            total_steps += 1;
        }
        trace!(total_steps, "run_until complete");
        total_steps
    }

    /// Advance simulated time by `duration` without exchanging packets.
    ///
    /// Useful for testing idle timeouts and flow expiry.
    pub fn advance_time(&mut self, duration: Duration) {
        self.clock.advance(duration);
        trace!(elapsed = ?self.clock.elapsed(), "time advanced");
    }

    /// Get the current simulated time as a [`Duration`] since start.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.clock.elapsed()
    }

    /// Total number of IP packets that have traversed the forward pipe.
    #[must_use]
    pub fn forward_count(&self) -> usize {
        self.forward_count
    }

    /// Total number of IP packets that have traversed the reverse pipe.
    #[must_use]
    pub fn reverse_count(&self) -> usize {
        self.reverse_count
    }

    /// The network topology configuration used to build this harness.
    #[must_use]
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    /// Enable pcap capture of all frames exchanged through the harness.
    ///
    /// Once enabled, every frame that transits the forward or reverse
    /// path is recorded with its simulated timestamp, direction, and
    /// processing stage (pre-pipe, post-pipe, or passthrough).  The
    /// resulting [`PcapCapture`] can be written to a file via
    /// [`pcap_capture`](Self::pcap_capture) for offline analysis in
    /// Wireshark, tcpdump, or similar tools.
    ///
    /// Calling this method a second time replaces the existing capture
    /// buffer (any previously recorded frames are discarded).
    #[cfg(feature = "pcap")]
    pub fn enable_pcap(&mut self) {
        self.capture = Some(PcapCapture::new());
    }

    /// Access the pcap capture buffer, if capture was
    /// [`enabled`](Self::enable_pcap).
    ///
    /// Returns `None` if [`enable_pcap`](Self::enable_pcap) was never
    /// called.
    #[cfg(feature = "pcap")]
    #[must_use]
    pub fn pcap_capture(&self) -> Option<&PcapCapture> {
        self.capture.as_ref()
    }

    /// Take ownership of the pcap capture buffer, leaving `None` in its
    /// place.
    ///
    /// This is useful when you want to write the capture to disk and
    /// then continue the simulation with a fresh (or no) capture.
    #[cfg(feature = "pcap")]
    pub fn take_pcap_capture(&mut self) -> Option<PcapCapture> {
        self.capture.take()
    }

    /// Get a shared reference to the client endpoint.
    pub(crate) fn client(&self) -> &Endpoint {
        &self.client
    }

    /// Get a mutable reference to the client endpoint.
    pub(crate) fn client_mut(&mut self) -> &mut Endpoint {
        &mut self.client
    }

    /// Get a shared reference to the server endpoint.
    pub(crate) fn server(&self) -> &Endpoint {
        &self.server
    }

    /// Get a mutable reference to the server endpoint.
    pub(crate) fn server_mut(&mut self) -> &mut Endpoint {
        &mut self.server
    }

    // --- internal frame routing --------------------------------------------

    /// Forward a single frame from client → server.
    fn forward_one_frame(&mut self, raw: &[u8]) {
        // Try to parse as an IP packet for the pipe closure.
        if let Some(packet) = frame_to_packet::<Buf>(raw) {
            trace!(len = raw.len(), "forward pipe: IP packet");
            self.forward_count += 1;
            #[cfg(feature = "pcap")]
            if let Some(cap) = &mut self.capture {
                cap.record(self.clock.elapsed(), Direction::Forward, Stage::PrePipe, raw);
            }
            if let Some(processed) = (self.forward_pipe)(packet) {
                if let Some(out) = packet_to_frame::<Buf>(processed) {
                    #[cfg(feature = "pcap")]
                    if let Some(cap) = &mut self.capture {
                        cap.record(self.clock.elapsed(), Direction::Forward, Stage::PostPipe, &out);
                    }
                    self.server.inject_rx(out);
                } else {
                    trace!("forward pipe: packet_to_frame serialization failed, dropping");
                }
            } else {
                trace!("forward pipe: closure dropped packet");
            }
        } else {
            // Non-IP frame (e.g. ARP) — forward as-is.
            trace!(len = raw.len(), "forward: passthrough non-IP frame");
            #[cfg(feature = "pcap")]
            if let Some(cap) = &mut self.capture {
                cap.record(self.clock.elapsed(), Direction::Forward, Stage::Passthrough, raw);
            }
            self.server.inject_rx(raw.to_vec());
        }
    }

    /// Forward a single frame from server → client.
    fn reverse_one_frame(&mut self, raw: &[u8]) {
        if let Some(packet) = frame_to_packet::<Buf>(raw) {
            trace!(len = raw.len(), "reverse pipe: IP packet");
            self.reverse_count += 1;
            #[cfg(feature = "pcap")]
            if let Some(cap) = &mut self.capture {
                cap.record(self.clock.elapsed(), Direction::Reverse, Stage::PrePipe, raw);
            }
            if let Some(processed) = (self.reverse_pipe)(packet) {
                if let Some(out) = packet_to_frame::<Buf>(processed) {
                    #[cfg(feature = "pcap")]
                    if let Some(cap) = &mut self.capture {
                        cap.record(self.clock.elapsed(), Direction::Reverse, Stage::PostPipe, &out);
                    }
                    self.client.inject_rx(out);
                } else {
                    trace!("reverse pipe: packet_to_frame serialization failed, dropping");
                }
            } else {
                trace!("reverse pipe: closure dropped packet");
            }
        } else {
            trace!(len = raw.len(), "reverse: passthrough non-IP frame");
            #[cfg(feature = "pcap")]
            if let Some(cap) = &mut self.capture {
                cap.record(self.clock.elapsed(), Direction::Reverse, Stage::Passthrough, raw);
            }
            self.client.inject_rx(raw.to_vec());
        }
    }
}

/// Convenience constructor for a harness with a single symmetric pipe closure
/// applied to both directions.
///
/// This avoids the need to specify the closure twice when both directions
/// use the same processing logic.
impl<Buf, Pipe> FlowHarness<Buf, Pipe, Pipe>
where
    Buf: FrameBuffer,
    Pipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>> + Clone,
{
    /// Create a harness with the same pipe closure for both directions.
    pub fn symmetric(pipe: Pipe) -> Self {
        let reverse = pipe.clone();
        Self::new(pipe, reverse)
    }

    /// Create a harness with the same pipe closure for both directions and
    /// a custom network topology.
    pub fn symmetric_with_config(config: NetworkConfig, pipe: Pipe) -> Self {
        let reverse = pipe.clone();
        Self::with_config(config, pipe, reverse)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use net::buffer::TestBuffer;
    use smoltcp::socket::tcp;

    /// Identity pipe: forwards every packet unmodified.
    #[allow(clippy::unnecessary_wraps)] // signature must match FnMut bounds
    fn identity(pkt: Packet<TestBuffer>) -> Option<Packet<TestBuffer>> {
        Some(pkt)
    }

    #[test]
    fn harness_creates_successfully() {
        let _harness = FlowHarness::<TestBuffer, _, _>::new(identity, identity);
    }

    #[test]
    fn symmetric_harness_creates_successfully() {
        let _harness = FlowHarness::<TestBuffer, _, _>::symmetric(identity);
    }

    #[test]
    fn step_on_idle_harness_returns_zero() {
        let mut harness = FlowHarness::<TestBuffer, _, _>::symmetric(identity);
        // An idle harness with no sockets should exchange zero frames.
        let exchanged = harness.step();
        assert_eq!(exchanged, 0);
    }

    #[test]
    fn elapsed_advances_with_steps() {
        let mut harness = FlowHarness::<TestBuffer, _, _>::symmetric(identity);
        assert_eq!(harness.elapsed(), Duration::ZERO);

        harness.step();
        assert_eq!(harness.elapsed(), Duration::from_millis(1));

        for _ in 0..9 {
            harness.step();
        }
        assert_eq!(harness.elapsed(), Duration::from_millis(10));
    }

    #[test]
    fn advance_time_does_not_exchange_packets() {
        let mut harness = FlowHarness::<TestBuffer, _, _>::symmetric(identity);
        harness.advance_time(Duration::from_secs(60));
        assert_eq!(harness.elapsed(), Duration::from_secs(60));
        assert_eq!(harness.forward_count(), 0);
        assert_eq!(harness.reverse_count(), 0);
    }

    #[test]
    fn tcp_handshake_completes_through_identity_pipe() {
        let mut harness = FlowHarness::<TestBuffer, _, _>::symmetric(identity);

        // Server listens on port 80.
        let server_handle = harness.server_mut().listen_tcp(80);

        // Client connects to server.
        let remote = server_endpoint(80);
        let client_handle = harness.client_mut().connect_tcp(remote, 49152);

        // Run until idle — should complete the 3-way handshake (plus ARP).
        let steps = harness.run_until_idle();
        assert!(steps > 0, "expected at least one step");

        // Verify both sides reached ESTABLISHED.
        assert_eq!(
            harness.client().tcp_socket(client_handle).state(),
            tcp::State::Established,
            "client should be ESTABLISHED after handshake"
        );
        assert_eq!(
            harness.server().tcp_socket(server_handle).state(),
            tcp::State::Established,
            "server should be ESTABLISHED after handshake"
        );

        // Verify IP packets went through the pipe (not just ARP).
        assert!(
            harness.forward_count() > 0,
            "expected forward pipe to have processed at least one IP packet"
        );
        assert!(
            harness.reverse_count() > 0,
            "expected reverse pipe to have processed at least one IP packet"
        );
    }

    #[test]
    fn tcp_data_exchange_through_identity_pipe() {
        let mut harness = FlowHarness::<TestBuffer, _, _>::symmetric(identity);

        let server_handle = harness.server_mut().listen_tcp(80);
        let remote = server_endpoint(80);
        let client_handle = harness.client_mut().connect_tcp(remote, 49152);

        // Complete handshake.
        harness.run_until_idle();

        // Client sends data.
        let payload = b"Hello, server!";
        let socket = harness.client_mut().tcp_socket_mut(client_handle);
        assert!(socket.can_send(), "client socket should be able to send");
        socket
            .send_slice(payload)
            .unwrap_or_else(|e| unreachable!("send should succeed: {e:?}"));

        // Run until the data reaches the server.
        harness.run_until_idle();

        // Server receives data.
        let socket = harness.server_mut().tcp_socket_mut(server_handle);
        assert!(socket.can_recv(), "server socket should have data to receive");
        let mut buf = vec![0u8; 256];
        let n = socket
            .recv_slice(&mut buf)
            .unwrap_or_else(|e| unreachable!("recv should succeed: {e:?}"));
        assert_eq!(&buf[..n], payload, "received data should match sent data");
    }

    #[test]
    fn dropping_pipe_prevents_handshake() {
        // A pipe that drops all packets — handshake should never complete.
        let mut harness = FlowHarness::<TestBuffer, _, _>::new(
            |_pkt: Packet<TestBuffer>| None,
            |_pkt: Packet<TestBuffer>| None,
        );

        let server_handle = harness.server_mut().listen_tcp(80);
        let remote = server_endpoint(80);
        let client_handle = harness.client_mut().connect_tcp(remote, 49152);

        // Run a bounded number of steps.
        harness.run_until_idle_with_limit(50);

        // Neither side should reach ESTABLISHED.
        assert_ne!(
            harness.client().tcp_socket(client_handle).state(),
            tcp::State::Established,
            "client should NOT be ESTABLISHED when pipe drops everything"
        );
        assert_ne!(
            harness.server().tcp_socket(server_handle).state(),
            tcp::State::Established,
            "server should NOT be ESTABLISHED when pipe drops everything"
        );
    }

    #[test]
    fn run_until_stops_on_predicate() {
        let mut harness = FlowHarness::<TestBuffer, _, _>::symmetric(identity);
        let _server_handle = harness.server_mut().listen_tcp(80);
        let remote = server_endpoint(80);
        let _client_handle = harness.client_mut().connect_tcp(remote, 49152);

        // Stop as soon as any forward pipe traffic has occurred.
        let steps = harness.run_until(|h| h.forward_count() > 0);
        assert!(steps > 0, "should have taken at least one step");
        assert!(
            harness.forward_count() > 0,
            "predicate should have triggered on forward_count"
        );
    }

    #[test]
    fn counters_track_ip_packets_not_arp() {
        let mut harness = FlowHarness::<TestBuffer, _, _>::symmetric(identity);

        // Initiate a connection — ARP will happen first, then IP.
        let _server_handle = harness.server_mut().listen_tcp(80);
        let remote = server_endpoint(80);
        let _client_handle = harness.client_mut().connect_tcp(remote, 49152);

        // After the first step, the client sends an ARP request.
        // ARP doesn't parse as IP, so forward_count should still be 0.
        harness.step();
        let initial_forward = harness.forward_count();

        // After a few more steps, ARP resolves and IP packets flow.
        harness.run_until_idle();
        assert!(
            harness.forward_count() > initial_forward,
            "IP packets should eventually flow through the forward pipe"
        );
    }

    // -- NetworkConfig tests ------------------------------------------------

    #[test]
    fn default_network_config_matches_legacy_constants() {
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.client_mac, CLIENT_MAC);
        assert_eq!(cfg.server_mac, SERVER_MAC);
        assert_eq!(cfg.client_ip, CLIENT_IP);
        assert_eq!(cfg.server_ip, SERVER_IP);
        assert_eq!(cfg.client_prefix_len, PREFIX_LEN);
        assert_eq!(cfg.server_prefix_len, PREFIX_LEN);
        assert!(cfg.client_gateway.is_none());
        assert!(cfg.server_gateway.is_none());
    }

    #[test]
    fn server_endpoint_helper_uses_config_ip() {
        let cfg = NetworkConfig {
            server_ip: Ipv4Address::new(192, 168, 1, 100),
            ..NetworkConfig::default()
        };
        let ep = cfg.server_endpoint(443);
        assert_eq!(ep.addr, IpAddress::from(Ipv4Address::new(192, 168, 1, 100)));
        assert_eq!(ep.port, 443);
    }

    #[test]
    fn client_endpoint_helper_uses_config_ip() {
        let cfg = NetworkConfig {
            client_ip: Ipv4Address::new(172, 16, 0, 5),
            ..NetworkConfig::default()
        };
        let ep = cfg.client_endpoint(8080);
        assert_eq!(ep.addr, IpAddress::from(Ipv4Address::new(172, 16, 0, 5)));
        assert_eq!(ep.port, 8080);
    }

    #[test]
    fn with_config_uses_default_config() {
        let harness = FlowHarness::<TestBuffer, _, _>::with_config(
            NetworkConfig::default(),
            identity,
            identity,
        );
        assert_eq!(harness.config().client_ip, CLIENT_IP);
        assert_eq!(harness.config().server_ip, SERVER_IP);
    }

    #[test]
    fn config_accessor_reflects_custom_topology() {
        let cfg = NetworkConfig {
            client_ip: Ipv4Address::new(1, 1, 0, 1),
            server_ip: Ipv4Address::new(10, 201, 201, 1),
            client_prefix_len: 16,
            server_prefix_len: 24,
            client_gateway: Some(Ipv4Address::new(1, 1, 0, 254)),
            server_gateway: Some(Ipv4Address::new(10, 201, 201, 254)),
            ..NetworkConfig::default()
        };
        let harness = FlowHarness::<TestBuffer, _, _>::with_config(
            cfg.clone(),
            identity,
            identity,
        );
        assert_eq!(harness.config().client_ip, Ipv4Address::new(1, 1, 0, 1));
        assert_eq!(harness.config().server_ip, Ipv4Address::new(10, 201, 201, 1));
        assert_eq!(harness.config().client_prefix_len, 16);
        assert_eq!(harness.config().server_prefix_len, 24);
        assert_eq!(harness.config().client_gateway, Some(Ipv4Address::new(1, 1, 0, 254)));
        assert_eq!(harness.config().server_gateway, Some(Ipv4Address::new(10, 201, 201, 254)));
    }

    #[test]
    fn handshake_completes_with_custom_same_subnet_config() {
        let cfg = NetworkConfig {
            client_ip: Ipv4Address::new(192, 168, 50, 10),
            server_ip: Ipv4Address::new(192, 168, 50, 20),
            ..NetworkConfig::default()
        };
        let server_ep = cfg.server_endpoint(80);
        let mut harness = FlowHarness::<TestBuffer, _, _>::with_config(
            cfg,
            identity,
            identity,
        );

        let server_handle = harness.server_mut().listen_tcp(80);
        let client_handle = harness.client_mut().connect_tcp(server_ep, 49152);

        harness.run_until_idle();

        assert_eq!(
            harness.client().tcp_socket(client_handle).state(),
            tcp::State::Established,
            "client should be ESTABLISHED with custom config"
        );
        assert_eq!(
            harness.server().tcp_socket(server_handle).state(),
            tcp::State::Established,
            "server should be ESTABLISHED with custom config"
        );
    }

    #[test]
    fn symmetric_with_config_uses_custom_topology() {
        let cfg = NetworkConfig {
            client_ip: Ipv4Address::new(172, 20, 0, 1),
            server_ip: Ipv4Address::new(172, 20, 0, 2),
            ..NetworkConfig::default()
        };
        let server_ep = cfg.server_endpoint(80);
        let mut harness =
            FlowHarness::<TestBuffer, _, _>::symmetric_with_config(cfg, identity);

        let server_handle = harness.server_mut().listen_tcp(80);
        let client_handle = harness.client_mut().connect_tcp(server_ep, 49152);

        harness.run_until_idle();

        assert_eq!(
            harness.client().tcp_socket(client_handle).state(),
            tcp::State::Established,
        );
        assert_eq!(
            harness.server().tcp_socket(server_handle).state(),
            tcp::State::Established,
        );
        assert_eq!(harness.config().client_ip, Ipv4Address::new(172, 20, 0, 1));
    }
}
