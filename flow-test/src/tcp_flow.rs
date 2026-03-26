// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! High-level TCP flow API.
//!
//! [`TcpFlow`] represents a TCP connection managed by the test harness,
//! providing ergonomic methods ([`connect`](TcpFlow::connect),
//! [`close`](TcpFlow::close), [`reset`](TcpFlow::reset)) that internally
//! drive the simulation.  [`FlowEndpoint`] gives access to one side of the
//! connection for data transfer ([`send`](FlowEndpoint::send),
//! [`recv`](FlowEndpoint::recv)) and state inspection
//! ([`state`](FlowEndpoint::state)).
//!
//! # Usage
//!
//! ```ignore
//! let mut flow = TcpFlow::new(&mut harness, 49152, 80);
//! flow.connect()?;
//!
//! flow.client().send(b"hello")?;
//! let data = flow.server().recv(5)?;
//! assert_eq!(&data, b"hello");
//!
//! flow.close()?;
//! ```

use net::buffer::FrameBuffer;
use net::packet::Packet;
use smoltcp::iface::SocketHandle;

use crate::error::FlowError;
use crate::harness::{server_endpoint, FlowHarness};
use crate::tcp_state::TcpState;

/// Type alias for a [`FlowHarness`] using identity-style function pointer
/// pipes.  Used in tests to avoid tripping `clippy::type_complexity`.
#[cfg(test)]
type IdentityPipe = fn(Packet<net::buffer::TestBuffer>) -> Option<Packet<net::buffer::TestBuffer>>;
#[cfg(test)]
type TestHarness = FlowHarness<net::buffer::TestBuffer, IdentityPipe, IdentityPipe>;

/// Maximum number of simulation steps for a single flow-level operation
/// (connect, close, send, recv, etc.).
///
/// 200 steps is generous for any single operation through a well-behaved
/// pipe.  If this limit is hit, the pipe is likely dropping or delaying
/// packets, which the caller should diagnose from the returned
/// [`FlowError::Timeout`].
const MAX_FLOW_STEPS: usize = 200;

/// Which side of the connection a [`FlowEndpoint`] represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// The side that initiated the connection (sent the SYN).
    Client,
    /// The side that accepted the connection (was listening).
    Server,
}

// ---------------------------------------------------------------------------
// TcpFlow
// ---------------------------------------------------------------------------

/// A handle to a TCP connection managed by the harness.
///
/// The "client" is the side that initiated the connection (sent the SYN).
/// The "server" is the side that accepted it.  Both sides can send and
/// receive — TCP is full-duplex.
///
/// # Lifetime and type parameters
///
/// - `'h` — borrow of the [`FlowHarness`].
/// - `Buf` — buffer type (must implement [`FrameBuffer`]).
/// - `FwdPipe` / `RevPipe` — closure types for the forward and reverse
///   packet-processing pipes.
///
/// In practice these parameters are always inferred; test code never needs
/// to write them out.
pub struct TcpFlow<'h, Buf, FwdPipe, RevPipe>
where
    Buf: FrameBuffer,
    FwdPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
    RevPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
{
    harness: &'h mut FlowHarness<Buf, FwdPipe, RevPipe>,
    client_handle: SocketHandle,
    server_handle: SocketHandle,
}

impl<'h, Buf, FwdPipe, RevPipe> TcpFlow<'h, Buf, FwdPipe, RevPipe>
where
    Buf: FrameBuffer,
    FwdPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
    RevPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
{
    /// Set up a new TCP flow.
    ///
    /// This creates a listening socket on the server at `server_port` and a
    /// connecting socket on the client from `client_port`.  No packets are
    /// exchanged yet — call [`connect`](Self::connect) to drive the 3-way
    /// handshake.
    pub fn new(
        harness: &'h mut FlowHarness<Buf, FwdPipe, RevPipe>,
        client_port: u16,
        server_port: u16,
    ) -> Self {
        let server_handle = harness.server_mut().listen_tcp(server_port);
        let remote = server_endpoint(server_port);
        let client_handle = harness.client_mut().connect_tcp(remote, client_port);
        Self {
            harness,
            client_handle,
            server_handle,
        }
    }

    /// Drive the TCP 3-way handshake to completion.
    ///
    /// Runs simulation steps until both sides reach
    /// [`Established`](TcpState::Established) or an error condition is
    /// detected.
    ///
    /// # Errors
    ///
    /// - [`FlowError::Timeout`] if the handshake does not complete within
    ///   [`MAX_FLOW_STEPS`] steps.
    /// - [`FlowError::UnexpectedState`] if either side transitions to
    ///   [`Closed`](TcpState::Closed) (e.g. RST received).
    pub fn connect(&mut self) -> Result<(), FlowError> {
        let ch = self.client_handle;
        let sh = self.server_handle;

        self.harness.run_until_with_limit(MAX_FLOW_STEPS, &mut |h| {
            let cs = TcpState::from_smoltcp(h.client().tcp_socket(ch).state());
            let ss = TcpState::from_smoltcp(h.server().tcp_socket(sh).state());
            (cs.is_established() && ss.is_established()) || cs.is_closed() || ss.is_closed()
        });

        let cs = self.client_state();
        let ss = self.server_state();

        if cs.is_established() && ss.is_established() {
            Ok(())
        } else if cs.is_closed() || ss.is_closed() {
            Err(FlowError::UnexpectedState {
                operation: "connect",
                actual: if cs.is_closed() { cs } else { ss },
                expected: Some(TcpState::Established),
            })
        } else {
            Err(FlowError::Timeout {
                operation: "connect",
                max_steps: MAX_FLOW_STEPS,
            })
        }
    }

    /// Initiate a graceful close (FIN exchange) from the client side.
    ///
    /// This performs a full orderly shutdown:
    /// 1. Client sends FIN.
    /// 2. Server receives it and enters `CloseWait`.
    /// 3. Server sends its own FIN.
    /// 4. Both sides reach a terminal state (`TimeWait` or `Closed`).
    ///
    /// # Errors
    ///
    /// - [`FlowError::Timeout`] if the close sequence does not complete.
    pub fn close(&mut self) -> Result<(), FlowError> {
        let ch = self.client_handle;
        let sh = self.server_handle;

        // Step 1: Client initiates close.
        {
            let socket = self.harness.client_mut().tcp_socket_mut(ch);
            socket.close();
        }

        // Step 2: Run until server enters CloseWait (received client FIN).
        self.harness.run_until_with_limit(MAX_FLOW_STEPS, &mut |h| {
            let ss = TcpState::from_smoltcp(h.server().tcp_socket(sh).state());
            ss == TcpState::CloseWait || ss.is_closed()
        });

        // Step 3: Server also closes.
        {
            let socket = self.harness.server_mut().tcp_socket_mut(sh);
            socket.close();
        }

        // Step 4: Run until both sides reach a terminal state.
        self.harness.run_until_with_limit(MAX_FLOW_STEPS, &mut |h| {
            let cs = TcpState::from_smoltcp(h.client().tcp_socket(ch).state());
            let ss = TcpState::from_smoltcp(h.server().tcp_socket(sh).state());
            is_terminal(cs) && is_terminal(ss)
        });

        let cs = self.client_state();
        let ss = self.server_state();

        if is_terminal(cs) && is_terminal(ss) {
            Ok(())
        } else {
            Err(FlowError::Timeout {
                operation: "close",
                max_steps: MAX_FLOW_STEPS,
            })
        }
    }

    /// Send RST from the client side, aborting the connection.
    ///
    /// After calling this, both sides should transition to `Closed`
    /// (assuming the pipe delivers the RST).
    ///
    /// # Errors
    ///
    /// - [`FlowError::Timeout`] if the reset does not complete.
    pub fn reset(&mut self) -> Result<(), FlowError> {
        let ch = self.client_handle;
        let sh = self.server_handle;

        {
            let socket = self.harness.client_mut().tcp_socket_mut(ch);
            socket.abort();
        }

        // Run until both sides are closed.
        self.harness.run_until_with_limit(MAX_FLOW_STEPS, &mut |h| {
            let cs = TcpState::from_smoltcp(h.client().tcp_socket(ch).state());
            let ss = TcpState::from_smoltcp(h.server().tcp_socket(sh).state());
            cs.is_closed() && ss.is_closed()
        });

        let cs = self.client_state();
        let ss = self.server_state();

        if cs.is_closed() && ss.is_closed() {
            Ok(())
        } else {
            Err(FlowError::Timeout {
                operation: "reset",
                max_steps: MAX_FLOW_STEPS,
            })
        }
    }

    /// Access the client (initiating) side of the connection.
    ///
    /// The returned [`FlowEndpoint`] borrows this `TcpFlow` mutably, so
    /// you must drop it before accessing the server side (or calling any
    /// other `&mut self` method).
    pub fn client(&mut self) -> FlowEndpoint<'_, 'h, Buf, FwdPipe, RevPipe> {
        FlowEndpoint {
            flow: self,
            side: Side::Client,
        }
    }

    /// Access the server (accepting) side of the connection.
    ///
    /// The returned [`FlowEndpoint`] borrows this `TcpFlow` mutably, so
    /// you must drop it before accessing the client side (or calling any
    /// other `&mut self` method).
    pub fn server(&mut self) -> FlowEndpoint<'_, 'h, Buf, FwdPipe, RevPipe> {
        FlowEndpoint {
            flow: self,
            side: Side::Server,
        }
    }

    /// Query the client's current TCP state.
    #[must_use]
    pub fn client_state(&self) -> TcpState {
        TcpState::from_smoltcp(
            self.harness
                .client()
                .tcp_socket(self.client_handle)
                .state(),
        )
    }

    /// Query the server's current TCP state.
    #[must_use]
    pub fn server_state(&self) -> TcpState {
        TcpState::from_smoltcp(
            self.harness
                .server()
                .tcp_socket(self.server_handle)
                .state(),
        )
    }
}

/// Returns `true` if `state` is a terminal state (connection fully closed
/// or waiting to close).
fn is_terminal(state: TcpState) -> bool {
    state == TcpState::Closed || state == TcpState::TimeWait
}

// ---------------------------------------------------------------------------
// FlowEndpoint
// ---------------------------------------------------------------------------

/// One side of a TCP connection, providing data transfer and state
/// inspection.
///
/// Obtained from [`TcpFlow::client`] or [`TcpFlow::server`].
///
/// # Lifetime parameters
///
/// - `'f` — borrow of the [`TcpFlow`].
/// - `'h` — borrow of the [`FlowHarness`] (inherited from `TcpFlow`).
///
/// In practice these are always inferred.
pub struct FlowEndpoint<'f, 'h, Buf, FwdPipe, RevPipe>
where
    Buf: FrameBuffer,
    FwdPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
    RevPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
{
    flow: &'f mut TcpFlow<'h, Buf, FwdPipe, RevPipe>,
    side: Side,
}

impl<Buf, FwdPipe, RevPipe> FlowEndpoint<'_, '_, Buf, FwdPipe, RevPipe>
where
    Buf: FrameBuffer,
    FwdPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
    RevPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
{
    /// Send data from this endpoint to the peer.
    ///
    /// Writes `data` into the socket's send buffer (stepping the harness
    /// if the buffer fills up before all data is written), then runs the
    /// simulation until idle so the data is transmitted and acknowledged.
    ///
    /// # Errors
    ///
    /// - [`FlowError::InvalidState`] if the socket is not in a sendable
    ///   state.
    /// - [`FlowError::TransferFailed`] if a write to the socket buffer
    ///   fails.
    /// - [`FlowError::Timeout`] if all data cannot be written within
    ///   [`MAX_FLOW_STEPS`].
    pub fn send(&mut self, data: &[u8]) -> Result<(), FlowError> {
        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0;

        for _ in 0..MAX_FLOW_STEPS {
            // --- write phase: push as much data as we can into the buffer ---
            {
                let handle = self.handle();
                let socket = self.endpoint_mut().tcp_socket_mut(handle);

                if !socket.may_send() {
                    return Err(FlowError::InvalidState {
                        operation: "send",
                        state: TcpState::from_smoltcp(socket.state()),
                    });
                }

                if socket.can_send() {
                    match socket.send_slice(&data[offset..]) {
                        Ok(n) => offset += n,
                        Err(e) => {
                            return Err(FlowError::TransferFailed {
                                operation: "send",
                                reason: format!("{e:?}"),
                            })
                        }
                    }
                }
            }

            if offset >= data.len() {
                // All data written to the buffer.  Run until idle so
                // it is transmitted and acknowledged by the peer.
                self.flow.harness.run_until_idle_with_limit(MAX_FLOW_STEPS);
                return Ok(());
            }

            // --- step phase: make room in the buffer by draining frames ---
            self.flow.harness.step();
        }

        Err(FlowError::Timeout {
            operation: "send",
            max_steps: MAX_FLOW_STEPS,
        })
    }

    /// Receive `expected_len` bytes of data that the peer sent to this
    /// endpoint.
    ///
    /// Drives simulation steps until the requested number of bytes have
    /// been accumulated in the receive buffer, then returns them.
    ///
    /// # Errors
    ///
    /// - [`FlowError::TransferFailed`] if the connection closes or resets
    ///   before all expected bytes arrive.
    /// - [`FlowError::Timeout`] if the data does not arrive within
    ///   [`MAX_FLOW_STEPS`].
    pub fn recv(&mut self, expected_len: usize) -> Result<Vec<u8>, FlowError> {
        if expected_len == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; expected_len];
        let mut received = 0;

        for _ in 0..MAX_FLOW_STEPS {
            // --- read phase: drain whatever is available ---
            {
                let handle = self.handle();
                let socket = self.endpoint_mut().tcp_socket_mut(handle);

                if socket.can_recv() {
                    match socket.recv_slice(&mut buf[received..]) {
                        Ok(n) => received += n,
                        Err(e) => {
                            return Err(FlowError::TransferFailed {
                                operation: "recv",
                                reason: format!("{e:?}"),
                            })
                        }
                    }
                }

                // If the connection can no longer receive and we haven't
                // gotten all the data, the transfer has failed.
                if !socket.may_recv() && received < expected_len {
                    return Err(FlowError::TransferFailed {
                        operation: "recv",
                        reason: format!(
                            "connection closed after {received} of {expected_len} bytes"
                        ),
                    });
                }
            }

            if received >= expected_len {
                buf.truncate(received);
                return Ok(buf);
            }

            // --- step phase: drive packets so more data arrives ---
            self.flow.harness.step();
        }

        Err(FlowError::Timeout {
            operation: "recv",
            max_steps: MAX_FLOW_STEPS,
        })
    }

    /// Query this endpoint's TCP state.
    #[must_use]
    pub fn state(&self) -> TcpState {
        let handle = self.handle();
        let socket = self.endpoint().tcp_socket(handle);
        TcpState::from_smoltcp(socket.state())
    }

    // --- private helpers ---------------------------------------------------

    /// The socket handle for this endpoint's side of the connection.
    fn handle(&self) -> SocketHandle {
        match self.side {
            Side::Client => self.flow.client_handle,
            Side::Server => self.flow.server_handle,
        }
    }

    /// Shared reference to this endpoint's side of the harness.
    fn endpoint(&self) -> &crate::endpoint::Endpoint {
        match self.side {
            Side::Client => self.flow.harness.client(),
            Side::Server => self.flow.harness.server(),
        }
    }

    /// Mutable reference to this endpoint's side of the harness.
    fn endpoint_mut(&mut self) -> &mut crate::endpoint::Endpoint {
        match self.side {
            Side::Client => self.flow.harness.client_mut(),
            Side::Server => self.flow.harness.server_mut(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use net::buffer::TestBuffer;

    /// Identity pipe: forwards every packet unmodified.
    #[allow(clippy::unnecessary_wraps)]
    fn identity(pkt: Packet<TestBuffer>) -> Option<Packet<TestBuffer>> {
        Some(pkt)
    }

    fn make_harness() -> TestHarness {
        FlowHarness::<TestBuffer, _, _>::symmetric(identity as IdentityPipe)
    }

    // -- connect -----------------------------------------------------------

    #[test]
    fn connect_succeeds_through_identity_pipe() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);

        flow.connect()?;

        assert_eq!(flow.client_state(), TcpState::Established);
        assert_eq!(flow.server_state(), TcpState::Established);
        Ok(())
    }

    #[test]
    fn connect_fails_when_forward_pipe_drops_packets() {
        let mut harness = FlowHarness::<TestBuffer, _, _>::new(
            |_pkt: Packet<TestBuffer>| None, // drop all forward traffic
            identity,                         // pass reverse traffic through
        );
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);

        let result = flow.connect();

        assert!(result.is_err(), "connect should fail when pipe drops SYN");
        match result {
            Err(FlowError::Timeout { .. }) => {} // expected
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    // -- data transfer (client → server) -----------------------------------

    #[test]
    fn client_send_server_recv() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        flow.client().send(payload)?;
        let received = flow.server().recv(payload.len())?;

        assert_eq!(received, payload, "server should receive exact data client sent");
        Ok(())
    }

    // -- data transfer (server → client) -----------------------------------

    #[test]
    fn server_send_client_recv() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        let payload = b"HTTP/1.1 200 OK\r\n\r\nHello!";
        flow.server().send(payload)?;
        let received = flow.client().recv(payload.len())?;

        assert_eq!(received, payload, "client should receive exact data server sent");
        Ok(())
    }

    // -- bidirectional exchange ---------------------------------------------

    #[test]
    fn full_request_response_cycle() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        // Client sends request.
        let request = b"PING";
        flow.client().send(request)?;
        let got_request = flow.server().recv(request.len())?;
        assert_eq!(got_request, request);

        // Server sends response.
        let response = b"PONG";
        flow.server().send(response)?;
        let got_response = flow.client().recv(response.len())?;
        assert_eq!(got_response, response);

        Ok(())
    }

    // -- close -------------------------------------------------------------

    #[test]
    fn close_transitions_to_terminal_states() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        flow.close()?;

        let cs = flow.client_state();
        let ss = flow.server_state();
        assert!(
            is_terminal(cs),
            "client should be in terminal state after close, got {cs}"
        );
        assert!(
            is_terminal(ss),
            "server should be in terminal state after close, got {ss}"
        );
        Ok(())
    }

    // -- reset -------------------------------------------------------------

    #[test]
    fn reset_closes_both_sides() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        flow.reset()?;

        assert_eq!(
            flow.client_state(),
            TcpState::Closed,
            "client should be CLOSED after reset"
        );
        assert_eq!(
            flow.server_state(),
            TcpState::Closed,
            "server should be CLOSED after reset"
        );
        Ok(())
    }

    // -- edge cases --------------------------------------------------------

    #[test]
    fn send_empty_data_is_noop() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        flow.client().send(b"")?;
        Ok(())
    }

    #[test]
    fn recv_zero_bytes_returns_empty_vec() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        let data = flow.server().recv(0)?;
        assert!(data.is_empty());
        Ok(())
    }

    #[test]
    fn state_is_readable_after_connect() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        assert_eq!(flow.client().state(), TcpState::Established);
        assert_eq!(flow.server().state(), TcpState::Established);
        Ok(())
    }

    #[test]
    fn close_after_data_exchange() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        flow.client().send(b"data before close")?;
        let _ = flow.server().recv(17)?;

        flow.close()?;

        assert!(is_terminal(flow.client_state()));
        assert!(is_terminal(flow.server_state()));
        Ok(())
    }

    #[test]
    fn reset_after_data_exchange() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        flow.client().send(b"some data")?;
        let _ = flow.server().recv(9)?;

        flow.reset()?;

        assert_eq!(flow.client_state(), TcpState::Closed);
        assert_eq!(flow.server_state(), TcpState::Closed);
        Ok(())
    }

    #[test]
    fn larger_payload_transfers_correctly() -> Result<(), FlowError> {
        let mut harness = make_harness();
        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect()?;

        // Send a payload larger than a single Ethernet frame.
        let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        flow.client().send(&payload)?;
        let received = flow.server().recv(payload.len())?;

        assert_eq!(received, payload, "large payload should transfer intact");
        Ok(())
    }
}
