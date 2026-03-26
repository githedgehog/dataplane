# In-Process TCP Flow Testing with smoltcp

## Motivation

The dataplane's current test infrastructure constructs individual, disconnected packets
using helpers like `build_test_udp_ipv4_frame()` and feeds them one at a time through
`NetworkFunction::process()`.  This approach verifies header-level rewriting but cannot
exercise the behaviors that only emerge from realistic multi-packet flows:

- TCP 3-way handshakes (SYN → SYN-ACK → ACK) and their interaction with flow creation
- Sequence and acknowledgment number progression across many packets
- FIN and RST teardown and their effect on flow table entries
- Retransmissions hitting an already-translated flow entry
- Many concurrent flows competing for NAT port allocations
- ICMP errors that embed inner headers from previously NATted packets
- Bidirectional traffic where the return path exercises the reverse flow entry

Bugs in NAT and flow-table implementations disproportionately live in these areas.

## Approach

[smoltcp](https://github.com/smoltcp-rs/smoltcp) is a mature, `no_std`-capable TCP/IP
stack with a pluggable physical-layer `Device` trait.  By implementing a custom `Device`
that captures and injects raw Ethernet frames, we can run two smoltcp TCP endpoints
entirely in-process and route their traffic through the dataplane's `NetworkFunction`
pipeline.  This gives us a realistic TCP state machine on both sides of the dataplane
without touching the OS network stack.

## Design Principles

### smoltcp is quarantined

All smoltcp types (`wire::*`, `iface::*`, `phy::*`, `socket::*`) live behind the new
crate's API boundary.  No downstream test ever imports `smoltcp::` directly.  The public
surface speaks exclusively in `net` crate types: `Packet<Buf>`, `Headers`, `Eth`, `Ipv4`,
`Tcp`, `FlowKey`, and so on.

### Generic over `PacketBufferMut`

The harness and bridge are parameterized over `Buf: FrameBuffer` (a small extension trait
over `PacketBufferMut`) rather than hardcoded to `TestBuffer`.  This keeps the door open
for specialized buffer implementations (e.g. one that simulates fragmented mbufs or
constrained headroom) while `TestBuffer` remains the default for most tests.

### A new workspace crate

The existing `test-utils` crate manages real network namespaces (tokio, rtnetlink, caps).
In-process TCP simulation is a fundamentally different concern.  A dedicated
`dataplane-flow-test` crate keeps the dependency graph clean.

### Closure-based pipe, not a `NetworkFunction` dependency

The harness accepts a closure `FnMut(Packet<Buf>) -> Option<Packet<Buf>>` rather than
depending on the `pipeline` crate.  Downstream tests supply their own
`NetworkFunction::process()` calls inside the closure.  This keeps the dependency arrow
pointing in the right direction (nat → flow-test, not the reverse) and avoids cycles.

### Feature-gated, never in the production closure

Follows the `bolero` pattern: optional dependency in crates that expose testing utilities,
dev-dependency in crates that consume them.

---

## Dependency Graph

```text
                    ┌──────────────────────┐
                    │   flow-test           │  (new crate)
                    │   ┌────────────────┐  │
                    │   │ smoltcp (dep)   │  │  ← quarantined inside
                    │   └────────────────┘  │
                    │   depends on: net      │
                    └──────────┬───────────┘
                               │ dev-dep
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                     ▼
    ┌───────────┐       ┌────────────┐       ┌─────────────┐
    │   nat     │       │ flow-entry │       │  (future)   │
    │ (tests)   │       │  (tests)   │       │             │
    └───────────┘       └────────────┘       └─────────────┘
```

`flow-test` depends on `net` (with the `test_buffer` feature).  It does **not** depend on
`pipeline`, `nat`, `flow-entry`, or `config`.  Those crates pull in `flow-test` as a
`[dev-dependency]` and supply their own pipeline logic via closures.

## Data Flow

```text
  ┌──────────────────┐                                         ┌──────────────────┐
  │  smoltcp Client   │                                         │  smoltcp Server   │
  │  Interface        │                                         │  Interface        │
  │  (e.g. 10.0.0.1)  │                                         │ (e.g. 192.168.1.1)│
  └────────┬─────────┘                                         └─────────┬────────┘
           │ raw Ethernet frames                                         │
           ▼                                                             ▲
  ┌────────────────┐    ┌─────────────────────────┐    ┌───────────────────────┐
  │ CaptureDevice  │───▸│  forward_pipe closure    │───▸│  CaptureDevice        │
  │ (collects TX)  │    │  (annotate + NAT + …)    │    │  (injects into RX)    │
  └────────────────┘    └─────────────────────────┘    └───────────────────────┘
           ▲                                                             │
           │                      ◂── return path ──                     │
           │              ┌─────────────────────────┐                    │
           └──────────────│  reverse_pipe closure    │◂──────────────────┘
                          │  (annotate + NAT + …)    │
                          └─────────────────────────┘
```

---

## Phase 0 — Workspace Plumbing

**Goal:** Wire up the new crate so it compiles, is feature-gated, and `cargo deny` passes.

### 0.1 Add `FrameBuffer` trait to `net`

The `FrameBuffer` trait is the single extension point that makes the harness generic.
It belongs in `net::buffer`, gated behind the existing `test_buffer` feature, since it
describes a capability of a buffer type (like `Prepend` or `Tailroom`), not a capability
of the flow-test machinery.

```rust
/// A [`PacketBufferMut`] that can be constructed from a raw Ethernet frame.
///
/// This is the minimum additional capability beyond [`PacketBufferMut`] needed to
/// bridge raw byte arrays (e.g. from an in-process TCP stack) into [`Packet<Buf>`].
pub trait FrameBuffer: PacketBufferMut + Sized {
    /// Construct a buffer whose active region contains exactly `frame`.
    ///
    /// Implementations must provide sufficient headroom and tailroom for
    /// downstream header manipulation (prepend, trim, append).
    fn from_frame(frame: &[u8]) -> Self;
}
```

With the implementation for `TestBuffer`:

```rust
impl FrameBuffer for TestBuffer {
    fn from_frame(frame: &[u8]) -> Self {
        TestBuffer::from_raw_data(frame)
    }
}
```

### 0.2 Add `smoltcp` to workspace dependencies

In `wasm/Cargo.toml` under `[workspace.dependencies]`:

```toml
smoltcp = { version = "0.13.0", default-features = false, features = [] }
```

Features are intentionally left empty at the workspace level.  Each consuming crate
enables exactly the features it needs.

### 0.3 Create the `flow-test` crate

Add `wasm/flow-test/Cargo.toml`:

```toml
[package]
name = "dataplane-flow-test"
edition.workspace = true
license.workspace = true
publish.workspace = true
version.workspace = true

[dependencies]
# Internal
net = { workspace = true, features = ["test_buffer"] }

# External
smoltcp = { workspace = true, features = [
    "medium-ethernet", "proto-ipv4", "socket-tcp", "socket-udp",
    "socket-icmp", "alloc",
] }
tracing = { workspace = true }

[dev-dependencies]
tracing-test = { workspace = true, features = [] }
```

Add to `[workspace.dependencies]`:

```toml
flow-test = { path = "./flow-test", package = "dataplane-flow-test", features = [] }
```

Add `"flow-test"` to the `members` list in `wasm/Cargo.toml`.

### 0.4 Stub `lib.rs`

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! In-process TCP/UDP flow testing for the dataplane.
//!
//! This crate provides a test harness that bridges two smoltcp TCP/IP endpoints
//! through a user-supplied packet processing closure.  All smoltcp types are
//! quarantined behind this crate's public API; consumers interact exclusively
//! with types from the [`net`] crate.
```

### 0.5 Verify

- `cargo check -p dataplane-flow-test` compiles.
- `cargo deny check` passes (smoltcp is BSD-0-Clause; already in the license allowlist).

### Deliverable

A crate that compiles with zero public API.

---

## Phase 1 — CaptureDevice and the Translation Layer

**Goal:** Build the bridge between smoltcp's `phy::Device` trait and `Packet<Buf>`.
This is the isolation layer that prevents smoltcp types from leaking.

### Module Structure

```text
flow-test/src/
├── lib.rs
├── device.rs         # CaptureDevice: smoltcp phy::Device impl
└── bridge.rs         # raw bytes ↔ Packet<Buf> conversion
```

### 1.1 `device.rs` — `CaptureDevice`

This is one of the very few files that directly touches `smoltcp::phy`.  It implements
the smoltcp `Device` trait backed by two `VecDeque<Vec<u8>>` queues:

- `transmit()` pushes the frame onto the TX queue.
- `receive()` pops a frame from the RX queue.
- `capabilities()` returns Ethernet medium, 1514 MTU, `max_burst_size` of 1, with
  checksum validation disabled (the dataplane computes its own checksums, and smoltcp's
  expectations would otherwise conflict).

The struct is `pub(crate)` — never exposed to consumers.  Its interface:

- `drain_tx() -> impl Iterator<Item = Vec<u8>>` — yield all transmitted frames.
- `inject_rx(&mut self, frame: Vec<u8>)` — enqueue a frame for the smoltcp stack to
  receive on its next `poll()`.
- `tx_pending(&self) -> usize` — number of frames waiting in the TX queue.
- `rx_pending(&self) -> usize` — number of frames waiting in the RX queue.

### 1.2 `bridge.rs` — The Translation Layer

Two public functions.  These are the **entire boundary** between the smoltcp world (raw
`&[u8]`) and the `net` crate world (`Packet<Buf>`).

```rust
use net::buffer::FrameBuffer;
use net::packet::Packet;

/// Convert a raw Ethernet frame into a [`Packet<Buf>`].
///
/// Returns `None` if the frame does not parse as a valid Ethernet packet.
pub fn frame_to_packet<Buf: FrameBuffer>(raw: &[u8]) -> Option<Packet<Buf>> {
    let buf = Buf::from_frame(raw);
    Packet::new(buf).ok()
}

/// Serialize a [`Packet<Buf>`] back to a raw Ethernet frame.
///
/// Returns `None` if serialization fails (e.g. insufficient headroom).
pub fn packet_to_frame<Buf: FrameBuffer>(packet: Packet<Buf>) -> Option<Vec<u8>> {
    let buf = packet.serialize().ok()?;
    Some(buf.as_ref().to_vec())
}
```

### Deliverable

Unit tests proving:

- A raw Ethernet frame (constructed by hand or via smoltcp `wire` helpers inside the
  test module) round-trips through `frame_to_packet` → `packet_to_frame` without data
  loss.
- `frame_to_packet` on a valid TCP/IPv4/Ethernet frame yields a `Packet` whose
  `try_tcp()`, `try_ipv4()`, and `try_eth()` all return `Some`.
- `frame_to_packet` on garbage bytes returns `None`.

---

## Phase 2 — Endpoint and Harness Core

**Goal:** Build `Endpoint` (wraps one smoltcp stack) and `FlowHarness` (connects two
endpoints through user-supplied pipe closures).

### Module Additions

```text
flow-test/src/
├── ...
├── endpoint.rs       # Endpoint: wraps smoltcp Interface + SocketSet + CaptureDevice
├── harness.rs        # FlowHarness: orchestrates two Endpoints
└── time.rs           # Deterministic simulated clock
```

### 2.1 `time.rs` — Simulated Clock

smoltcp's `Interface::poll()` accepts an `Instant`.  The harness owns a monotonic
simulated clock that advances in controlled increments per step.  This makes tests
fully deterministic and allows deliberately testing timeout behavior by jumping forward.

```rust
/// A deterministic clock for driving smoltcp's time-dependent behavior.
pub struct SimClock { /* smoltcp::time::Instant internally */ }

impl SimClock {
    /// Create a clock starting at time zero.
    pub fn new() -> Self { ... }

    /// Current simulated time.
    pub fn now(&self) -> smoltcp::time::Instant { ... } // pub(crate) return type

    /// Advance the clock by `duration`.
    pub fn advance(&mut self, duration: Duration) { ... }
}
```

The `smoltcp::time::Instant` return is `pub(crate)`; the public API uses
`std::time::Duration` for advancing.

### 2.2 `endpoint.rs` — `Endpoint`

Wraps a smoltcp `Interface` + `SocketSet` + `CaptureDevice` into one unit.
This is `pub(crate)`.

- Constructed with an IP address, MAC address, and gateway.
- Provides socket creation helpers (TCP listen, TCP connect, UDP bind).
- `poll(clock)` drives the smoltcp state machine.
- Exposes the `CaptureDevice` for frame exchange.

### 2.3 `harness.rs` — `FlowHarness`

The central orchestrator.  Generic over `Buf: FrameBuffer`:

```rust
pub struct FlowHarness<Buf, FwdPipe, RevPipe>
where
    Buf: FrameBuffer,
    FwdPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
    RevPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
{
    client: Endpoint,
    server: Endpoint,
    forward_pipe: FwdPipe,
    reverse_pipe: RevPipe,
    clock: SimClock,
    // ... counters, optional pcap writer, etc.
}
```

The two pipe closures allow asymmetric processing (e.g., different VPC discriminants on
the forward vs. reverse path).  A convenience constructor accepts a single symmetric pipe.

#### The `step()` loop

```rust
impl<Buf, F, R> FlowHarness<Buf, F, R>
where
    Buf: FrameBuffer,
    F: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
    R: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
{
    /// Advance the simulation by one tick:
    ///
    /// 1. Poll client smoltcp stack.
    /// 2. Drain client TX → `frame_to_packet` → `forward_pipe` →
    ///    `packet_to_frame` → inject into server RX.
    /// 3. Poll server smoltcp stack.
    /// 4. Drain server TX → `frame_to_packet` → `reverse_pipe` →
    ///    `packet_to_frame` → inject into client RX.
    ///
    /// Returns the number of packets exchanged.
    pub fn step(&mut self) -> usize { ... }

    /// Run steps until no packets are exchanged (quiescent) or a maximum
    /// iteration count is reached.
    pub fn run_until_idle(&mut self) -> usize { ... }

    /// Run steps until a predicate returns true or a maximum iteration
    /// count is reached.
    pub fn run_until(
        &mut self,
        pred: impl FnMut(&Self) -> bool,
    ) -> usize { ... }

    /// Advance simulated time by `duration` without exchanging packets.
    /// Useful for testing idle timeouts.
    pub fn advance_time(&mut self, duration: Duration) { ... }

    /// Get the current simulated time as a `Duration` since start.
    pub fn elapsed(&self) -> Duration { ... }
}
```

#### ARP handling

Both endpoints are configured on the same /24 subnet so ARP works naturally via the
frame exchange.  Non-IP frames (ARP) pass through the pipe closure, which can inspect
`try_eth().ether_type()` and pass them through unmodified.  The bridge module should
provide a helper for this pattern:

```rust
/// Returns `true` if the packet is an IPv4 packet (i.e., not ARP or other
/// non-IP traffic that should typically be passed through unmodified).
pub fn is_ipv4<Buf: FrameBuffer>(pkt: &Packet<Buf>) -> bool { ... }
```

### Deliverable

A test that creates a `FlowHarness` with identity pipes (`|pkt| Some(pkt)`) and verifies
that a TCP SYN-ACK handshake completes between client and server.  This proves the
plumbing works end-to-end without any dataplane logic in the path.

---

## Phase 3 — High-Level Flow API

**Goal:** Provide ergonomic methods for TCP/UDP operations so tests read like scenario
descriptions rather than state machine drivers.

### Module Additions

```text
flow-test/src/
├── ...
├── tcp_flow.rs       # TcpFlow and FlowEndpoint
├── tcp_state.rs      # TcpState enum (net-native, no smoltcp leakage)
├── udp_flow.rs       # UdpFlow (simpler)
└── error.rs          # FlowError
```

### 3.1 `tcp_state.rs` — `TcpState`

A `net`-native enum mirroring the RFC 793 state machine.  Defined here so consumers
never import `smoltcp::socket::tcp::State`.

```rust
/// TCP connection state (RFC 793).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}
```

With a `pub(crate) fn from_smoltcp(state: smoltcp::socket::tcp::State) -> TcpState`
conversion function.

### 3.2 `tcp_flow.rs` — `TcpFlow` and `FlowEndpoint`

```rust
/// A handle to a TCP connection managed by the harness.
///
/// The "client" is the side that initiated the connection (sent the SYN).
/// The "server" is the side that accepted it.  Both sides can send and
/// receive — TCP is full-duplex.
pub struct TcpFlow<'h, Buf: FrameBuffer> { /* borrows harness */ }

impl<Buf: FrameBuffer> TcpFlow<'_, Buf> {
    /// Drive the TCP 3-way handshake to completion.
    pub fn connect(&mut self) -> Result<(), FlowError> { ... }

    /// Initiate graceful close (FIN exchange) from the client side.
    pub fn close(&mut self) -> Result<(), FlowError> { ... }

    /// Send RST from the client side.
    pub fn reset(&mut self) -> Result<(), FlowError> { ... }

    /// Access the client (initiating) side of the connection.
    pub fn client(&mut self) -> FlowEndpoint<'_, Buf> { ... }

    /// Access the server (accepting) side of the connection.
    pub fn server(&mut self) -> FlowEndpoint<'_, Buf> { ... }
}
```

```rust
/// One side of a TCP connection.
pub struct FlowEndpoint<'a, Buf: FrameBuffer> { /* borrows TcpFlow */ }

impl<Buf: FrameBuffer> FlowEndpoint<'_, Buf> {
    /// Send data from this endpoint to the peer.
    /// Drives harness steps until all data is transmitted and acknowledged.
    pub fn send(&mut self, data: &[u8]) -> Result<(), FlowError> { ... }

    /// Receive data that the peer sent to this endpoint.
    /// Drives harness steps until `expected_len` bytes arrive.
    pub fn recv(&mut self, expected_len: usize) -> Result<Vec<u8>, FlowError> { ... }

    /// Query this endpoint's TCP state.
    pub fn state(&self) -> TcpState { ... }
}
```

Each method internally calls `harness.run_until(...)` with the appropriate predicate.

A typical test then reads naturally:

```rust
let mut flow = harness.open_tcp(49152, 80)?;
flow.connect()?;

flow.client().send(b"GET / HTTP/1.1\r\n\r\n")?;
let request = flow.server().recv(expected_len)?;

flow.server().send(b"HTTP/1.1 200 OK\r\n\r\n")?;
let response = flow.client().recv(expected_len)?;

flow.close()?;
```

### 3.3 `udp_flow.rs` — `UdpFlow`

A simpler version for UDP.  Since UDP is connectionless, this is essentially a pair of
bound sockets with `send_to()` / `recv_from()` semantics.

### Deliverable

Tests proving:

- `TcpFlow::connect()` + `client().send()` + `server().recv()` + `close()` works through
  an identity pipe.
- `TcpFlow::connect()` fails (returns `FlowError`) when the forward pipe drops SYN
  packets.
- `server().send()` + `client().recv()` transfers data in the reverse direction.
- `TcpFlow::reset()` transitions both sides to appropriate states.

---

## Phase 4 — Metadata Annotation Helpers

**Goal:** Provide reusable annotation helpers so each NAT test does not need to manually
wire up VPC discriminants and pipeline flags.

This phase can proceed in parallel with Phases 2 and 3 since it only depends on the
`net` crate types.

### Module Addition

```text
flow-test/src/
├── ...
└── annotate.rs       # Reusable metadata annotation builder
```

### 4.1 `Annotator`

```rust
/// Builder for constructing packet metadata annotations.
///
/// Many dataplane pipeline stages expect specific metadata flags
/// (overlay, stateful NAT, VPC discriminants) to be set before
/// processing.  `Annotator` provides a composable way to build
/// the annotation logic once and apply it to many packets.
pub struct Annotator {
    overlay: bool,
    stateful_nat: bool,
    src_vpcd: Option<VpcDiscriminant>,
    dst_vpcd: Option<VpcDiscriminant>,
    // extensible with additional fields as needed
}

impl Annotator {
    pub fn new() -> Self { ... }
    pub fn overlay(mut self) -> Self { ... }
    pub fn stateful_nat(mut self) -> Self { ... }
    pub fn src_vpcd(mut self, v: VpcDiscriminant) -> Self { ... }
    pub fn dst_vpcd(mut self, v: VpcDiscriminant) -> Self { ... }

    /// Apply this annotation to a packet in place.
    pub fn annotate<Buf: PacketBufferMut>(&self, pkt: &mut Packet<Buf>) { ... }
}
```

`VpcDiscriminant`, `Vni`, etc. come from the `net` crate, which is already a dependency.
This module needs no knowledge of `pipeline` or `nat`.

### 4.2 Usage pattern

A test composes annotation with pipeline processing:

```rust
let ann = Annotator::new()
    .overlay()
    .stateful_nat()
    .src_vpcd(VpcDiscriminant::from_vni(vni(100)))
    .dst_vpcd(VpcDiscriminant::from_vni(vni(200)));

let harness = FlowHarness::new(|mut pkt| {
    ann.annotate(&mut pkt);
    nat.process(std::iter::once(pkt)).next()
});
```

### 4.3 Non-IP passthrough helper

A wrapper that applies the pipe only to IPv4/IPv6 packets and passes ARP and other
non-IP frames through unmodified:

```rust
/// Wrap a pipe closure so that non-IP frames (ARP, etc.) are passed through
/// without processing.
pub fn ip_only<Buf, F>(mut inner: F) -> impl FnMut(Packet<Buf>) -> Option<Packet<Buf>>
where
    Buf: FrameBuffer,
    F: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
{
    move |pkt| {
        if is_ipv4(&pkt) || is_ipv6(&pkt) {
            inner(pkt)
        } else {
            Some(pkt)
        }
    }
}
```

### Deliverable

Unit tests verifying:

- `Annotator` correctly sets all `PacketMeta` flags.
- `ip_only` passes ARP frames through and delegates IPv4 frames to the inner closure.

---

## Phase 5 — First NAT Integration Tests

**Goal:** Write the first real tests exercising `StatefulNat`, `FlowLookup`, and
`FlowTable` with realistic TCP traffic.

### Where These Tests Live

In `wasm/nat/`, either in the existing `src/stateful/test.rs` or a new
`src/stateful/flow_test.rs`, alongside the existing single-packet tests.

```toml
# wasm/nat/Cargo.toml
[dev-dependencies]
flow-test = { workspace = true }
```

### 5.1 TCP handshake through stateful NAT

- Configure NAT with a known address mapping (reuse existing overlay builders).
- `TcpFlow::connect()` through the NAT pipe.
- Verify forward and reverse flow table entries exist with correct `FlowKey`s.
- Verify that after the handshake, `client().send()` + `server().recv()` transfers
  data correctly (sequence numbers survive NAT).

### 5.2 TCP close through stateful NAT

- After an established connection, `flow.close()`.
- Verify FIN packets are correctly NATted in both directions.
- Verify flow table entries are still present (idle-timeout-based, not FIN-based, per
  the current implementation).

### 5.3 TCP RST through stateful NAT

- After an established connection, `flow.reset()`.
- Verify RST is correctly translated on both paths.

### 5.4 Concurrent TCP flows competing for port allocations

- Open N TCP connections through NAT, each on a different client port.
- Verify each gets a unique translated source port.
- Verify all N can exchange data simultaneously (interleave `client().send()` and
  `server().recv()` across flows).

### 5.5 Connection after flow expiry

- Establish a connection.
- `harness.advance_time(...)` past the idle timeout.
- Attempt a new connection on the same 5-tuple.
- Verify a new flow table entry is created (not a stale hit on the expired one).

### Deliverable

The test suite passes under `cargo nextest run`.  These tests exercise the actual
`StatefulNat` implementation with multi-packet TCP flows for the first time.

---

## Phase 6 — Advanced Scenarios and Bolero Integration

**Goal:** Leverage the harness for property-based / fuzz testing and edge-case coverage.

### 6.1 Bolero-driven flow testing

Add an optional `bolero` feature to `flow-test`:

```toml
[features]
default = []
bolero = ["dep:bolero", "net/bolero"]

[dependencies]
bolero = { workspace = true, optional = true }
```

Provide `TypeGenerator` / `ValueGenerator` implementations for flow scenarios:

```rust
/// A randomly generated TCP flow scenario.
pub struct FuzzTcpScenario {
    pub client_port: u16,
    pub server_port: u16,
    pub payload_sizes: Vec<usize>,
    pub actions: Vec<FlowAction>,  // Send, Recv, Close, Reset, Wait, ...
}
```

Bolero generates entire interaction sequences; the test verifies invariants:

- Every NATted packet has a valid reverse flow entry.
- Port allocations are unique across concurrent flows.
- Data received equals data sent (no corruption through NAT).
- Flow table size is bounded.

### 6.2 ICMP error testing

smoltcp's `socket-icmp` feature enables ICMP send/receive.  Build scenarios that
generate ICMP Destination Unreachable messages whose inner IP header references a
NATted flow.  Verify the `IcmpErrorHandler` correctly un-translates the embedded
5-tuple.

### 6.3 Pcap capture

An optional method on the harness for debugging test failures:

```rust
impl<...> FlowHarness<...> {
    /// Enable pcap capture of all frames exchanged through the harness.
    /// Frames are captured at both the pre-pipe and post-pipe stage.
    pub fn enable_pcap(&mut self, path: impl AsRef<Path>) { ... }
}
```

This is implemented at the harness level (not the smoltcp device level) so that it
captures frames as they transit the pipe, showing pre-NAT and post-NAT views.

### Deliverable

Bolero fuzz tests that run briefly under `cargo nextest run` and are designed to run
under a full fuzzing engine via `just fuzz` once that recipe lands.

---

## Phase 7 — Documentation and CI

**Goal:** Make the harness usable by other developers without an oral tradition.

### 7.1 Crate-level rustdoc

A worked example in the `lib.rs` doc comment showing a NAT test end-to-end.

### 7.2 `flow-test/README.md`

Explains:

- What the crate does and does not do.
- The isolation boundary (smoltcp types never leak).
- How to write a new flow test.
- How to debug failures (pcap capture, tracing).

### 7.3 Update `testing.md`

Add a section on flow testing alongside the existing sections on nextest, llvm-cov,
and bolero.

### 7.4 CI

The tests are normal `#[test]` functions, so they run under `cargo nextest run` with
no special CI changes.  Verify they also appear in `just coverage` output.

### 7.5 `deny.toml`

If smoltcp's transitive deps cause version duplication warnings, add appropriate
`[[bans.skip]]` entries.  In `no_std` configuration, smoltcp's dependency tree is
minimal: `managed`, `heapless`, `bitflags`, `byteorder` — all MIT/Apache-2.0 licensed.

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| smoltcp ARP frames confuse the NAT pipe | The `ip_only()` helper (Phase 4) wraps a pipe closure so non-IP frames pass through unmodified. |
| smoltcp checksum expectations conflict with dataplane checksums | Disable smoltcp's checksum validation via `DeviceCapabilities::checksum` in the `CaptureDevice`. |
| Wall-clock non-determinism | The `SimClock` (Phase 2) owns a monotonic simulated clock.  Tests advance it explicitly.  No wall-clock dependency. |
| smoltcp TCP retransmit timers fire unexpectedly | With deterministic time, retransmissions only happen when the test explicitly advances time.  This is a feature: it lets you test retransmission behavior deliberately. |
| Large dependency added to workspace | smoltcp with the selected features has minimal transitive deps.  All are permissively licensed.  Compile-time impact is small. |
| `FrameBuffer` trait too narrow or too wide | The trait has a single method.  If additional capabilities are needed later, it can be extended with default methods or supertraits without breaking existing impls. |

## Effort Estimates and Ordering

| Phase | Est. Effort | Depends On | Parallelizable With |
|-------|------------|------------|---------------------|
| Phase 0: Workspace plumbing | Small | — | — |
| Phase 1: CaptureDevice + bridge | Medium | Phase 0 | — |
| Phase 2: Endpoint + harness core | Medium | Phase 1 | Phase 4 |
| Phase 3: High-level flow API | Medium | Phase 2 | Phase 4 |
| Phase 4: Annotation helpers | Small | Phase 0 | Phases 2, 3 |
| Phase 5: NAT integration tests | Medium–Large | Phases 3 + 4 | — |
| Phase 6: Bolero + advanced | Large | Phase 5 | — |
| Phase 7: Docs + CI | Small | Phase 5 | Phase 6 |

Phases 0–3 are the critical path.  Phase 4 can proceed in parallel once the `FrameBuffer`
trait exists.  Phase 5 is where the investment pays off — real bugs found in NAT/flow
handling.  Phase 6 is where the investment compounds via fuzz-driven discovery.
