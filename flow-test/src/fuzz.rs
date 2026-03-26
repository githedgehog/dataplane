// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bolero-driven property-testing types for TCP flow scenarios.
//!
//! This module provides [`FuzzTcpScenario`] and [`FlowAction`] for
//! generating random but structurally valid TCP interaction sequences.
//! Combined with Bolero's [`check!`](bolero::check) macro these types
//! enable property-based and fuzz testing of the dataplane's packet
//! processing pipeline.
//!
//! # Invariants verified by scenario execution
//!
//! When a [`FuzzTcpScenario`] is [`run`](FuzzTcpScenario::run) through a
//! [`FlowHarness`] the following properties are checked:
//!
//! - Data received on one endpoint equals data sent from the other
//!   (no corruption through the pipe).
//! - The TCP handshake, data transfer, and optional close/reset all
//!   complete within the harness step budget.
//! - No panics, memory errors, or protocol violations occur inside
//!   smoltcp or the pipe closure.
//!
//! # Example
//!
//! ```ignore
//! use dataplane_flow_test::fuzz::FuzzTcpScenario;
//!
//! #[test]
//! fn fuzz_tcp_through_identity_pipe() {
//!     bolero::check!()
//!         .with_type::<FuzzTcpScenario>()
//!         .for_each(|scenario| {
//!             let mut harness = FlowHarness::<TestBuffer, _, _>::new(
//!                 |pkt| Some(pkt),
//!                 |pkt| Some(pkt),
//!             );
//!             scenario.run(&mut harness).expect("scenario should succeed");
//!         });
//! }
//! ```
//!
//! [`FlowHarness`]: crate::harness::FlowHarness

use std::fmt;
use std::ops::Bound;

use bolero::{Driver, TypeGenerator};

use crate::error::FlowError;
use crate::harness::FlowHarness;
use crate::tcp_flow::TcpFlow;
use net::buffer::FrameBuffer;
use net::packet::Packet;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum payload size (in bytes) for generated send actions.
///
/// Kept moderate (4 KiB) so that fuzz iterations complete quickly under
/// `cargo nextest run` while still exercising multi-segment TCP transfers.
const MAX_PAYLOAD_SIZE: usize = 4096;

/// Maximum number of data-transfer actions in a generated scenario.
///
/// A short sequence keeps individual iterations fast; Bolero compensates
/// by running many iterations with different sequences.
const MAX_TRANSFERS: usize = 8;

/// Start of the IANA ephemeral port range.
const EPHEMERAL_PORT_MIN: u16 = 49152;

/// End of the IANA ephemeral port range (inclusive).
const EPHEMERAL_PORT_MAX: u16 = 65535;

/// Minimum server (service) port.
const SERVICE_PORT_MIN: u16 = 1;

/// Maximum server (service) port (inclusive).
///
/// Restricted to the non-ephemeral range to avoid collisions with
/// client ports.
const SERVICE_PORT_MAX: u16 = 49151;

// ---------------------------------------------------------------------------
// FlowAction
// ---------------------------------------------------------------------------

/// An individual action in a [`FuzzTcpScenario`].
///
/// Actions describe what happens **after** the TCP 3-way handshake.
/// [`ClientSend`](Self::ClientSend) and [`ServerSend`](Self::ServerSend)
/// are bidirectional data transfers that also verify payload integrity;
/// [`Close`](Self::Close) and [`Reset`](Self::Reset) terminate the
/// connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowAction {
    /// The client sends `size` bytes to the server.
    ///
    /// The runner generates a deterministic payload via
    /// [`generate_payload`], transmits it from the client endpoint,
    /// receives it on the server endpoint, and verifies byte-for-byte
    /// equality.
    ClientSend {
        /// Number of bytes to transfer.
        size: usize,
    },

    /// The server sends `size` bytes to the client.
    ///
    /// Symmetric to [`ClientSend`](Self::ClientSend) but in the reverse
    /// direction.
    ServerSend {
        /// Number of bytes to transfer.
        size: usize,
    },

    /// Initiate a graceful close (FIN exchange) from the client side.
    ///
    /// Should appear only as the **last** action in a scenario — the
    /// [`FuzzTcpScenario`] [`TypeGenerator`] enforces this.
    Close,

    /// Abort the connection with a RST from the client side.
    ///
    /// Should appear only as the **last** action in a scenario — the
    /// [`FuzzTcpScenario`] [`TypeGenerator`] enforces this.
    Reset,
}

impl fmt::Display for FlowAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientSend { size } => write!(f, "client send ({size} B)"),
            Self::ServerSend { size } => write!(f, "server send ({size} B)"),
            Self::Close => write!(f, "close"),
            Self::Reset => write!(f, "reset"),
        }
    }
}

// ---------------------------------------------------------------------------
// FuzzTcpScenario
// ---------------------------------------------------------------------------

/// A randomly generated TCP flow scenario for property-based testing.
///
/// Each scenario describes a complete TCP interaction: which ports to use
/// and an ordered sequence of [`FlowAction`]s to execute after the
/// handshake.
///
/// # `TypeGenerator` contract
///
/// The [`TypeGenerator`] implementation guarantees:
///
/// | Field          | Range                     |
/// |----------------|---------------------------|
/// | `client_port`  | 49 152 – 65 535           |
/// | `server_port`  | 1 – 49 151                |
/// | payload sizes  | 1 – 4 096 bytes           |
/// | transfer count | 0 – 8                     |
/// | terminator     | at most one, always last  |
///
/// [`Close`](FlowAction::Close) and [`Reset`](FlowAction::Reset) appear
/// **only** as the final action (if present at all).
///
/// # Execution
///
/// Call [`run`](Self::run) with a [`FlowHarness`] to execute the scenario
/// and verify data-integrity invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzTcpScenario {
    /// Ephemeral port for the initiating (client) side.
    pub client_port: u16,
    /// Service port for the accepting (server) side.
    pub server_port: u16,
    /// Ordered sequence of actions to execute after the TCP handshake.
    pub actions: Vec<FlowAction>,
}

impl fmt::Display for FuzzTcpScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP flow {} -> {} ({} actions)",
            self.client_port,
            self.server_port,
            self.actions.len()
        )
    }
}

impl TypeGenerator for FuzzTcpScenario {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        // --- ports ----------------------------------------------------------
        let client_port = d.gen_u16(
            Bound::Included(&EPHEMERAL_PORT_MIN),
            Bound::Included(&EPHEMERAL_PORT_MAX),
        )?;
        let server_port = d.gen_u16(
            Bound::Included(&SERVICE_PORT_MIN),
            Bound::Included(&SERVICE_PORT_MAX),
        )?;

        // --- data-transfer actions ------------------------------------------
        let num_transfers =
            d.gen_usize(Bound::Included(&0), Bound::Included(&MAX_TRANSFERS))?;

        let mut actions = Vec::with_capacity(num_transfers + 1);
        for _ in 0..num_transfers {
            let from_client: bool = d.produce()?;
            let size =
                d.gen_usize(Bound::Included(&1), Bound::Included(&MAX_PAYLOAD_SIZE))?;
            actions.push(if from_client {
                FlowAction::ClientSend { size }
            } else {
                FlowAction::ServerSend { size }
            });
        }

        // --- optional terminator --------------------------------------------
        // 0 → leave the connection open; 1 → Close; 2 → Reset.
        let terminator = d.gen_u8(Bound::Included(&0), Bound::Included(&2))?;
        match terminator {
            1 => actions.push(FlowAction::Close),
            2 => actions.push(FlowAction::Reset),
            _ => { /* leave connection open */ }
        }

        Some(Self {
            client_port,
            server_port,
            actions,
        })
    }
}

// ---------------------------------------------------------------------------
// Payload generation
// ---------------------------------------------------------------------------

/// Generate a deterministic payload of `size` bytes.
///
/// The bytes follow a repeating pattern (`0, 1, 2, …, 250, 0, 1, …`)
/// using modulus 251 (a prime) so the pattern does not align with
/// power-of-two boundaries — making accidental passes from alignment
/// coincidences less likely.
///
/// Returns an empty `Vec` when `size` is zero.
#[must_use]
pub fn generate_payload(size: usize) -> Vec<u8> {
    // 251 is prime; i % 251 is always in 0..=250 which fits in u8.
    #[allow(clippy::cast_possible_truncation)]
    (0..size).map(|i| (i % 251) as u8).collect()
}

// ---------------------------------------------------------------------------
// Scenario execution
// ---------------------------------------------------------------------------

impl FuzzTcpScenario {
    /// Execute this scenario against a [`FlowHarness`].
    ///
    /// 1. Creates a [`TcpFlow`] using [`client_port`](Self::client_port)
    ///    and [`server_port`](Self::server_port).
    /// 2. Drives the TCP 3-way handshake to completion.
    /// 3. Executes each [`FlowAction`] in order:
    ///    - **`ClientSend`** / **`ServerSend`**: sends a deterministic
    ///      payload (see [`generate_payload`]) and verifies the receiver
    ///      gets identical bytes.
    ///    - **`Close`**: performs a graceful FIN exchange.
    ///    - **`Reset`**: aborts with RST.
    ///
    /// # Errors
    ///
    /// Returns [`FlowError`] if the handshake, any data transfer, or the
    /// termination step fails.  A data-integrity mismatch is reported as
    /// [`FlowError::TransferFailed`].
    pub fn run<Buf, FwdPipe, RevPipe>(
        &self,
        harness: &mut FlowHarness<Buf, FwdPipe, RevPipe>,
    ) -> Result<(), FlowError>
    where
        Buf: FrameBuffer,
        FwdPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
        RevPipe: FnMut(Packet<Buf>) -> Option<Packet<Buf>>,
    {
        let mut flow = TcpFlow::new(harness, self.client_port, self.server_port);
        flow.connect()?;

        for (i, action) in self.actions.iter().enumerate() {
            match action {
                FlowAction::ClientSend { size } => {
                    let payload = generate_payload(*size);
                    flow.client().send(&payload)?;
                    let received = flow.server().recv(payload.len())?;
                    if received != payload {
                        return Err(FlowError::TransferFailed {
                            operation: "client-to-server data verify",
                            reason: format!(
                                "data integrity failure at action {i}: \
                                 sent {size} bytes, received different content"
                            ),
                        });
                    }
                }
                FlowAction::ServerSend { size } => {
                    let payload = generate_payload(*size);
                    flow.server().send(&payload)?;
                    let received = flow.client().recv(payload.len())?;
                    if received != payload {
                        return Err(FlowError::TransferFailed {
                            operation: "server-to-client data verify",
                            reason: format!(
                                "data integrity failure at action {i}: \
                                 sent {size} bytes, received different content"
                            ),
                        });
                    }
                }
                FlowAction::Close => flow.close()?,
                FlowAction::Reset => flow.reset()?,
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use net::buffer::TestBuffer;

    // -- generate_payload ---------------------------------------------------

    #[test]
    fn generate_payload_empty() {
        assert!(generate_payload(0).is_empty());
    }

    #[test]
    fn generate_payload_correct_length() {
        for &size in &[1, 100, 251, 1024, 4096] {
            assert_eq!(generate_payload(size).len(), size);
        }
    }

    #[test]
    fn generate_payload_is_deterministic() {
        let a = generate_payload(1024);
        let b = generate_payload(1024);
        assert_eq!(a, b);
    }

    #[test]
    fn generate_payload_uses_prime_modulus() {
        let payload = generate_payload(252);
        // The 251st byte (index 250) should be 250.
        assert_eq!(payload[250], 250);
        // The 252nd byte (index 251) wraps back to 0.
        assert_eq!(payload[251], 0);
    }

    // -- FlowAction display -------------------------------------------------

    #[test]
    fn flow_action_display_client_send() {
        let action = FlowAction::ClientSend { size: 42 };
        assert_eq!(action.to_string(), "client send (42 B)");
    }

    #[test]
    fn flow_action_display_server_send() {
        let action = FlowAction::ServerSend { size: 100 };
        assert_eq!(action.to_string(), "server send (100 B)");
    }

    #[test]
    fn flow_action_display_close() {
        assert_eq!(FlowAction::Close.to_string(), "close");
    }

    #[test]
    fn flow_action_display_reset() {
        assert_eq!(FlowAction::Reset.to_string(), "reset");
    }

    // -- FuzzTcpScenario display --------------------------------------------

    #[test]
    fn scenario_display_includes_ports_and_count() {
        let scenario = FuzzTcpScenario {
            client_port: 49152,
            server_port: 80,
            actions: vec![FlowAction::ClientSend { size: 64 }, FlowAction::Close],
        };
        let display = scenario.to_string();
        assert!(display.contains("49152"), "should show client port");
        assert!(display.contains("80"), "should show server port");
        assert!(display.contains("2 actions"), "should show action count");
    }

    // -- TypeGenerator invariants -------------------------------------------

    #[test]
    fn scenario_generator_produces_valid_port_ranges() {
        bolero::check!()
            .with_type::<FuzzTcpScenario>()
            .for_each(|scenario| {
                assert!(
                    scenario.client_port >= EPHEMERAL_PORT_MIN,
                    "client port {} below ephemeral minimum",
                    scenario.client_port
                );

                assert!(
                    scenario.server_port >= SERVICE_PORT_MIN,
                    "server port {} is zero",
                    scenario.server_port
                );
                assert!(
                    scenario.server_port <= SERVICE_PORT_MAX,
                    "server port {} above service maximum",
                    scenario.server_port
                );
            });
    }

    #[test]
    fn scenario_generator_terminal_actions_only_at_end() {
        bolero::check!()
            .with_type::<FuzzTcpScenario>()
            .for_each(|scenario| {
                for (i, action) in scenario.actions.iter().enumerate() {
                    if matches!(action, FlowAction::Close | FlowAction::Reset) {
                        assert_eq!(
                            i,
                            scenario.actions.len() - 1,
                            "terminal action at index {i} but scenario has {} actions",
                            scenario.actions.len()
                        );
                    }
                }
            });
    }

    #[test]
    fn scenario_generator_payload_sizes_in_range() {
        bolero::check!()
            .with_type::<FuzzTcpScenario>()
            .for_each(|scenario| {
                for action in &scenario.actions {
                    match action {
                        FlowAction::ClientSend { size }
                        | FlowAction::ServerSend { size } => {
                            assert!(
                                *size >= 1,
                                "payload size must be at least 1, got {size}"
                            );
                            assert!(
                                *size <= MAX_PAYLOAD_SIZE,
                                "payload size {size} exceeds maximum {MAX_PAYLOAD_SIZE}"
                            );
                        }
                        FlowAction::Close | FlowAction::Reset => {}
                    }
                }
            });
    }

    #[test]
    fn scenario_generator_bounded_action_count() {
        bolero::check!()
            .with_type::<FuzzTcpScenario>()
            .for_each(|scenario| {
                // At most MAX_TRANSFERS data actions + 1 optional terminator.
                assert!(
                    scenario.actions.len() <= MAX_TRANSFERS + 1,
                    "too many actions: {}",
                    scenario.actions.len()
                );
            });
    }

    // -- Scenario execution -------------------------------------------------

    #[test]
    fn run_succeeds_with_identity_pipe() {
        let scenario = FuzzTcpScenario {
            client_port: 49152,
            server_port: 80,
            actions: vec![
                FlowAction::ClientSend { size: 64 },
                FlowAction::ServerSend { size: 128 },
                FlowAction::Close,
            ],
        };

        let mut harness = FlowHarness::<TestBuffer, _, _>::new(Some, Some);

        scenario.run(&mut harness).unwrap_or_else(|e| {
            unreachable!("identity pipe scenario should succeed: {e}")
        });
    }

    #[test]
    fn run_with_only_close() {
        let scenario = FuzzTcpScenario {
            client_port: 50000,
            server_port: 443,
            actions: vec![FlowAction::Close],
        };

        let mut harness = FlowHarness::<TestBuffer, _, _>::new(Some, Some);

        scenario.run(&mut harness).unwrap_or_else(|e| {
            unreachable!("close-only scenario should succeed: {e}")
        });
    }

    #[test]
    fn run_with_only_reset() {
        let scenario = FuzzTcpScenario {
            client_port: 50001,
            server_port: 8080,
            actions: vec![FlowAction::Reset],
        };

        let mut harness = FlowHarness::<TestBuffer, _, _>::new(Some, Some);

        scenario.run(&mut harness).unwrap_or_else(|e| {
            unreachable!("reset-only scenario should succeed: {e}")
        });
    }

    #[test]
    fn run_with_no_actions() {
        let scenario = FuzzTcpScenario {
            client_port: 50002,
            server_port: 22,
            actions: vec![],
        };

        let mut harness = FlowHarness::<TestBuffer, _, _>::new(Some, Some);

        scenario.run(&mut harness).unwrap_or_else(|e| {
            unreachable!("empty scenario should succeed: {e}")
        });
    }

    #[test]
    fn run_fails_when_pipe_drops_packets() {
        let scenario = FuzzTcpScenario {
            client_port: 49152,
            server_port: 80,
            actions: vec![FlowAction::ClientSend { size: 10 }],
        };

        // Forward pipe drops all packets — the handshake should fail.
        let mut harness =
            FlowHarness::<TestBuffer, _, _>::new(|_pkt| None, Some);

        assert!(
            scenario.run(&mut harness).is_err(),
            "scenario should fail when forward pipe drops packets"
        );
    }
}
