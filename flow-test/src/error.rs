// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Error types for high-level flow operations.
//!
//! [`FlowError`] is the single error type returned by [`TcpFlow`] and
//! [`FlowEndpoint`] methods.  It covers the failure modes that arise when
//! driving a simulated TCP connection through the harness: timeouts,
//! unexpected state transitions, and data transfer failures.
//!
//! [`TcpFlow`]: crate::tcp_flow::TcpFlow
//! [`FlowEndpoint`]: crate::tcp_flow::FlowEndpoint

use crate::tcp_state::TcpState;
use std::fmt;

/// Error returned by high-level flow operations ([`TcpFlow`], [`FlowEndpoint`]).
///
/// [`TcpFlow`]: crate::tcp_flow::TcpFlow
/// [`FlowEndpoint`]: crate::tcp_flow::FlowEndpoint
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// The operation did not complete within the maximum number of
    /// simulation steps.
    ///
    /// This typically means the pipe closure is dropping or delaying
    /// packets, or the connection never reached the expected state.
    Timeout {
        /// What the operation was waiting for when it timed out.
        operation: &'static str,
        /// Maximum number of steps that were attempted.
        max_steps: usize,
    },

    /// The connection entered an unexpected TCP state.
    ///
    /// For example, a `connect()` that finds the socket in `Closed`
    /// rather than `Established` after running the handshake.
    UnexpectedState {
        /// What the operation was trying to do.
        operation: &'static str,
        /// The state the socket was actually in.
        actual: TcpState,
        /// The state the operation expected (if a single state was expected).
        expected: Option<TcpState>,
    },

    /// The socket is not in a valid state for the requested operation.
    ///
    /// For example, attempting to send data on a socket that is not
    /// `Established` or `CloseWait`.
    InvalidState {
        /// What was attempted.
        operation: &'static str,
        /// The state the socket was in.
        state: TcpState,
    },

    /// A data transfer operation failed.
    ///
    /// The inner string describes the smoltcp-level failure reason.
    /// This is intentionally a `String` rather than a smoltcp error type
    /// to maintain the quarantine boundary.
    TransferFailed {
        /// What was attempted (`"send"` or `"recv"`).
        operation: &'static str,
        /// Description of the underlying failure.
        reason: String,
    },
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout {
                operation,
                max_steps,
            } => write!(
                f,
                "{operation} timed out after {max_steps} simulation steps"
            ),
            Self::UnexpectedState {
                operation,
                actual,
                expected: Some(expected),
            } => write!(
                f,
                "{operation}: expected state {expected}, got {actual}"
            ),
            Self::UnexpectedState {
                operation,
                actual,
                expected: None,
            } => write!(f, "{operation}: unexpected state {actual}"),
            Self::InvalidState { operation, state } => {
                write!(f, "{operation}: invalid in state {state}")
            }
            Self::TransferFailed { operation, reason } => {
                write!(f, "{operation} failed: {reason}")
            }
        }
    }
}

impl std::error::Error for FlowError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_display() {
        let err = FlowError::Timeout {
            operation: "connect",
            max_steps: 1000,
        };
        let msg = err.to_string();
        assert!(msg.contains("connect"), "should mention operation");
        assert!(msg.contains("1000"), "should mention step count");
    }

    #[test]
    fn unexpected_state_with_expected_display() {
        let err = FlowError::UnexpectedState {
            operation: "connect",
            actual: TcpState::Closed,
            expected: Some(TcpState::Established),
        };
        let msg = err.to_string();
        assert!(msg.contains("ESTABLISHED"), "should mention expected state");
        assert!(msg.contains("CLOSED"), "should mention actual state");
    }

    #[test]
    fn unexpected_state_without_expected_display() {
        let err = FlowError::UnexpectedState {
            operation: "close",
            actual: TcpState::SynSent,
            expected: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("SYN-SENT"), "should mention actual state");
        assert!(msg.contains("close"), "should mention operation");
    }

    #[test]
    fn invalid_state_display() {
        let err = FlowError::InvalidState {
            operation: "send",
            state: TcpState::Closed,
        };
        let msg = err.to_string();
        assert!(msg.contains("send"), "should mention operation");
        assert!(msg.contains("CLOSED"), "should mention state");
    }

    #[test]
    fn transfer_failed_display() {
        let err = FlowError::TransferFailed {
            operation: "recv",
            reason: "connection reset".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("recv"), "should mention operation");
        assert!(
            msg.contains("connection reset"),
            "should mention reason"
        );
    }

    /// Compile-gate: if `FlowError` ever loses its `std::error::Error` impl
    /// this test will fail to build.  The `&dyn` form additionally asserts
    /// object-safety so callers can use `Box<dyn Error>`, `anyhow`, etc.
    #[test]
    fn flow_error_implements_std_error() {
        fn assert_error(_: &dyn std::error::Error) {}

        let err = FlowError::Timeout {
            operation: "test",
            max_steps: 10,
        };
        assert_error(&err);
    }
}
