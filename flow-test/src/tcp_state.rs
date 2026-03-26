// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Net-native TCP connection state enum.
//!
//! [`TcpState`] mirrors the [RFC 793] state machine so that downstream
//! consumers never need to import `smoltcp::socket::tcp::State`.
//! A `pub(crate)` conversion bridges the two representations inside this
//! crate.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

use smoltcp::socket::tcp;
use std::fmt;

/// TCP connection state ([RFC 793]).
///
/// This enum is intentionally defined outside of smoltcp so that the
/// flow-test public API speaks exclusively in `net`-native types.
///
/// [RFC 793]: https://www.rfc-editor.org/rfc/rfc793
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    /// No connection state at all.
    Closed,
    /// Waiting for a connection request from any remote TCP and port.
    Listen,
    /// Waiting for a matching connection request after having sent one.
    SynSent,
    /// Waiting for a confirming connection request acknowledgment.
    SynReceived,
    /// An open connection; data can be sent and received.
    Established,
    /// Waiting for a connection termination request from the remote TCP,
    /// or an acknowledgment of the previously sent termination request.
    FinWait1,
    /// Waiting for a connection termination request from the remote TCP.
    FinWait2,
    /// Waiting for a connection termination request from the local user.
    CloseWait,
    /// Waiting for a connection termination request acknowledgment from
    /// the remote TCP.
    Closing,
    /// Waiting for an acknowledgment of the connection termination
    /// request previously sent to the remote TCP.
    LastAck,
    /// Waiting for enough time to pass to be sure the remote TCP
    /// received the acknowledgment of its connection termination request.
    TimeWait,
}

impl TcpState {
    /// Convert from smoltcp's internal TCP state representation.
    ///
    /// This is `pub(crate)` so that the smoltcp type never leaks through
    /// the public API.
    pub(crate) fn from_smoltcp(state: tcp::State) -> Self {
        match state {
            tcp::State::Closed => Self::Closed,
            tcp::State::Listen => Self::Listen,
            tcp::State::SynSent => Self::SynSent,
            tcp::State::SynReceived => Self::SynReceived,
            tcp::State::Established => Self::Established,
            tcp::State::FinWait1 => Self::FinWait1,
            tcp::State::FinWait2 => Self::FinWait2,
            tcp::State::CloseWait => Self::CloseWait,
            tcp::State::Closing => Self::Closing,
            tcp::State::LastAck => Self::LastAck,
            tcp::State::TimeWait => Self::TimeWait,
        }
    }

    /// Returns `true` if the connection is fully open and can transfer data.
    #[must_use]
    pub fn is_established(self) -> bool {
        self == Self::Established
    }

    /// Returns `true` if the connection is fully closed.
    #[must_use]
    pub fn is_closed(self) -> bool {
        self == Self::Closed
    }

    /// Returns `true` if the connection is in a closing state
    /// (`FinWait1`, `FinWait2`, `Closing`, `LastAck`, `TimeWait`, or
    /// `CloseWait`).
    #[must_use]
    pub fn is_closing(self) -> bool {
        matches!(
            self,
            Self::FinWait1
                | Self::FinWait2
                | Self::Closing
                | Self::LastAck
                | Self::TimeWait
                | Self::CloseWait
        )
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "CLOSED"),
            Self::Listen => write!(f, "LISTEN"),
            Self::SynSent => write!(f, "SYN-SENT"),
            Self::SynReceived => write!(f, "SYN-RECEIVED"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::FinWait1 => write!(f, "FIN-WAIT-1"),
            Self::FinWait2 => write!(f, "FIN-WAIT-2"),
            Self::CloseWait => write!(f, "CLOSE-WAIT"),
            Self::Closing => write!(f, "CLOSING"),
            Self::LastAck => write!(f, "LAST-ACK"),
            Self::TimeWait => write!(f, "TIME-WAIT"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustively verify that every smoltcp state maps to the correct
    /// [`TcpState`] variant.
    #[test]
    fn from_smoltcp_is_exhaustive_and_correct() {
        let pairs = [
            (tcp::State::Closed, TcpState::Closed),
            (tcp::State::Listen, TcpState::Listen),
            (tcp::State::SynSent, TcpState::SynSent),
            (tcp::State::SynReceived, TcpState::SynReceived),
            (tcp::State::Established, TcpState::Established),
            (tcp::State::FinWait1, TcpState::FinWait1),
            (tcp::State::FinWait2, TcpState::FinWait2),
            (tcp::State::CloseWait, TcpState::CloseWait),
            (tcp::State::Closing, TcpState::Closing),
            (tcp::State::LastAck, TcpState::LastAck),
            (tcp::State::TimeWait, TcpState::TimeWait),
        ];

        for (smoltcp_state, expected) in pairs {
            assert_eq!(
                TcpState::from_smoltcp(smoltcp_state),
                expected,
                "mismatch for smoltcp state {smoltcp_state}"
            );
        }
    }

    #[test]
    fn is_established_predicate() {
        assert!(TcpState::Established.is_established());
        assert!(!TcpState::Closed.is_established());
        assert!(!TcpState::SynSent.is_established());
    }

    #[test]
    fn is_closed_predicate() {
        assert!(TcpState::Closed.is_closed());
        assert!(!TcpState::Established.is_closed());
        assert!(!TcpState::TimeWait.is_closed());
    }

    #[test]
    fn is_closing_predicate() {
        let closing_states = [
            TcpState::FinWait1,
            TcpState::FinWait2,
            TcpState::Closing,
            TcpState::LastAck,
            TcpState::TimeWait,
            TcpState::CloseWait,
        ];
        for state in closing_states {
            assert!(state.is_closing(), "{state} should be closing");
        }

        let non_closing = [
            TcpState::Closed,
            TcpState::Listen,
            TcpState::SynSent,
            TcpState::SynReceived,
            TcpState::Established,
        ];
        for state in non_closing {
            assert!(!state.is_closing(), "{state} should NOT be closing");
        }
    }

    #[test]
    fn display_matches_rfc_conventions() {
        assert_eq!(TcpState::Closed.to_string(), "CLOSED");
        assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpState::SynSent.to_string(), "SYN-SENT");
        assert_eq!(TcpState::FinWait1.to_string(), "FIN-WAIT-1");
        assert_eq!(TcpState::TimeWait.to_string(), "TIME-WAIT");
    }
}
