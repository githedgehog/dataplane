// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Types common to port-forwarding and masquerading.
//! While common to both NAT flavors, their use is not dictated here
//! but individually by each NAT flavor implementation.

use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicU8, Ordering};
use std::fmt::Display;

/// Timeout multiplier for flows in emulated tests.
///
/// Emulation increases the wall-clock time between packet refreshes. Masquerade and port
/// forwarding share this multiplier so both scale their lifetimes under emulation.
pub(crate) const TIMEOUT_SCALE: u64 = cfg_select! {
    emulated => 100,
    _ => 1,
};

/// A type to represent a NAT action
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NatAction {
    /// Nat destination address and ports
    DstNat,
    /// Nat source address and ports
    SrcNat,
}
impl Display for NatAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatAction::DstNat => write!(f, "dnat"),
            NatAction::SrcNat => write!(f, "snat"),
        }
    }
}

/// The status of a flow from the perspective of port forwarding or masquerading.
/// This status is shared between a pair of related flows. How these status change
/// is determined by their users and not prescribed here.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnState {
    OneWay = 0,
    TwoWay = 1,
    Established = 2,
    Reset = 3,
    CClosing = 4,
    SClosing = 5,
    CHalfClose = 6,
    SHalfClose = 7,
    LastAck = 8,
    Closed = 9,
}

impl ConnState {
    /// Tell if the connection is over, closed or reset.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, ConnState::Closed | ConnState::Reset)
    }
}

impl From<u8> for ConnState {
    fn from(value: u8) -> Self {
        match value {
            0 => ConnState::OneWay,
            1 => ConnState::TwoWay,
            2 => ConnState::Established,
            3 => ConnState::Reset,
            4 => ConnState::CClosing,
            5 => ConnState::SClosing,
            6 => ConnState::CHalfClose,
            7 => ConnState::SHalfClose,
            8 => ConnState::LastAck,
            9 => ConnState::Closed,
            _ => unreachable!(),
        }
    }
}
impl From<ConnState> for u8 {
    fn from(value: ConnState) -> Self {
        value as u8
    }
}

impl Display for ConnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnState::OneWay => write!(f, "oneway"),
            ConnState::TwoWay => write!(f, "twoway"),
            ConnState::Established => write!(f, "established"),
            ConnState::Reset => write!(f, "reset"),
            ConnState::CClosing => write!(f, "client-closing"),
            ConnState::SClosing => write!(f, "server-closing"),
            ConnState::CHalfClose => write!(f, "client-half-close"),
            ConnState::SHalfClose => write!(f, "server-half-close"),
            ConnState::LastAck => write!(f, "last-ack"),
            ConnState::Closed => write!(f, "closed"),
        }
    }
}

/// A thread-safe, shareable and mutable wrapper of `NatFlowStatus`
#[derive(Debug, Clone)]
pub struct AtomicNatFlowStatus(Arc<AtomicU8>);
impl AtomicNatFlowStatus {
    #[must_use]
    pub fn new() -> Self {
        AtomicNatFlowStatus(Arc::new(AtomicU8::new(ConnState::OneWay.into())))
    }

    #[must_use]
    pub fn load(&self) -> ConnState {
        self.0.load(Ordering::Relaxed).into()
    }

    pub fn store(&self, status: ConnState) {
        self.0.store(status.into(), Ordering::Relaxed);
    }

    /// Tell if `self` and `other` are the same shared status.
    #[must_use]
    pub fn is_shared_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
