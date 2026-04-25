// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Types common to port-forwarding and masquerading.
//! While common to both NAT flavors, their use is not dictated here
//! but individually by each NAT flavor implementation.

use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;

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
pub enum NatFlowStatus {
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

impl From<u8> for NatFlowStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => NatFlowStatus::OneWay,
            1 => NatFlowStatus::TwoWay,
            2 => NatFlowStatus::Established,
            3 => NatFlowStatus::Reset,
            4 => NatFlowStatus::CClosing,
            5 => NatFlowStatus::SClosing,
            6 => NatFlowStatus::CHalfClose,
            7 => NatFlowStatus::SHalfClose,
            8 => NatFlowStatus::LastAck,
            9 => NatFlowStatus::Closed,
            _ => unreachable!(),
        }
    }
}
impl From<NatFlowStatus> for u8 {
    fn from(value: NatFlowStatus) -> Self {
        value as u8
    }
}

impl Display for NatFlowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatFlowStatus::OneWay => write!(f, "oneway"),
            NatFlowStatus::TwoWay => write!(f, "twoway"),
            NatFlowStatus::Established => write!(f, "established"),
            NatFlowStatus::Reset => write!(f, "reset"),
            NatFlowStatus::CClosing => write!(f, "client-closing"),
            NatFlowStatus::SClosing => write!(f, "server-closing"),
            NatFlowStatus::CHalfClose => write!(f, "client-half-close"),
            NatFlowStatus::SHalfClose => write!(f, "server-half-close"),
            NatFlowStatus::LastAck => write!(f, "last-ack"),
            NatFlowStatus::Closed => write!(f, "closed"),
        }
    }
}

/// A thread-safe, shareable and mutable wrapper of `NatFlowStatus`
#[derive(Debug, Clone)]
pub struct AtomicNatFlowStatus(Arc<AtomicU8>);
impl AtomicNatFlowStatus {
    #[must_use]
    pub fn new() -> Self {
        AtomicNatFlowStatus(Arc::new(AtomicU8::new(NatFlowStatus::OneWay.into())))
    }

    #[must_use]
    pub fn load(&self) -> NatFlowStatus {
        self.0.load(std::sync::atomic::Ordering::Relaxed).into()
    }

    pub fn store(&self, status: NatFlowStatus) {
        self.0
            .store(status.into(), std::sync::atomic::Ordering::Relaxed);
    }
}
