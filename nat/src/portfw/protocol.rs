// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Types to represent the status of a communication in a port-forwarding context
//! These types do not aim to represent a real state machine for any protocol.
//! The status here modelled is aimed at determining how much the lifetime of a flow
//! entry should be extended, or if it could be removed.

use net::buffer::PacketBufferMut;
use net::headers::TryTcp;
use net::packet::Packet;
use net::tcp::Tcp;
use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;

use super::PortFwState;
use crate::common::NatAction;

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

fn next_flow_status_tcp(pfw_state: &PortFwState, tcp: &Tcp) -> NatFlowStatus {
    let status = pfw_state.status.load();
    match pfw_state.action {
        NatAction::DstNat => match status {
            NatFlowStatus::TwoWay if !tcp.syn() && tcp.ack() => NatFlowStatus::Established,
            NatFlowStatus::Established if tcp.fin() => NatFlowStatus::CClosing,
            NatFlowStatus::SClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::SHalfClose,
            NatFlowStatus::SClosing if tcp.fin() && tcp.ack() => NatFlowStatus::LastAck,
            NatFlowStatus::SHalfClose if tcp.fin() => NatFlowStatus::LastAck,
            NatFlowStatus::LastAck if tcp.ack() => NatFlowStatus::Closed,
            _other if tcp.rst() => NatFlowStatus::Reset,
            other => other,
        },
        NatAction::SrcNat => match status {
            NatFlowStatus::OneWay if tcp.syn() && tcp.ack() => NatFlowStatus::TwoWay,
            NatFlowStatus::Established if tcp.fin() => NatFlowStatus::SClosing,
            NatFlowStatus::CClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::CHalfClose,
            NatFlowStatus::CClosing if tcp.fin() && tcp.ack() => NatFlowStatus::LastAck,
            NatFlowStatus::CClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::CHalfClose,
            NatFlowStatus::CHalfClose if tcp.fin() => NatFlowStatus::LastAck,
            NatFlowStatus::LastAck if tcp.ack() => NatFlowStatus::Closed,
            _other if tcp.rst() => NatFlowStatus::Reset,
            other => other,
        },
    }
}
fn next_flow_status_non_tcp(pfw_state: &PortFwState) -> NatFlowStatus {
    let status = pfw_state.status.load();
    match pfw_state.action {
        NatAction::DstNat => match status {
            NatFlowStatus::TwoWay => NatFlowStatus::Established,
            other => other,
        },
        NatAction::SrcNat => match status {
            NatFlowStatus::OneWay => NatFlowStatus::TwoWay,
            other => other,
        },
    }
}

/// Compute the next `PortFwFlowStatus` of a flow, given the current, the received packet and
/// the direction, which is implicit in the `PortFwAction`:
///     `DstNat` is the forward path and
///     `SrcNat` the reverse path.
pub(crate) fn next_flow_status<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    pfw_state: &PortFwState,
) -> NatFlowStatus {
    if let Some(tcp) = packet.try_tcp() {
        next_flow_status_tcp(pfw_state, tcp)
    } else {
        next_flow_status_non_tcp(pfw_state)
    }
}

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
