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
use super::flow_state::PortFwAction;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PortFwFlowStatus {
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

impl From<u8> for PortFwFlowStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => PortFwFlowStatus::OneWay,
            1 => PortFwFlowStatus::TwoWay,
            2 => PortFwFlowStatus::Established,
            3 => PortFwFlowStatus::Reset,
            4 => PortFwFlowStatus::CClosing,
            5 => PortFwFlowStatus::SClosing,
            6 => PortFwFlowStatus::CHalfClose,
            7 => PortFwFlowStatus::SHalfClose,
            8 => PortFwFlowStatus::LastAck,
            9 => PortFwFlowStatus::Closed,
            _ => unreachable!(),
        }
    }
}
impl From<PortFwFlowStatus> for u8 {
    fn from(value: PortFwFlowStatus) -> Self {
        value as u8
    }
}

impl Display for PortFwFlowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortFwFlowStatus::OneWay => write!(f, "oneway"),
            PortFwFlowStatus::TwoWay => write!(f, "twoway"),
            PortFwFlowStatus::Established => write!(f, "established"),
            PortFwFlowStatus::Reset => write!(f, "reset"),
            PortFwFlowStatus::CClosing => write!(f, "client-closing"),
            PortFwFlowStatus::SClosing => write!(f, "server-closing"),
            PortFwFlowStatus::CHalfClose => write!(f, "client-half-close"),
            PortFwFlowStatus::SHalfClose => write!(f, "server-half-close"),
            PortFwFlowStatus::LastAck => write!(f, "last-ack"),
            PortFwFlowStatus::Closed => write!(f, "closed"),
        }
    }
}

fn next_flow_status_tcp(pfw_state: &PortFwState, tcp: &Tcp) -> PortFwFlowStatus {
    let status = pfw_state.status.load();
    match pfw_state.action {
        PortFwAction::DstNat => match status {
            PortFwFlowStatus::TwoWay if !tcp.syn() && tcp.ack() => PortFwFlowStatus::Established,
            PortFwFlowStatus::Established if tcp.fin() => PortFwFlowStatus::CClosing,
            PortFwFlowStatus::SClosing if !tcp.fin() && tcp.ack() => PortFwFlowStatus::SHalfClose,
            PortFwFlowStatus::SClosing if tcp.fin() && tcp.ack() => PortFwFlowStatus::LastAck,
            PortFwFlowStatus::SHalfClose if tcp.fin() => PortFwFlowStatus::LastAck,
            PortFwFlowStatus::LastAck if tcp.ack() => PortFwFlowStatus::Closed,
            _other if tcp.rst() => PortFwFlowStatus::Reset,
            other => other,
        },
        PortFwAction::SrcNat => match status {
            PortFwFlowStatus::OneWay if tcp.syn() && tcp.ack() => PortFwFlowStatus::TwoWay,
            PortFwFlowStatus::Established if tcp.fin() => PortFwFlowStatus::SClosing,
            PortFwFlowStatus::CClosing if !tcp.fin() && tcp.ack() => PortFwFlowStatus::CHalfClose,
            PortFwFlowStatus::CClosing if tcp.fin() && tcp.ack() => PortFwFlowStatus::LastAck,
            PortFwFlowStatus::CClosing if !tcp.fin() && tcp.ack() => PortFwFlowStatus::CHalfClose,
            PortFwFlowStatus::CHalfClose if tcp.fin() => PortFwFlowStatus::LastAck,
            PortFwFlowStatus::LastAck if tcp.ack() => PortFwFlowStatus::Closed,
            _other if tcp.rst() => PortFwFlowStatus::Reset,
            other => other,
        },
    }
}
fn next_flow_status_non_tcp(pfw_state: &PortFwState) -> PortFwFlowStatus {
    let status = pfw_state.status.load();
    match pfw_state.action {
        PortFwAction::DstNat => match status {
            PortFwFlowStatus::TwoWay => PortFwFlowStatus::Established,
            other => other,
        },
        PortFwAction::SrcNat => match status {
            PortFwFlowStatus::OneWay => PortFwFlowStatus::TwoWay,
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
) -> PortFwFlowStatus {
    if let Some(tcp) = packet.try_tcp() {
        next_flow_status_tcp(pfw_state, tcp)
    } else {
        next_flow_status_non_tcp(pfw_state)
    }
}

#[derive(Debug, Clone)]
pub struct AtomicPortFwFlowStatus(Arc<AtomicU8>);
impl AtomicPortFwFlowStatus {
    #[must_use]
    pub fn new() -> Self {
        AtomicPortFwFlowStatus(Arc::new(AtomicU8::new(PortFwFlowStatus::OneWay.into())))
    }

    #[must_use]
    pub fn load(&self) -> PortFwFlowStatus {
        self.0.load(std::sync::atomic::Ordering::Relaxed).into()
    }

    pub fn store(&self, status: PortFwFlowStatus) {
        self.0
            .store(status.into(), std::sync::atomic::Ordering::Relaxed);
    }
}
