// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The NAT state a flow carries.
//!
//! A flow is created by one NAT stage (masquerade, port forwarding, static NAT, or plain tracking)
//! and carries that stage's state inline, in [`NatFlowState`]: no separate allocation for the
//! packet path to chase. A masquerade mapping, which belongs to the NAT crate, is kept here only as
//! an opaque owner the packet path does not follow.

use crate::flows::atomic_instant::AtomicInstant;
use crate::flows::flow_info_item::FlowInfoItem;
use crate::ip::UnicastIpAddr;
use crate::tcp::port::TcpPort;
use crate::udp::port::UdpPort;
use concurrency::sync::Arc;
use concurrency::sync::atomic::Ordering;
use std::any::Any;
use std::fmt::{self, Debug, Display};
use std::num::NonZero;
use std::time::Duration;

/// A type to represent a NAT action
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NatAction {
    /// Nat destination address and ports
    DstNat,
    /// Nat source address and ports
    SrcNat,
}

impl Display for NatAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatAction::DstNat => write!(f, "dnat"),
            NatAction::SrcNat => write!(f, "snat"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NatPortError {
    #[error("invalid port ({0})")]
    InvalidPort(u16),
    #[error("wrong type (port/identfier {0})")]
    WrongType(u16),
}

/// `NatPort` is a type to represent L4 ports (TCP/UDP) or identifier (ICMP v4, v6) usable in
/// stateful NAT.
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatPort {
    Port(NonZero<u16>),
    Identifier(u16),
}

impl std::fmt::Display for NatPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatPort::Port(port) => write!(f, "port:{}", port.get()),
            NatPort::Identifier(id) => write!(f, "id:{id}"),
        }
    }
}

impl NatPort {
    #[must_use]
    pub fn new_port(port: NonZero<u16>) -> NatPort {
        NatPort::Port(port)
    }

    /// A port from a raw value.
    ///
    /// # Errors
    ///
    /// Returns [`NatPortError::InvalidPort`] for port 0.
    pub fn new_port_checked(port: u16) -> Result<NatPort, NatPortError> {
        NonZero::new(port).map_or(Err(NatPortError::InvalidPort(port)), |port| {
            Ok(NatPort::Port(port))
        })
    }

    #[must_use]
    pub fn new_identifier(port: u16) -> NatPort {
        NatPort::Identifier(port)
    }

    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            NatPort::Port(port) => port.into(),
            NatPort::Identifier(port) => port,
        }
    }
}

impl From<TcpPort> for NatPort {
    fn from(port: TcpPort) -> Self {
        Self::new_port(port.into())
    }
}

impl TryFrom<NatPort> for TcpPort {
    type Error = NatPortError;

    fn try_from(port: NatPort) -> Result<Self, Self::Error> {
        match port {
            NatPort::Port(port) => Ok(TcpPort::new(port)),
            NatPort::Identifier(id) => Err(NatPortError::WrongType(id)),
        }
    }
}

impl From<UdpPort> for NatPort {
    fn from(port: UdpPort) -> Self {
        Self::new_port(port.into())
    }
}

impl TryFrom<NatPort> for UdpPort {
    type Error = NatPortError;

    fn try_from(port: NatPort) -> Result<Self, Self::Error> {
        match port {
            NatPort::Port(port) => Ok(UdpPort::new(port)),
            NatPort::Identifier(id) => Err(NatPortError::WrongType(id)),
        }
    }
}

impl TryFrom<NatPort> for NonZero<u16> {
    type Error = NatPortError;

    fn try_from(port: NatPort) -> Result<Self, Self::Error> {
        port.as_u16()
            .try_into()
            .map_err(|_| NatPortError::InvalidPort(port.as_u16()))
    }
}

impl From<NatPort> for u16 {
    fn from(port: NatPort) -> Self {
        port.as_u16()
    }
}

/// Something a flow keeps alive for the NAT crate, without knowing or touching it.
pub struct Owned(Box<dyn Any + Send + Sync>);

impl Owned {
    /// Keep `value` alive for as long as the flow lives.
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self(Box::new(value))
    }

    /// The value, if it is a `T`.
    #[must_use]
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }
}

impl Debug for Owned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Owned(..)")
    }
}

/// The deadline of a masquerade mapping, shared with the mapping, so that outbound traffic can
/// refresh it (RFC 4787 REQ-6) without reaching the mapping itself.
#[derive(Debug, Clone)]
pub struct MappingDeadline {
    expires_at: Arc<AtomicInstant>,
    idle_timeout: Duration,
}

impl MappingDeadline {
    /// A mapping deadline `idle_timeout` from now.
    #[must_use]
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            expires_at: Arc::new(AtomicInstant::new(clock::deadline(idle_timeout))),
            idle_timeout,
        }
    }

    /// When the mapping expires.
    #[must_use]
    pub fn expires_at(&self) -> std::time::Instant {
        self.expires_at.load(Ordering::Relaxed)
    }

    /// Push the deadline to `idle_timeout` from now. Several flows on several cores may refresh
    /// the same mapping at once, and the deadline must never go backwards.
    pub fn refresh(&self) {
        let new = clock::deadline(self.idle_timeout);
        self.expires_at.fetch_max(new, Ordering::Relaxed);
    }
}

/// What a masqueraded flow translates to, and for the outbound half, the mapping it holds.
#[derive(Debug)]
pub struct MasqueradeFlow {
    pub action: NatAction,
    pub use_ip: UnicastIpAddr,
    pub use_port: NatPort,
    pub idle_timeout: Duration,
    /// The outbound half's mapping: its deadline, and the mapping itself (owned by the NAT crate).
    pub mapping: Option<(MappingDeadline, Owned)>,
}

/// The NAT state of a flow: which stage created it, and that stage's state.
#[derive(Debug, Default)]
pub enum NatFlowState {
    /// Not created by a NAT or tracking stage.
    #[default]
    None,
    /// Masqueraded.
    Masquerade(MasqueradeFlow),
    /// Port-forwarded. Port forwarding's state holds its rule, which lives in the NAT crate, so it
    /// stays boxed there for now; it is off the masquerade path.
    PortForward(Box<dyn FlowInfoItem>),
    /// Tracked by static NAT.
    StaticNat,
    /// Tracked without NAT (for flow-scoped ACLs).
    Tracked,
}

impl NatFlowState {
    #[must_use]
    pub fn is_masquerade(&self) -> bool {
        matches!(self, Self::Masquerade(_))
    }

    #[must_use]
    pub fn is_port_forward(&self) -> bool {
        matches!(self, Self::PortForward(_))
    }

    /// Tracked, by static NAT or without NAT.
    #[must_use]
    pub fn is_tracked(&self) -> bool {
        matches!(self, Self::StaticNat | Self::Tracked)
    }
}

impl Display for MasqueradeFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            " {} ip:{} {} {} timeout: {}",
            self.action,
            self.use_ip.inner(),
            self.use_port,
            self.mapping.as_ref().map_or("", |_| "(allocated)"),
            self.idle_timeout.as_secs(),
        )
    }
}

impl Display for NatFlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::Masquerade(m) => write!(f, "{m}"),
            Self::PortForward(p) => write!(f, "{p}"),
            Self::StaticNat | Self::Tracked => write!(f, " tracked"),
        }
    }
}
