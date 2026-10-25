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
use concurrency::sync::atomic::{AtomicUsize, Ordering};
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

/// The deadline of a masquerade mapping, shared between the mapping and the flows holding it.
///
/// The packet path does not touch it. Each flow keeps its own outbound deadline (see
/// [`MappingHold`]) and publishes it here when it lets go of the mapping, and the mapping does not
/// expire while any flow holds it. So outbound traffic still keeps the mapping alive (RFC 4787
/// REQ-6), without every packet writing a line of its own, shared with every flow on the mapping.
#[derive(Debug, Clone)]
pub struct MappingDeadline {
    shared: Arc<MappingClock>,
    idle_timeout: Duration,
}

#[derive(Debug)]
struct MappingClock {
    expires_at: AtomicInstant,
    /// The flows holding the mapping.
    holders: AtomicUsize,
}

impl MappingDeadline {
    /// A mapping deadline `idle_timeout` from now.
    #[must_use]
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            shared: Arc::new(MappingClock {
                expires_at: AtomicInstant::new(clock::deadline(idle_timeout)),
                holders: AtomicUsize::new(0),
            }),
            idle_timeout,
        }
    }

    /// When the mapping expires, if no flow holds it by then.
    #[must_use]
    pub fn expires_at(&self) -> std::time::Instant {
        self.shared.expires_at.load(Ordering::Relaxed)
    }

    /// How long the mapping lives once idle.
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Whether a flow holds the mapping. A flow publishes its deadline before it lets go, so once
    /// this is false, [`MappingDeadline::expires_at`] accounts for every flow that held it.
    #[must_use]
    pub fn is_held(&self) -> bool {
        self.shared.holders.load(Ordering::Acquire) > 0
    }

    /// Whether the mapping has expired as of `now`: no flow holds it, and its deadline has passed.
    #[must_use]
    pub fn is_expired(&self, now: std::time::Instant) -> bool {
        !self.is_held() && self.expires_at() <= now
    }

    /// Push the deadline to `idle_timeout` from now (a new flow joining the mapping). Several
    /// threads may do so at once, and the deadline must never go backwards.
    pub fn refresh(&self) {
        self.publish(clock::deadline(self.idle_timeout));
    }

    fn publish(&self, deadline: std::time::Instant) {
        self.shared.expires_at.fetch_max(deadline, Ordering::Relaxed);
    }
}

/// A flow's hold on its masquerade mapping: the mapping itself (owned by the NAT crate, opaque
/// here), and the flow's own outbound deadline.
///
/// Outbound packets push only the flow's deadline, which lives inline in the flow. Letting go of
/// the hold publishes it to the mapping, and until then the mapping does not expire.
pub struct MappingHold {
    deadline: MappingDeadline,
    outbound: AtomicInstant,
    owner: Owned,
}

impl MappingHold {
    /// Hold the mapping that `deadline` belongs to, kept alive by `owner`, from now.
    #[must_use]
    pub fn new(deadline: MappingDeadline, owner: Owned) -> Self {
        deadline.shared.holders.fetch_add(1, Ordering::Relaxed);
        Self {
            outbound: AtomicInstant::new(clock::deadline(deadline.idle_timeout)),
            deadline,
            owner,
        }
    }

    /// An outbound packet: the mapping is to live `idle_timeout` from now at least.
    pub fn refresh(&self) {
        let new = clock::deadline(self.deadline.idle_timeout);
        self.outbound.fetch_max(new, Ordering::Relaxed);
    }

    /// The deadline this flow's outbound traffic gives the mapping.
    #[must_use]
    pub fn expires_at(&self) -> std::time::Instant {
        self.outbound.load(Ordering::Relaxed)
    }

    /// The mapping, if it is a `T`.
    #[must_use]
    pub fn owner<T: Any>(&self) -> Option<&T> {
        self.owner.get()
    }

    /// The mapping's deadline.
    #[must_use]
    pub fn deadline(&self) -> &MappingDeadline {
        &self.deadline
    }
}

impl Drop for MappingHold {
    fn drop(&mut self) {
        // Publish first: whoever sees the holder count drop sees this flow's deadline too.
        self.deadline.publish(self.outbound.load(Ordering::Relaxed));
        self.deadline.shared.holders.fetch_sub(1, Ordering::Release);
    }
}

impl Debug for MappingHold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappingHold")
            .field("deadline", &self.deadline)
            .field("outbound", &self.outbound)
            .finish_non_exhaustive()
    }
}

/// What a masqueraded flow translates to, and for the outbound half, the mapping it holds.
#[derive(Debug)]
pub struct MasqueradeFlow {
    pub action: NatAction,
    pub use_ip: UnicastIpAddr,
    pub use_port: NatPort,
    pub idle_timeout: Duration,
    /// The outbound half's hold on its mapping.
    pub mapping: Option<MappingHold>,
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

#[cfg(test)]
mod tests {
    use super::*;

    // Outbound packets write only the flow's own deadline. The mapping cannot expire while a flow
    // holds it, and learns the flow's deadline when the flow lets go.
    #[test]
    fn a_hold_keeps_its_mapping_and_publishes_its_deadline_when_dropped() {
        let deadline = MappingDeadline::new(Duration::from_secs(60));
        let initial = deadline.expires_at();
        let hold = MappingHold::new(deadline.clone(), Owned::new(()));
        assert!(deadline.is_held());
        assert!(
            !deadline.is_expired(initial + Duration::from_hours(1)),
            "a held mapping expired"
        );

        std::thread::sleep(Duration::from_millis(2));
        hold.refresh();
        let outbound = hold.expires_at();
        assert!(outbound > initial, "an outbound packet did not push the flow's deadline");
        assert_eq!(
            deadline.expires_at(),
            initial,
            "an outbound packet wrote the mapping's shared deadline"
        );

        drop(hold);
        assert!(!deadline.is_held());
        assert_eq!(deadline.expires_at(), outbound, "the flow's deadline was not published");
        assert!(!deadline.is_expired(initial), "the mapping expired before the flow's deadline");
        assert!(deadline.is_expired(outbound));
    }
}
