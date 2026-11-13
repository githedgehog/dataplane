// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The switch to turn the SYN proxy on and off at runtime, shared by all workers, and its
//! counters.

use crate::cookie::{CookieKey, SLOT};
use clock::Instant;
use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use net::buffer::PacketBufferMut;
use net::flows::AtomicInstant;
use net::headers::TryHeaders;
use net::packet::Packet;
use std::fmt::Display;
use std::time::Duration;

/// How long the proxy keeps accepting cookies after it is turned off: the longest lifetime of a
/// cookie. A client may have received one just before.
pub const GRACE_PERIOD: Duration = SLOT.saturating_mul(2);

/// Whether the proxy answers SYNs.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynProxyMode {
    /// The proxy lets SYNs through. It keeps handling the connections it set up.
    Off = 0,
    /// The proxy answers SYNs with cookies.
    On = 1,
}

impl Display for SynProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SynProxyMode::Off => write!(f, "off"),
            SynProxyMode::On => write!(f, "on"),
        }
    }
}

/// What the proxy did, since the dataplane started.
#[derive(Debug, Default)]
pub struct Counters {
    /// SYNs answered with a cookie.
    pub cookies_sent: AtomicU64,
    /// ACKs with a valid cookie that the ACL and rate-limit stages let through, for which the
    /// proxy opened a connection to the server.
    pub cookies_accepted: AtomicU64,
    /// Connections that the server accepted, and that the proxy now translates.
    pub connections: AtomicU64,
    /// Connections that the server refused.
    pub connections_refused: AtomicU64,
}

#[derive(Debug)]
struct Shared {
    mode: AtomicU8,
    // When the proxy is off, it accepts cookies until then
    accept_cookies_until: AtomicInstant,
    key: CookieKey,
    counters: Counters,
}

/// The switch of the SYN proxy, its cookie key and its counters. Clones share them.
#[derive(Debug, Clone)]
pub struct SynProxyControl(Arc<Shared>);

impl SynProxyControl {
    /// A new proxy, off, with a new cookie key.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Shared {
            mode: AtomicU8::new(SynProxyMode::Off as u8),
            accept_cookies_until: AtomicInstant::new(clock::now()),
            key: CookieKey::new(),
            counters: Counters::default(),
        }))
    }

    /// The current mode.
    #[must_use]
    pub fn mode(&self) -> SynProxyMode {
        // Pairs with the store in set_mode: see the end of the grace period it set before
        match self.0.mode.load(Ordering::Acquire) {
            0 => SynProxyMode::Off,
            _ => SynProxyMode::On,
        }
    }

    /// Change the mode. Turning the proxy off starts the grace period during which it still
    /// accepts cookies.
    ///
    /// Only one thread, the one of the CLI, changes the mode.
    pub fn set_mode(&self, mode: SynProxyMode) {
        // Start the grace period before the workers can see the proxy off, or they could reject
        // valid cookies in between
        if mode == SynProxyMode::Off && self.mode() == SynProxyMode::On {
            self.0
                .accept_cookies_until
                .store(clock::deadline(GRACE_PERIOD), Ordering::Relaxed);
        }
        self.0.mode.store(mode as u8, Ordering::Release);
    }

    /// Tell if the proxy answers the SYN of a new connection: when it is on, if the connection
    /// gets flows, and if the SYN is not a fragment.
    ///
    /// The proxy protects the flow table, by creating flows only for clients that complete the
    /// handshake. Connections that get no flows put no pressure on the table: proxying them would
    /// only create flows for them, and lose the TCP options that the proxy does not negotiate.
    ///
    /// The proxy cannot answer a fragment: it would answer with the fragmentation fields of the
    /// SYN. Such SYNs carry data, and are rare enough to let through.
    #[must_use]
    pub fn answers_syns<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> bool {
        self.mode() == SynProxyMode::On
            && packet.meta().gets_flows()
            && !packet.headers().is_fragment()
    }

    /// Tell if the proxy validates the cookie of an ACK without a flow: if the connection gets
    /// flows, when the proxy is on or during the grace period after turning it off.
    ///
    /// The cookie stage runs before the ACL stage, which may still clear the request for flow
    /// tracking. So the ACKs it checks are a superset of the connections whose SYNs the proxy
    /// answered, as long as the configuration does not change in between.
    #[must_use]
    pub fn accepts_cookies<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
        now: Instant,
    ) -> bool {
        packet.meta().gets_flows() && self.may_accept_cookies(now)
    }

    /// Tell if the proxy may accept any cookie: when it is on, or during the grace period after
    /// turning it off. Stages can skip whole bursts otherwise.
    #[must_use]
    pub(crate) fn may_accept_cookies(&self, now: Instant) -> bool {
        self.mode() == SynProxyMode::On || now < self.0.accept_cookies_until.load(Ordering::Relaxed)
    }

    /// The key for the cookies.
    #[must_use]
    pub(crate) fn key(&self) -> &CookieKey {
        &self.0.key
    }

    /// The counters of the proxy.
    #[must_use]
    pub fn counters(&self) -> &Counters {
        &self.0.counters
    }
}

impl Default for SynProxyControl {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for SynProxyControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let counters = self.counters();
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let grace = self
            .0
            .accept_cookies_until
            .load(Ordering::Relaxed)
            .saturating_duration_since(clock::now());
        writeln!(f, "SYN proxy: {}", self.mode())?;
        if self.mode() == SynProxyMode::Off && !grace.is_zero() {
            writeln!(f, "  accepting cookies for {}s more", grace.as_secs())?;
        }
        writeln!(f, "  cookies sent:        {}", get(&counters.cookies_sent))?;
        writeln!(
            f,
            "  cookies accepted:    {}",
            get(&counters.cookies_accepted)
        )?;
        writeln!(f, "  connections:         {}", get(&counters.connections))?;
        writeln!(
            f,
            "  connections refused: {}",
            get(&counters.connections_refused)
        )
    }
}

#[cfg(test)]
mod test {
    use super::{GRACE_PERIOD, SynProxyControl, SynProxyMode};
    use net::buffer::TestBuffer;
    use net::packet::Packet;
    use net::packet::test_utils::build_test_tcp_ipv4_packet;

    // A packet of a connection that gets flows
    fn packet() -> Packet<TestBuffer> {
        let mut packet = build_test_tcp_ipv4_packet("10.0.0.1", "10.0.0.2", 1234, 80);
        packet.meta_mut().set_forced_flow_tracking(true);
        packet
    }

    #[test]
    fn grace_period_after_turning_off() {
        let proxy = SynProxyControl::new();
        let packet = packet();
        let now = clock::now();
        assert!(!proxy.answers_syns(&packet));
        assert!(!proxy.accepts_cookies(&packet, now));

        proxy.set_mode(SynProxyMode::On);
        assert!(proxy.answers_syns(&packet));
        assert!(proxy.accepts_cookies(&packet, now));

        proxy.set_mode(SynProxyMode::Off);
        let now = clock::now();
        assert!(!proxy.answers_syns(&packet));
        assert!(proxy.accepts_cookies(&packet, now));
        assert!(!proxy.accepts_cookies(&packet, now + GRACE_PERIOD));

        // Turning it off again does not extend the grace period
        let until = proxy.0.accept_cookies_until.load(super::Ordering::Relaxed);
        proxy.set_mode(SynProxyMode::Off);
        assert_eq!(
            proxy.0.accept_cookies_until.load(super::Ordering::Relaxed),
            until
        );
    }

    // Connections that get no flows put no pressure on the flow table: leave them alone
    #[test]
    fn only_connections_with_flows() {
        let proxy = SynProxyControl::new();
        proxy.set_mode(SynProxyMode::On);
        let now = clock::now();
        let mut packet = build_test_tcp_ipv4_packet("10.0.0.1", "10.0.0.2", 1234, 80);
        assert!(!proxy.answers_syns(&packet));
        assert!(!proxy.accepts_cookies(&packet, now));

        packet.meta_mut().set_masquerade(true);
        assert!(proxy.answers_syns(&packet));
        assert!(proxy.accepts_cookies(&packet, now));

        packet.meta_mut().set_masquerade(false);
        packet.meta_mut().set_port_forwarding(true);
        assert!(proxy.answers_syns(&packet));
        assert!(proxy.accepts_cookies(&packet, now));
    }
}
