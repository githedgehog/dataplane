// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A minimal BGP speaker ([RFC 4271]): enough to bring a session to Established with a gateway,
//! keep it there, and say how it fared.
//!
//! [`Session`] is the protocol over a byte stream, and does no I/O: it is told when its TCP
//! connection comes up or goes down, given the bytes that arrive, and asked for the bytes to send,
//! all at times it is told. A [`crate::tcp::Host`] with a BGP role carries it over smoltcp.
//!
//! It opens, keeps alive, notifies and holds -- and nothing else: it advertises no routes and
//! ignores the UPDATEs it receives, counting them. It offers the 4-octet AS number capability
//! ([RFC 6793]) and IPv4 unicast ([RFC 4760]), so that a real speaker accepts it.
//!
//! Like the BFD peer, what a session reports is meant to be read: how often it reached Established
//! and how often it dropped out, why, and the gaps between the messages it received measured
//! against the Hold Time.
//!
//! [RFC 4271]: https://www.rfc-editor.org/rfc/rfc4271
//! [RFC 4760]: https://www.rfc-editor.org/rfc/rfc4760
//! [RFC 6793]: https://www.rfc-editor.org/rfc/rfc6793

use std::net::Ipv4Addr;

use flowgen_report::Sample;
use serde::{Deserialize, Serialize};

/// The TCP port BGP listens on.
pub const PORT: u16 = 179;

const HEADER_LEN: usize = 19;
const MAX_LEN: usize = 4096;
const OPEN_MIN_LEN: usize = 29;
const NOTIFICATION_MIN_LEN: usize = 21;
const UPDATE_MIN_LEN: usize = 23;

const OPEN: u8 = 1;
const UPDATE: u8 = 2;
const NOTIFICATION: u8 = 3;
const KEEPALIVE: u8 = 4;

/// The AS number sent in OPEN's 2-octet field when the real one does not fit (RFC 6793).
const AS_TRANS: u16 = 23456;

/// The Hold Time before an OPEN has set one: the "large value" RFC 4271 section 8 suggests.
const OPEN_HOLD_NS: u64 = 240 * NS;

const NS: u64 = 1_000_000_000;

/// How a session is to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// This speaker's AS number.
    pub asn: u32,
    /// This speaker's BGP Identifier.
    pub router_id: Ipv4Addr,
    /// The Hold Time it proposes, in seconds: zero, or at least three.
    pub hold_time_s: u16,
    /// The AS the peer must be in, if it matters.
    pub peer_asn: Option<u32>,
}

/// A session's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// No connection.
    Idle = 0,
    /// OPEN sent, waiting for the peer's.
    OpenSent = 3,
    /// OPENs exchanged, waiting for the peer's KEEPALIVE.
    OpenConfirm = 4,
    /// Up.
    Established = 5,
}

/// Why a session left a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The TCP connection came up.
    Connected,
    /// The peer's OPEN was acceptable.
    OpenReceived,
    /// The peer confirmed with a KEEPALIVE.
    KeepaliveReceived,
    /// The TCP connection went down.
    Disconnected,
    /// Nothing arrived for a Hold Time.
    HoldTimerExpired,
    /// The peer sent a NOTIFICATION.
    NotificationReceived {
        /// Its Error Code.
        code: u8,
        /// Its Error Subcode.
        subcode: u8,
    },
    /// This speaker found an error and sent a NOTIFICATION.
    NotificationSent {
        /// Its Error Code.
        code: u8,
        /// Its Error Subcode.
        subcode: u8,
    },
}

/// One change of a session's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    /// When, in nanoseconds on the session's clock.
    pub t_ns: u64,
    /// From.
    pub from: State,
    /// To.
    pub to: State,
    /// Why.
    pub reason: Reason,
}

/// What a session saw: everything a report says about it.
#[derive(Debug, Clone, Default)]
pub struct Log {
    /// Every change of state, in order.
    pub transitions: Vec<Transition>,
    /// Times the session reached Established.
    pub established: u64,
    /// Times it left Established.
    pub drops: u64,
    /// Times its Hold Timer expired.
    pub hold_expiries: u64,
    /// KEEPALIVEs sent.
    pub keepalives_sent: u64,
    /// KEEPALIVEs received.
    pub keepalives_received: u64,
    /// UPDATEs received, and ignored.
    pub updates_received: u64,
    /// NOTIFICATIONs sent.
    pub notifications_sent: u64,
    /// NOTIFICATIONs received.
    pub notifications_received: u64,
    /// Gaps between messages received while Established longer than two thirds of the Hold Time:
    /// two KEEPALIVEs missed, one more from expiry.
    pub gaps_over_two_thirds_hold: u64,
    /// The longest gap between messages received while Established, in nanoseconds.
    pub max_gap_ns: u64,
    /// When the session first reached Established, in nanoseconds.
    pub first_established_ns: Option<u64>,
    /// Time spent Established, in nanoseconds, up to the last time the session was looked at.
    pub time_established_ns: u64,
}

/// A NOTIFICATION's Error Code and Subcode, for an error found in what arrived.
type Error = (u8, u8);

/// A BGP session over one TCP connection at a time. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct Session {
    config: Config,
    state: State,
    /// Bytes received and not yet a whole message.
    rx: Vec<u8>,
    /// Bytes to send.
    tx: Vec<u8>,
    /// The Hold Time in force, in nanoseconds; zero for none.
    hold_ns: u64,
    last_rx_ns: u64,
    last_keepalive_ns: u64,
    established_since_ns: Option<u64>,
    /// The connection should be closed: the session ended it.
    close: bool,
    log: Log,
}

impl Session {
    /// A session, Idle until its connection comes up.
    ///
    /// # Panics
    ///
    /// If `config`'s Hold Time is one or two seconds.
    //= https://www.rfc-editor.org/rfc/rfc4271#section-4.2
    //# The
    //# Hold Time MUST be either zero or at least three seconds.
    #[must_use]
    pub fn new(config: Config) -> Session {
        assert!(
            !matches!(config.hold_time_s, 1 | 2),
            "a Hold Time is zero or at least three seconds"
        );
        Session {
            config,
            state: State::Idle,
            rx: Vec::new(),
            tx: Vec::new(),
            hold_ns: OPEN_HOLD_NS,
            last_rx_ns: 0,
            last_keepalive_ns: 0,
            established_since_ns: None,
            close: false,
            log: Log::default(),
        }
    }

    /// The session's state.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether the session has ended its connection and wants it closed.
    #[must_use]
    pub fn wants_close(&self) -> bool {
        self.close
    }

    /// What the session has seen, with time Established counted to `now_ns`.
    #[must_use]
    pub fn log(&self, now_ns: u64) -> Log {
        let mut log = self.log.clone();
        if let Some(since) = self.established_since_ns {
            log.time_established_ns += now_ns.saturating_sub(since);
        }
        log
    }

    fn set_state(&mut self, to: State, reason: Reason, now_ns: u64) {
        if to == self.state {
            return;
        }
        if self.state == State::Established {
            self.log.drops += 1;
            if let Some(since) = self.established_since_ns.take() {
                self.log.time_established_ns += now_ns.saturating_sub(since);
            }
        }
        if to == State::Established {
            self.log.established += 1;
            self.established_since_ns = Some(now_ns);
            self.log.first_established_ns.get_or_insert(now_ns);
        }
        self.log.transitions.push(Transition {
            t_ns: now_ns,
            from: self.state,
            to,
            reason,
        });
        self.state = to;
    }

    /// The TCP connection is up: send OPEN.
    pub fn connected(&mut self, now_ns: u64) {
        self.rx.clear();
        self.tx.clear();
        self.close = false;
        self.hold_ns = OPEN_HOLD_NS;
        self.last_rx_ns = now_ns;
        self.open();
        self.set_state(State::OpenSent, Reason::Connected, now_ns);
    }

    /// The TCP connection is down.
    pub fn disconnected(&mut self, now_ns: u64) {
        self.set_state(State::Idle, Reason::Disconnected, now_ns);
        self.rx.clear();
        self.tx.clear();
        self.close = false;
    }

    /// Take `bytes` from the connection, at `now_ns`.
    pub fn receive(&mut self, bytes: &[u8], now_ns: u64) {
        if self.state == State::Idle || self.close {
            return;
        }
        self.rx.extend_from_slice(bytes);
        while self.rx.len() >= HEADER_LEN && !self.close {
            let len = usize::from(u16::from_be_bytes([self.rx[16], self.rx[17]]));
            if let Err((code, subcode)) = header(&self.rx) {
                let data = if (code, subcode) == (1, 2) {
                    self.rx[16..18].to_vec()
                } else if (code, subcode) == (1, 3) {
                    vec![self.rx[18]]
                } else {
                    Vec::new()
                };
                self.fail(code, subcode, &data, now_ns);
                return;
            }
            if self.rx.len() < len {
                return;
            }
            let message: Vec<u8> = self.rx.drain(..len).collect();
            self.message(&message, now_ns);
        }
    }

    /// Handle one whole message, its header already checked.
    fn message(&mut self, message: &[u8], now_ns: u64) {
        let gap = now_ns.saturating_sub(self.last_rx_ns);
        self.last_rx_ns = now_ns;
        let kind = message[18];
        if self.state == State::Established && matches!(kind, UPDATE | KEEPALIVE) {
            self.log.max_gap_ns = self.log.max_gap_ns.max(gap);
            if self.hold_ns != 0 && gap * 3 > self.hold_ns * 2 {
                self.log.gaps_over_two_thirds_hold += 1;
            }
        }
        match (self.state, kind) {
            (_, NOTIFICATION) => {
                self.log.notifications_received += 1;
                let (code, subcode) = (message[19], message[20]);
                self.close = true;
                self.set_state(
                    State::Idle,
                    Reason::NotificationReceived { code, subcode },
                    now_ns,
                );
            }
            (State::OpenSent, OPEN) => match self.check_open(message) {
                Ok(hold_s) => {
                    self.hold_ns = u64::from(hold_s) * NS;
                    self.keepalive(now_ns);
                    self.set_state(State::OpenConfirm, Reason::OpenReceived, now_ns);
                }
                Err((code, subcode)) => self.fail(code, subcode, &[], now_ns),
            },
            (State::OpenConfirm, KEEPALIVE) => {
                self.log.keepalives_received += 1;
                self.set_state(State::Established, Reason::KeepaliveReceived, now_ns);
            }
            (State::Established, KEEPALIVE) => self.log.keepalives_received += 1,
            (State::Established, UPDATE) => self.log.updates_received += 1,
            // Anything else in a state not expecting it: a Finite State Machine Error.
            _ => self.fail(5, 0, &[], now_ns),
        }
    }

    /// Check a received OPEN; the Hold Time to use if it is acceptable.
    //= https://www.rfc-editor.org/rfc/rfc4271#section-4.2
    //# Upon
    //# receipt of an OPEN message, a BGP speaker MUST calculate the
    //# value of the Hold Timer by using the smaller of its configured
    //# Hold Time and the Hold Time received in the OPEN message.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.2
    //# If the version number in the Version field of the received OPEN
    //# message is not supported, then the Error Subcode MUST be set to
    //# Unsupported Version Number.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.2
    //# If the Autonomous System field of the OPEN message is unacceptable,
    //# then the Error Subcode MUST be set to Bad Peer AS.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.2
    //# If the Hold Time field of the OPEN message is unacceptable, then the
    //# Error Subcode MUST be set to Unacceptable Hold Time.  An
    //# implementation MUST reject Hold Time values of one or two seconds.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.2
    //# If the BGP Identifier field of the OPEN message is syntactically
    //# incorrect, then the Error Subcode MUST be set to Bad BGP Identifier.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.2
    //# If one of the Optional Parameters in the OPEN message is not
    //# recognized, then the Error Subcode MUST be set to Unsupported
    //# Optional Parameters.
    fn check_open(&self, message: &[u8]) -> Result<u16, Error> {
        if message.len() < OPEN_MIN_LEN {
            return Err((1, 2));
        }
        if message[19] != 4 {
            return Err((2, 1));
        }
        let two_octet_as = u16::from_be_bytes([message[20], message[21]]);
        let hold = u16::from_be_bytes([message[22], message[23]]);
        let identifier = Ipv4Addr::new(message[24], message[25], message[26], message[27]);
        let params_len = usize::from(message[28]);
        let params = message.get(29..29 + params_len).ok_or((2, 0))?;
        let peer_as = four_octet_as(params)?.unwrap_or(u32::from(two_octet_as));
        if self.config.peer_asn.is_some_and(|wanted| wanted != peer_as) {
            return Err((2, 2));
        }
        if matches!(hold, 1 | 2) {
            return Err((2, 6));
        }
        if identifier.is_unspecified() || identifier.is_broadcast() || identifier.is_multicast() {
            return Err((2, 3));
        }
        Ok(hold.min(self.config.hold_time_s))
    }

    /// Send a NOTIFICATION for an error found in what arrived, and end the session.
    fn fail(&mut self, code: u8, subcode: u8, data: &[u8], now_ns: u64) {
        let mut body = vec![code, subcode];
        body.extend_from_slice(data);
        self.tx.extend(message(NOTIFICATION, &body));
        self.log.notifications_sent += 1;
        self.close = true;
        self.set_state(
            State::Idle,
            Reason::NotificationSent { code, subcode },
            now_ns,
        );
    }

    fn open(&mut self) {
        let asn = self.config.asn;
        let two_octet = u16::try_from(asn).unwrap_or(AS_TRANS);
        // Capabilities: IPv4 unicast (code 1: AFI 1, reserved, SAFI 1) and 4-octet AS (code 65).
        let mut caps = vec![1, 4, 0, 1, 0, 1, 65, 4];
        caps.extend_from_slice(&asn.to_be_bytes());
        let caps_len = u8::try_from(caps.len()).unwrap_or(u8::MAX);
        let mut body = vec![4];
        body.extend_from_slice(&two_octet.to_be_bytes());
        body.extend_from_slice(&self.config.hold_time_s.to_be_bytes());
        body.extend_from_slice(&self.config.router_id.octets());
        body.push(caps_len + 2);
        body.push(2); // Capabilities
        body.push(caps_len);
        body.extend(caps);
        self.tx.extend(message(OPEN, &body));
    }

    fn keepalive(&mut self, now_ns: u64) {
        self.tx.extend(message(KEEPALIVE, &[]));
        self.log.keepalives_sent += 1;
        self.last_keepalive_ns = now_ns;
    }

    /// The bytes to send at `now_ns`, if any; and the session's timers, checked.
    //= https://www.rfc-editor.org/rfc/rfc4271#section-4.4
    //# KEEPALIVE messages MUST NOT be sent more
    //# frequently than one per second.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-4.4
    //# If the negotiated Hold Time interval is zero, then periodic KEEPALIVE
    //# messages MUST NOT be sent.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.5
    //# If a system does not receive successive KEEPALIVE, UPDATE, and/or
    //# NOTIFICATION messages within the period specified in the Hold Time
    //# field of the OPEN message, then the NOTIFICATION message with the
    //# Hold Timer Expired Error Code is sent and the BGP connection is
    //# closed.
    pub fn transmit(&mut self, now_ns: u64) -> Option<Vec<u8>> {
        if self.state != State::Idle && !self.close && self.hold_ns != 0 {
            if now_ns.saturating_sub(self.last_rx_ns) > self.hold_ns {
                self.log.hold_expiries += 1;
                self.tx.extend(message(NOTIFICATION, &[4, 0]));
                self.log.notifications_sent += 1;
                self.close = true;
                self.set_state(State::Idle, Reason::HoldTimerExpired, now_ns);
            } else if matches!(self.state, State::OpenConfirm | State::Established) {
                let interval = (self.hold_ns / 3).max(NS);
                if now_ns.saturating_sub(self.last_keepalive_ns) >= interval {
                    self.keepalive(now_ns);
                }
            }
        }
        if self.tx.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.tx))
        }
    }

    /// When the session next has something to do on its own, in nanoseconds.
    #[must_use]
    pub fn next_deadline_ns(&self) -> u64 {
        if !self.tx.is_empty() {
            return 0;
        }
        if self.state == State::Idle || self.hold_ns == 0 {
            return u64::MAX;
        }
        let expiry = self.last_rx_ns + self.hold_ns + 1;
        if matches!(self.state, State::OpenConfirm | State::Established) {
            expiry.min(self.last_keepalive_ns + (self.hold_ns / 3).max(NS))
        } else {
            expiry
        }
    }

    /// `sample`, with the session's log under `bgp.<name>.` as of `now_ns`.
    #[must_use]
    pub fn sample(&self, name: &str, now_ns: u64, sample: Sample) -> Sample {
        let log = self.log(now_ns);
        let path = |what: &str| format!("bgp.{name}.{what}");
        let sample = [
            ("established", log.established),
            ("drops", log.drops),
            ("hold_expiries", log.hold_expiries),
            ("keepalives_sent", log.keepalives_sent),
            ("keepalives_received", log.keepalives_received),
            ("updates_received", log.updates_received),
            ("notifications_sent", log.notifications_sent),
            ("notifications_received", log.notifications_received),
            ("gaps_over_two_thirds_hold", log.gaps_over_two_thirds_hold),
            ("transitions", log.transitions.len() as u64),
        ]
        .into_iter()
        .fold(sample, |sample, (what, n)| sample.counter(path(what), n));
        let sample = sample
            .gauge(path("state"), self.state as u64)
            .gauge(path("hold_time_ns"), self.hold_ns)
            .gauge(path("max_gap_ns"), log.max_gap_ns)
            .gauge(path("time_established_ns"), log.time_established_ns);
        match log.first_established_ns {
            Some(t) => sample.gauge(path("first_established_ns"), t),
            None => sample,
        }
    }
}

/// A message of type `kind` with `body` after the header.
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = u16::try_from(HEADER_LEN + body.len()).unwrap_or(u16::MAX);
    let mut out = vec![0xff; 16];
    out.extend_from_slice(&len.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// Check a message header, at the start of `bytes`.
//= https://www.rfc-editor.org/rfc/rfc4271#section-6.1
//# The expected value of the Marker field of the message header is all
//# ones.  If the Marker field of the message header is not as expected,
//# then a synchronization error has occurred and the Error Subcode MUST
//# be set to Connection Not Synchronized.
//
//= https://www.rfc-editor.org/rfc/rfc4271#section-6.1
//# If the Type field of the message header is not recognized, then the
//# Error Subcode MUST be set to Bad Message Type.  The Data field MUST
//# contain the erroneous Type field.
fn header(bytes: &[u8]) -> Result<(), Error> {
    if bytes[..16].iter().any(|&b| b != 0xff) {
        return Err((1, 1));
    }
    let len = usize::from(u16::from_be_bytes([bytes[16], bytes[17]]));
    let least = match bytes[18] {
        OPEN => OPEN_MIN_LEN,
        UPDATE => UPDATE_MIN_LEN,
        NOTIFICATION => NOTIFICATION_MIN_LEN,
        KEEPALIVE => HEADER_LEN,
        _ => return Err((1, 3)),
    };
    if len < least || len > MAX_LEN || (bytes[18] == KEEPALIVE && len != HEADER_LEN) {
        return Err((1, 2));
    }
    Ok(())
}

/// The AS number from a 4-octet AS capability among OPEN's optional parameters, if one is there.
fn four_octet_as(mut params: &[u8]) -> Result<Option<u32>, Error> {
    let mut found = None;
    while !params.is_empty() {
        let [kind, len, rest @ ..] = params else {
            return Err((2, 0));
        };
        let value = rest.get(..usize::from(*len)).ok_or((2, 0))?;
        if *kind != 2 {
            // Only Capabilities are recognised.
            return Err((2, 4));
        }
        let mut caps = value;
        while !caps.is_empty() {
            let [code, len, rest @ ..] = caps else {
                return Err((2, 0));
            };
            let cap = rest.get(..usize::from(*len)).ok_or((2, 0))?;
            if *code == 65 && cap.len() == 4 {
                found = Some(u32::from_be_bytes([cap[0], cap[1], cap[2], cap[3]]));
            }
            caps = &rest[usize::from(*len)..];
        }
        params = &rest[usize::from(*len)..];
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn config(asn: u32, id: u8, peer_asn: u32) -> Config {
        Config {
            asn,
            router_id: Ipv4Addr::new(10, 0, 0, id),
            hold_time_s: 9,
            peer_asn: Some(peer_asn),
        }
    }

    /// Two sessions joined by a lossless byte stream, on a virtual clock, from `from` until `until`;
    /// what `a` sends is lost if `mute_a`.
    fn run(a: &mut Session, b: &mut Session, from: u64, until: u64, mute_a: bool) -> u64 {
        let mut now = from;
        while now < until {
            if let Some(bytes) = a.transmit(now)
                && !mute_a
            {
                b.receive(&bytes, now);
            }
            if let Some(bytes) = b.transmit(now) {
                a.receive(&bytes, now);
            }
            now = a
                .next_deadline_ns()
                .min(b.next_deadline_ns())
                .min(until)
                .max(now + 1);
        }
        now
    }

    fn connected() -> (Session, Session) {
        let mut a = Session::new(config(65001, 1, 4_200_000_000));
        let mut b = Session::new(config(4_200_000_000, 2, 65001));
        a.connected(0);
        b.connected(0);
        (a, b)
    }

    #[test]
    fn sessions_reach_established_and_stay() {
        let (mut a, mut b) = connected();
        let now = run(&mut a, &mut b, 0, 60 * NS, false);
        for session in [&a, &b] {
            assert_eq!(session.state(), State::Established);
            let log = session.log(now);
            assert_eq!(log.established, 1);
            assert_eq!(log.drops, 0);
            assert_eq!(log.gaps_over_two_thirds_hold, 0);
            // A KEEPALIVE every three seconds for a minute.
            assert!(log.keepalives_received >= 19, "{log:?}");
            assert!(log.max_gap_ns <= 3 * NS);
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.5
    //= type=test
    //# If a system does not receive successive KEEPALIVE, UPDATE, and/or
    //# NOTIFICATION messages within the period specified in the Hold Time
    //# field of the OPEN message, then the NOTIFICATION message with the
    //# Hold Timer Expired Error Code is sent and the BGP connection is
    //# closed.
    #[test]
    fn silence_for_a_hold_time_ends_the_session() {
        let (mut a, mut b) = connected();
        let now = run(&mut a, &mut b, 0, 10 * NS, false);
        assert_eq!(b.state(), State::Established);
        let now = run(&mut a, &mut b, now, now + 20 * NS, true);
        let log = b.log(now);
        assert_eq!(b.state(), State::Idle);
        assert!(b.wants_close());
        assert_eq!((log.hold_expiries, log.drops), (1, 1));
        assert_eq!(
            log.transitions.last().map(|t| t.reason),
            Some(Reason::HoldTimerExpired)
        );
    }

    //= https://www.rfc-editor.org/rfc/rfc4271#section-4.4
    //= type=test
    //# KEEPALIVE messages MUST NOT be sent more
    //# frequently than one per second.
    #[test]
    fn keepalives_are_no_more_than_one_a_second() {
        let mut a = Session::new(Config {
            hold_time_s: 3,
            ..config(65001, 1, 65002)
        });
        let mut b = Session::new(Config {
            hold_time_s: 3,
            ..config(65002, 2, 65001)
        });
        a.connected(0);
        b.connected(0);
        let now = run(&mut a, &mut b, 0, 30 * NS, false);
        let log = a.log(now);
        assert_eq!(a.state(), State::Established);
        assert!(log.keepalives_sent <= 31, "{} in 30 s", log.keepalives_sent);
    }

    /// The NOTIFICATION a session sends after receiving `bytes` in `OpenSent`.
    fn notification_for(bytes: &[u8]) -> (u8, u8) {
        let mut session = Session::new(config(65001, 1, 65002));
        session.connected(0);
        let _ = session.transmit(0);
        session.receive(bytes, 1);
        let sent = session.transmit(2).expect("a NOTIFICATION");
        assert_eq!(sent[18], NOTIFICATION);
        assert!(session.wants_close());
        (sent[19], sent[20])
    }

    fn open_from(asn: u32, hold: u16, id: [u8; 4]) -> Vec<u8> {
        let mut peer = Session::new(Config {
            asn,
            router_id: Ipv4Addr::from(id),
            hold_time_s: 9,
            peer_asn: None,
        });
        peer.connected(0);
        let mut open = peer.transmit(0).unwrap();
        open[22..24].copy_from_slice(&hold.to_be_bytes());
        open
    }

    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.1
    //= type=test
    //# The expected value of the Marker field of the message header is all
    //# ones.  If the Marker field of the message header is not as expected,
    //# then a synchronization error has occurred and the Error Subcode MUST
    //# be set to Connection Not Synchronized.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.2
    //= type=test
    //# If the Autonomous System field of the OPEN message is unacceptable,
    //# then the Error Subcode MUST be set to Bad Peer AS.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.2
    //= type=test
    //# If the Hold Time field of the OPEN message is unacceptable, then the
    //# Error Subcode MUST be set to Unacceptable Hold Time.  An
    //# implementation MUST reject Hold Time values of one or two seconds.
    //
    //= https://www.rfc-editor.org/rfc/rfc4271#section-6.2
    //= type=test
    //# If the BGP Identifier field of the OPEN message is syntactically
    //# incorrect, then the Error Subcode MUST be set to Bad BGP Identifier.
    #[test]
    fn bad_messages_are_notified() {
        let mut unsynchronised = open_from(65002, 9, [10, 0, 0, 2]);
        unsynchronised[0] = 0;
        assert_eq!(notification_for(&unsynchronised), (1, 1));
        let mut bad_type = message(KEEPALIVE, &[]);
        bad_type[18] = 9;
        assert_eq!(notification_for(&bad_type), (1, 3));
        let mut long_keepalive = message(KEEPALIVE, &[0]);
        long_keepalive[18] = KEEPALIVE;
        assert_eq!(notification_for(&long_keepalive), (1, 2));
        assert_eq!(
            notification_for(&open_from(65009, 9, [10, 0, 0, 2])),
            (2, 2)
        );
        assert_eq!(
            notification_for(&open_from(65002, 2, [10, 0, 0, 2])),
            (2, 6)
        );
        assert_eq!(notification_for(&open_from(65002, 9, [0, 0, 0, 0])), (2, 3));
        assert_eq!(notification_for(&message(KEEPALIVE, &[])), (5, 0));
    }

    /// Whatever bytes arrive, a session never panics, and either keeps going or ends itself with a
    /// NOTIFICATION.
    #[test]
    fn any_bytes_are_survived() {
        bolero::check!()
            .with_type::<Vec<u8>>()
            .for_each(|bytes: &Vec<u8>| {
                let mut session = Session::new(config(65001, 1, 65002));
                session.connected(0);
                let _ = session.transmit(0);
                session.receive(bytes, 1);
                let _ = session.transmit(2);
                if session.state() == State::Idle {
                    assert!(session.wants_close());
                }
            });
    }
}
