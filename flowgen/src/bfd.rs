// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A BFD peer ([RFC 5880], single hop over IPv4 per [RFC 5881]): enough of the protocol to hold a
//! session with a gateway's BFD and to say how that session fared.
//!
//! [`Session`] is the protocol, and does no I/O: it is told what arrived and when, and asked what to
//! send and when, so a test can drive it by a clock of its own. Asynchronous mode only: no Demand
//! mode, no Echo function, no authentication. It initiates Poll Sequences when its transmit
//! interval changes and answers the remote's.
//!
//! What a session reports is meant to be read, not decoded: its state over time, how often it went
//! down, and the gaps between the packets it received measured against its Detection Time -- so a
//! report says not only whether the session survived but by what margin.
//!
//! [RFC 5880]: https://www.rfc-editor.org/rfc/rfc5880
//! [RFC 5881]: https://www.rfc-editor.org/rfc/rfc5881

use std::fmt;

use flowgen_report::Sample;

use crate::frame::{self, Endpoints};
use serde::{Deserialize, Serialize};

/// The UDP port single-hop BFD Control packets go to.
pub const CONTROL_PORT: u16 = 3784;

/// The TTL every single-hop BFD Control packet is sent with, and must arrive with.
pub const TTL: u8 = 255;

/// Bytes in a Control packet without authentication.
pub const PACKET_LEN: usize = 24;

/// [`PACKET_LEN`], as the Length field carries it.
const PACKET_LEN_FIELD: u8 = 24;

/// The least `bfd.DesiredMinTxInterval` while a session is not Up: one second.
const SLOW_TX_US: u32 = 1_000_000;

/// A session's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Administratively down.
    AdminDown = 0,
    /// Down.
    Down = 1,
    /// Coming up.
    Init = 2,
    /// Up.
    Up = 3,
}

impl State {
    fn from_bits(bits: u8) -> State {
        match bits & 0x3 {
            0 => State::AdminDown,
            1 => State::Down,
            2 => State::Init,
            _ => State::Up,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Why a session last changed state, as the Diagnostic field carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Diag {
    /// No diagnostic.
    None = 0,
    /// No packet arrived for a Detection Time.
    DetectionTimeExpired = 1,
    /// The neighbour said the session went down.
    NeighborSignaledDown = 3,
}

/// A BFD Control packet without authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    /// Why the sender's session last changed state, as a raw code.
    pub diag: u8,
    /// The sender's session state.
    pub state: State,
    /// Poll: the sender asks for a Final.
    pub poll: bool,
    /// Final: the answer to a Poll.
    pub fin: bool,
    /// Detect Mult.
    pub detect_mult: u8,
    /// My Discriminator.
    pub my_discriminator: u32,
    /// Your Discriminator.
    pub your_discriminator: u32,
    /// Desired Min TX Interval, in microseconds.
    pub desired_min_tx_us: u32,
    /// Required Min RX Interval, in microseconds.
    pub required_min_rx_us: u32,
    /// Required Min Echo RX Interval, in microseconds.
    pub required_min_echo_rx_us: u32,
}

/// Why a received Control packet was discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Discard {
    /// Shorter than its own Length field, or than a Control packet.
    #[error("too short")]
    Short,
    /// Not version 1.
    #[error("version {0}, not 1")]
    Version(u8),
    /// Its Length is under 24.
    #[error("length {0} under 24")]
    Length(u8),
    /// Detect Mult is zero.
    #[error("Detect Mult zero")]
    DetectMult,
    /// The Multipoint bit is set.
    #[error("Multipoint set")]
    Multipoint,
    /// My Discriminator is zero.
    #[error("My Discriminator zero")]
    MyDiscriminator,
    /// Your Discriminator names another session.
    #[error("Your Discriminator {0} is not this session's")]
    YourDiscriminator(u32),
    /// Your Discriminator is zero, from a session that is neither Down nor `AdminDown`.
    #[error("Your Discriminator zero from a session {0}")]
    Unselected(State),
    /// Authenticated, which this peer is not.
    #[error("authenticated")]
    Authenticated,
    /// Arrived with a TTL other than 255.
    #[error("TTL {0}, not 255")]
    Ttl(u8),
    /// This session is administratively down.
    #[error("the session is administratively down")]
    AdminDown,
}

impl Packet {
    /// The packet as it goes on the wire.
    #[must_use]
    pub fn encode(&self) -> [u8; PACKET_LEN] {
        let mut out = [0u8; PACKET_LEN];
        out[0] = (1 << 5) | (self.diag & 0x1f);
        out[1] = ((self.state as u8) << 6) | (u8::from(self.poll) << 5) | (u8::from(self.fin) << 4);
        out[2] = self.detect_mult;
        out[3] = PACKET_LEN_FIELD;
        out[4..8].copy_from_slice(&self.my_discriminator.to_be_bytes());
        out[8..12].copy_from_slice(&self.your_discriminator.to_be_bytes());
        out[12..16].copy_from_slice(&self.desired_min_tx_us.to_be_bytes());
        out[16..20].copy_from_slice(&self.required_min_rx_us.to_be_bytes());
        out[20..24].copy_from_slice(&self.required_min_echo_rx_us.to_be_bytes());
        out
    }

    /// The packet in `bytes`, the UDP payload, checked as far as it can be without a session.
    ///
    /// # Errors
    ///
    /// The first rule of [RFC 5880 section 6.8.6] the packet breaks that needs no session state.
    ///
    /// [RFC 5880 section 6.8.6]: https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If the version number is not correct (1), the packet MUST be
    //# discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If the Length field is less than the minimum correct value (24 if
    //# the A bit is clear, or 26 if the A bit is set), the packet MUST be
    //# discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If the Length field is greater than the payload of the
    //# encapsulating protocol, the packet MUST be discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If the Detect Mult field is zero, the packet MUST be discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If the Multipoint (M) bit is nonzero, the packet MUST be
    //# discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If the My Discriminator field is zero, the packet MUST be
    //# discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If the A bit is set and no authentication is in use (bfd.AuthType
    //# is zero), the packet MUST be discarded.
    pub fn decode(bytes: &[u8]) -> Result<Packet, Discard> {
        let head = bytes.get(..PACKET_LEN).ok_or(Discard::Short)?;
        let version = head[0] >> 5;
        if version != 1 {
            return Err(Discard::Version(version));
        }
        let length = head[3];
        let authenticated = head[1] & 0x04 != 0;
        let least = if authenticated { 26 } else { 24 };
        if usize::from(length) < least {
            return Err(Discard::Length(length));
        }
        if usize::from(length) > bytes.len() {
            return Err(Discard::Short);
        }
        if head[2] == 0 {
            return Err(Discard::DetectMult);
        }
        if head[1] & 0x01 != 0 {
            return Err(Discard::Multipoint);
        }
        let word =
            |at: usize| u32::from_be_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]);
        if word(4) == 0 {
            return Err(Discard::MyDiscriminator);
        }
        if authenticated {
            return Err(Discard::Authenticated);
        }
        Ok(Packet {
            diag: head[0] & 0x1f,
            state: State::from_bits(head[1] >> 6),
            poll: head[1] & 0x20 != 0,
            fin: head[1] & 0x10 != 0,
            detect_mult: head[2],
            my_discriminator: word(4),
            your_discriminator: word(8),
            desired_min_tx_us: word(12),
            required_min_rx_us: word(16),
            required_min_echo_rx_us: word(20),
        })
    }
}

/// How a session is to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// This session's discriminator; nonzero.
    pub discriminator: u32,
    /// The interval it would like to send at once Up, in microseconds.
    pub desired_min_tx_us: u32,
    /// The least interval it will receive at, in microseconds.
    pub required_min_rx_us: u32,
    /// Detect Mult.
    pub detect_mult: u8,
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
    pub diag: Diag,
}

/// What a session saw: everything a report says about it.
#[derive(Debug, Clone, Default)]
pub struct Log {
    /// Every change of state, in order.
    pub transitions: Vec<Transition>,
    /// Packets sent.
    pub sent: u64,
    /// Packets received and accepted.
    pub received: u64,
    /// Packets received and discarded.
    pub discarded: u64,
    /// The first reasons packets were discarded.
    pub discard_reasons: Vec<Discard>,
    /// Times the session went from Up to anything else.
    pub flaps: u64,
    /// Gaps between packets received while Up, longer than half the Detection Time.
    pub gaps_over_half: u64,
    /// Gaps longer than three quarters of the Detection Time: one more lost packet from a flap.
    pub gaps_over_three_quarters: u64,
    /// The longest gap between packets received while Up, in nanoseconds.
    pub max_gap_ns: u64,
    /// Time spent Up, in nanoseconds, up to the last time the session was looked at.
    pub time_up_ns: u64,
    /// When the session first came Up, in nanoseconds.
    pub first_up_ns: Option<u64>,
}

/// A BFD session. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct Session {
    config: Config,
    state: State,
    diag: Diag,
    remote_state: State,
    remote_discriminator: u32,
    remote_min_rx_us: u32,
    remote_desired_min_tx_us: u32,
    remote_detect_mult: u8,
    /// The Desired Min TX Interval in effect: slow until Up.
    desired_min_tx_us: u32,
    /// Sending Polls until a Final arrives.
    polling: bool,
    /// A Final is owed.
    owe_final: bool,
    /// The state has changed since the last packet was sent.
    changed: bool,
    last_rx_ns: Option<u64>,
    /// When the last packet was sent.
    last_tx_ns: Option<u64>,
    next_tx_ns: u64,
    up_since_ns: Option<u64>,
    jitter: u64,
    log: Log,
}

/// The most discard reasons a log keeps.
const MAX_DISCARD_REASONS: usize = 16;

impl Session {
    /// A session starting Down at `now_ns`.
    ///
    /// # Panics
    ///
    /// If `config`'s discriminator or Detect Mult is zero.
    #[must_use]
    pub fn new(config: Config, now_ns: u64) -> Session {
        assert!(
            config.discriminator != 0,
            "a BFD discriminator must be nonzero"
        );
        assert!(config.detect_mult != 0, "a BFD Detect Mult must be nonzero");
        Session {
            config,
            state: State::Down,
            diag: Diag::None,
            remote_state: State::Down,
            remote_discriminator: 0,
            // bfd.RemoteMinRxInterval starts at 1 (RFC 5880 section 6.8.1).
            remote_min_rx_us: 1,
            remote_desired_min_tx_us: 0,
            remote_detect_mult: 0,
            desired_min_tx_us: SLOW_TX_US.max(config.desired_min_tx_us),
            polling: false,
            owe_final: false,
            changed: true,
            last_rx_ns: None,
            last_tx_ns: None,
            next_tx_ns: now_ns,
            up_since_ns: None,
            jitter: u64::from(config.discriminator) | 1,
            log: Log::default(),
        }
    }

    /// The session's state.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// What the session has seen, with time Up counted to `now_ns`.
    #[must_use]
    pub fn log(&self, now_ns: u64) -> Log {
        let mut log = self.log.clone();
        if let Some(since) = self.up_since_ns {
            log.time_up_ns += now_ns.saturating_sub(since);
        }
        log
    }

    /// The Detection Time, in nanoseconds: the remote's Detect Mult times the greater of the
    /// interval this session will receive at and the one the remote would send at.
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.4
    //# In Asynchronous mode, the Detection Time calculated in the local
    //# system is equal to the value of Detect Mult received from the remote
    //# system, multiplied by the agreed transmit interval of the remote
    //# system (the greater of bfd.RequiredMinRxInterval and the last
    //# received Desired Min TX Interval).
    #[must_use]
    pub fn detection_time_ns(&self) -> u64 {
        let interval = self
            .config
            .required_min_rx_us
            .max(self.remote_desired_min_tx_us);
        u64::from(self.remote_detect_mult) * u64::from(interval) * 1_000
    }

    /// The interval this session sends at, before jitter, in nanoseconds.
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.7
    //# The transmit interval MUST be recalculated whenever
    //# bfd.DesiredMinTxInterval changes, or whenever bfd.RemoteMinRxInterval
    //# changes, and is equal to the greater of those two values.
    fn tx_interval_ns(&self) -> u64 {
        u64::from(self.desired_min_tx_us.max(self.remote_min_rx_us)) * 1_000
    }

    fn set_state(&mut self, to: State, diag: Diag, now_ns: u64) {
        if to == self.state {
            return;
        }
        if self.state == State::Up {
            self.log.flaps += 1;
            if let Some(since) = self.up_since_ns.take() {
                self.log.time_up_ns += now_ns.saturating_sub(since);
            }
        }
        if to == State::Up {
            self.up_since_ns = Some(now_ns);
            self.log.first_up_ns.get_or_insert(now_ns);
        }
        self.diag = diag;
        self.log.transitions.push(Transition {
            t_ns: now_ns,
            from: self.state,
            to,
            diag,
        });
        self.state = to;
        self.changed = true;
        self.retime();
    }

    /// Set the Desired Min TX Interval the state calls for, polling if it changed.
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.3
    //# When bfd.SessionState is not Up, the system MUST set
    //# bfd.DesiredMinTxInterval to a value of not less than one second
    //# (1,000,000 microseconds).
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.3
    //# If either bfd.DesiredMinTxInterval is changed or
    //# bfd.RequiredMinRxInterval is changed, a Poll Sequence MUST be
    //# initiated (see section 6.5).
    fn retime(&mut self) {
        let desired = if self.state == State::Up {
            self.config.desired_min_tx_us
        } else {
            SLOW_TX_US.max(self.config.desired_min_tx_us)
        };
        if desired != self.desired_min_tx_us {
            self.desired_min_tx_us = desired;
            self.polling = true;
            self.honor_interval();
        }
    }

    /// Bring the next periodic packet forward if the transmit interval has shrunk below the time
    /// it was scheduled for.
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.3
    //# In other words, the local system cannot
    //# wait longer than the new interval between the previous packet
    //# transmission and the next one.
    fn honor_interval(&mut self) {
        if let Some(last) = self.last_tx_ns {
            self.next_tx_ns = self.next_tx_ns.min(last + self.tx_interval_ns());
        }
    }

    /// Take a received Control packet, the payload of a UDP datagram that arrived at `now_ns` with
    /// `ttl`.
    ///
    /// # Errors
    ///
    /// Why the packet was discarded; it is counted, and changes nothing else.
    //= https://www.rfc-editor.org/rfc/rfc5881#section-5
    //# All received BFD Control packets that are
    //# demultiplexed to the session MUST be discarded if the received TTL or
    //# Hop Limit is not equal to 255.
    pub fn receive(&mut self, payload: &[u8], ttl: u8, now_ns: u64) -> Result<(), Discard> {
        let result = self.accept(payload, ttl, now_ns);
        if let Err(reason) = result {
            self.log.discarded += 1;
            if self.log.discard_reasons.len() < MAX_DISCARD_REASONS {
                self.log.discard_reasons.push(reason);
            }
        }
        result
    }

    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If the Your Discriminator field is nonzero, it MUST be used to
    //# select the session with which this BFD packet is associated.  If
    //# no session is found, the packet MUST be discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If the Your Discriminator field is zero and the State field is not
    //# Down or AdminDown, the packet MUST be discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If a Poll Sequence is being transmitted by the local system and
    //# the Final (F) bit in the received packet is set, the Poll Sequence
    //# MUST be terminated.
    fn accept(&mut self, payload: &[u8], ttl: u8, now_ns: u64) -> Result<(), Discard> {
        if ttl != TTL {
            return Err(Discard::Ttl(ttl));
        }
        let packet = Packet::decode(payload)?;
        if packet.your_discriminator != 0 && packet.your_discriminator != self.config.discriminator
        {
            return Err(Discard::YourDiscriminator(packet.your_discriminator));
        }
        if packet.your_discriminator == 0 && !matches!(packet.state, State::Down | State::AdminDown)
        {
            return Err(Discard::Unselected(packet.state));
        }
        self.remote_discriminator = packet.my_discriminator;
        self.remote_state = packet.state;
        self.remote_min_rx_us = packet.required_min_rx_us;
        self.honor_interval();
        self.remote_desired_min_tx_us = packet.desired_min_tx_us;
        self.remote_detect_mult = packet.detect_mult;
        if self.polling && packet.fin {
            self.polling = false;
        }
        if self.state == State::AdminDown {
            return Err(Discard::AdminDown);
        }
        self.note_arrival(now_ns);
        self.transition_on(packet.state, now_ns);
        if packet.poll {
            self.owe_final = true;
        }
        Ok(())
    }

    /// Record a packet's arrival, and the gap since the last one if the session is Up.
    fn note_arrival(&mut self, now_ns: u64) {
        self.log.received += 1;
        if self.state == State::Up
            && let Some(last) = self.last_rx_ns
        {
            let gap = now_ns.saturating_sub(last);
            let detect = self.detection_time_ns();
            self.log.max_gap_ns = self.log.max_gap_ns.max(gap);
            if gap * 2 > detect {
                self.log.gaps_over_half += 1;
            }
            if gap * 4 > detect * 3 {
                self.log.gaps_over_three_quarters += 1;
            }
        }
        self.last_rx_ns = Some(now_ns);
    }

    /// Change state for a packet from a remote in state `remote`.
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //# If bfd.SessionState is AdminDown
    //#
    //# Discard the packet
    //#
    //# If received state is AdminDown
    //# If bfd.SessionState is not Down
    //# Set bfd.LocalDiag to 3 (Neighbor signaled
    //# session down)
    //# Set bfd.SessionState to Down
    //#
    //# Else
    //#
    //# If bfd.SessionState is Down
    //# If received State is Down
    //# Set bfd.SessionState to Init
    //# Else if received State is Init
    //# Set bfd.SessionState to Up
    //#
    //# Else if bfd.SessionState is Init
    //# If received State is Init or Up
    //# Set bfd.SessionState to Up
    //#
    //# Else (bfd.SessionState is Up)
    //# If received State is Down
    //# Set bfd.LocalDiag to 3 (Neighbor signaled
    //# session down)
    //# Set bfd.SessionState to Down
    fn transition_on(&mut self, remote: State, now_ns: u64) {
        if remote == State::AdminDown {
            if self.state != State::Down {
                self.set_state(State::Down, Diag::NeighborSignaledDown, now_ns);
            }
            return;
        }
        match (self.state, remote) {
            (State::Down, State::Down) => self.set_state(State::Init, Diag::None, now_ns),
            (State::Down, State::Init) | (State::Init, State::Init | State::Up) => {
                self.set_state(State::Up, Diag::None, now_ns);
            }
            (State::Up, State::Down) => {
                self.set_state(State::Down, Diag::NeighborSignaledDown, now_ns);
            }
            _ => {}
        }
    }

    /// Bring the session down if no packet has arrived for a Detection Time.
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.4
    //# If Demand mode is not active, and a period of time equal to the
    //# Detection Time passes without receiving a BFD Control packet from the
    //# remote system, and bfd.SessionState is Init or Up, the session has
    //# gone down -- the local system MUST set bfd.SessionState to Down and
    //# bfd.LocalDiag to 1 (Control Detection Time Expired).
    fn check_detection(&mut self, now_ns: u64) {
        if !matches!(self.state, State::Init | State::Up) {
            return;
        }
        if let Some(last) = self.last_rx_ns
            && now_ns.saturating_sub(last) > self.detection_time_ns()
        {
            self.set_state(State::Down, Diag::DetectionTimeExpired, now_ns);
            self.remote_discriminator = 0;
        }
    }

    /// The packet to send at `now_ns`, if one is due; and the session's timers, checked.
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.7
    //# The periodic transmission of BFD Control packets MUST be jittered on
    //# a per-packet basis by up to 25%, that is, the interval MUST be
    //# reduced by a random value of 0 to 25%, in order to avoid self-
    //# synchronization with other systems on the same subnetwork.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.7
    //# If bfd.DetectMult is equal to 1, the interval between transmitted BFD
    //# Control packets MUST be no more than 90% of the negotiated
    //# transmission interval, and MUST be no less than 75% of the negotiated
    //# transmission interval.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.7
    //# A system MUST NOT periodically transmit BFD Control packets if
    //# bfd.RemoteMinRxInterval is zero.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.7
    //# If a BFD Control packet is received with the Poll (P) bit set to 1,
    //# the receiving system MUST transmit a BFD Control packet with the Poll
    //# (P) bit clear and the Final (F) bit set as soon as practicable,
    //# without respect to the transmission timer or any other transmission
    //# limitations, without respect to the session state, and without
    //# respect to whether Demand mode is active on either system.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.7
    //# A BFD Control packet SHOULD be transmitted during the interval
    //# between periodic Control packet transmissions when the contents of
    //# that packet would differ from that in the previously transmitted
    //# packet (other than the Poll and Final bits) in order to more rapidly
    //# communicate a change in state.
    pub fn poll_transmit(&mut self, now_ns: u64) -> Option<Packet> {
        self.check_detection(now_ns);
        let periodic = now_ns >= self.next_tx_ns && self.remote_min_rx_us != 0;
        if !(periodic || self.owe_final || self.changed) {
            return None;
        }
        let fin = std::mem::take(&mut self.owe_final);
        let changed = std::mem::take(&mut self.changed);
        // A Final alone is outside the schedule; a periodic packet, or news of a change, restarts it.
        if periodic || changed {
            let interval = self.tx_interval_ns();
            let jitter = self.next_jitter();
            // Up to 25% off, or between 10% and 25% off with a Detect Mult of 1.
            let off = if self.config.detect_mult == 1 {
                interval / 10 + interval * 15 / 100 * jitter / 1_000
            } else {
                interval / 4 * jitter / 1_000
            };
            self.next_tx_ns = now_ns + interval - off;
        }
        self.log.sent += 1;
        self.last_tx_ns = Some(now_ns);
        Some(Packet {
            diag: self.diag as u8,
            state: self.state,
            poll: self.polling && !fin,
            fin,
            detect_mult: self.config.detect_mult,
            my_discriminator: self.config.discriminator,
            your_discriminator: self.remote_discriminator,
            desired_min_tx_us: self.desired_min_tx_us,
            required_min_rx_us: self.config.required_min_rx_us,
            required_min_echo_rx_us: 0,
        })
    }

    /// When [`Session::poll_transmit`] should next be called, in nanoseconds: at once if a packet
    /// is owed now -- a Final, or news of a change of state -- and otherwise the earlier of the next
    /// periodic packet and the Detection Time running out.
    #[must_use]
    pub fn next_deadline_ns(&self) -> u64 {
        if self.owe_final || self.changed {
            return 0;
        }
        let detect = match (self.state, self.last_rx_ns) {
            (State::Init | State::Up, Some(last)) => last + self.detection_time_ns() + 1,
            _ => u64::MAX,
        };
        self.next_tx_ns.min(detect)
    }

    /// A pseudo-random number in `0..=1000`, the fraction of the jitter range to apply.
    fn next_jitter(&mut self) -> u64 {
        // xorshift64: deterministic for a given discriminator, which is all jitter needs.
        let mut x = self.jitter;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.jitter = x;
        x % 1_001
    }

    /// `sample`, with the session's log under `bfd.<name>.` as of `now_ns`.
    #[must_use]
    pub fn sample(&self, name: &str, now_ns: u64, sample: Sample) -> Sample {
        let log = self.log(now_ns);
        let path = |what: &str| format!("bfd.{name}.{what}");
        let sample = [
            ("sent", log.sent),
            ("received", log.received),
            ("discarded", log.discarded),
            ("flaps", log.flaps),
            ("transitions", log.transitions.len() as u64),
            ("gaps_over_half_detection", log.gaps_over_half),
            (
                "gaps_over_three_quarters_detection",
                log.gaps_over_three_quarters,
            ),
        ]
        .into_iter()
        .fold(sample, |sample, (what, n)| sample.counter(path(what), n));
        let sample = sample
            .gauge(path("state"), self.state as u64)
            .gauge(path("detection_time_ns"), self.detection_time_ns())
            .gauge(path("max_gap_ns"), log.max_gap_ns)
            .gauge(path("time_up_ns"), log.time_up_ns);
        match log.first_up_ns {
            Some(t) => sample.gauge(path("first_up_ns"), t),
            None => sample,
        }
    }
}

/// A BFD session speaking over a wire, as an [`Agent`](crate::drive::Agent): it sends its Control
/// packets from `endpoints` and takes the ones that come back addressed the other way.
pub struct Peer {
    name: String,
    wire: usize,
    endpoints: Endpoints,
    session: Session,
}

impl Peer {
    /// A peer called `name` -- its counters are reported under `bfd.<name>.` -- running `session`
    /// on wire `wire` between `endpoints`, whose destination port should be [`CONTROL_PORT`] and
    /// whose source port should be in `49152..=65535`.
    //= https://www.rfc-editor.org/rfc/rfc5881#section-4
    //# BFD Control packets MUST be transmitted in UDP packets with
    //# destination port 3784, within an IPv4 or IPv6 packet.  The source
    //# port MUST be in the range 49152 through 65535.
    #[must_use]
    pub fn new(name: &str, wire: usize, endpoints: Endpoints, session: Session) -> Peer {
        Peer {
            name: name.to_string(),
            wire,
            endpoints,
            session,
        }
    }

    /// The session.
    #[must_use]
    pub fn session(&self) -> &Session {
        &self.session
    }
}

impl crate::drive::Agent for Peer {
    fn wire(&self) -> usize {
        self.wire
    }

    //= https://www.rfc-editor.org/rfc/rfc5881#section-5
    //# If BFD authentication is not in use on a session, all BFD Control
    //# packets for the session MUST be sent with a Time to Live (TTL) or Hop
    //# Limit value of 255.
    fn transmit(&mut self, now_ns: u64) -> Option<Vec<u8>> {
        let packet = self.session.poll_transmit(now_ns)?;
        Some(frame::udp(&self.endpoints, TTL, &packet.encode()))
    }

    fn receive(&mut self, frame: &[u8], now_ns: u64) -> bool {
        let Some(datagram) = frame::datagram(frame) else {
            return false;
        };
        let (src, _) = self.endpoints.src;
        let (dst, dport) = self.endpoints.dst;
        let ours =
            datagram.tuple.dport == dport && datagram.tuple.src == dst && datagram.tuple.dst == src;
        if ours {
            // A discarded packet is counted in the session's log; it is still this peer's.
            let _ = self.session.receive(datagram.payload, datagram.ttl, now_ns);
        }
        ours
    }

    fn sample(&self, now_ns: u64, sample: Sample) -> Sample {
        self.session.sample(&self.name, now_ns, sample)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const MS: u64 = 1_000_000;

    fn config(discriminator: u32) -> Config {
        Config {
            discriminator,
            desired_min_tx_us: 50_000,
            required_min_rx_us: 50_000,
            detect_mult: 3,
        }
    }

    /// Two sessions joined by a link with a fixed delay, run on a virtual clock, with every packet
    /// from either side passed through `lose` first.
    struct Pair {
        a: Session,
        b: Session,
        /// Packets in flight: when they land, which way, and the bytes.
        flight: Vec<(u64, bool, [u8; PACKET_LEN])>,
        now: u64,
        delay: u64,
        sent: u64,
    }

    impl Pair {
        fn new() -> Pair {
            Pair {
                a: Session::new(config(0x0a), 0),
                b: Session::new(config(0x0b), 0),
                flight: Vec::new(),
                now: 0,
                delay: MS,
                sent: 0,
            }
        }

        /// Run until `until`, losing the packets `lose` says to, by their order of sending.
        fn run(&mut self, until: u64, lose: &mut dyn FnMut(u64, u64) -> bool) {
            while self.now < until {
                for (to_b, session) in [(true, &mut self.a), (false, &mut self.b)] {
                    while let Some(packet) = session.poll_transmit(self.now) {
                        self.sent += 1;
                        if !lose(self.sent, self.now) {
                            self.flight
                                .push((self.now + self.delay, to_b, packet.encode()));
                        }
                    }
                }
                let landed: Vec<_> = self
                    .flight
                    .iter()
                    .filter(|(t, _, _)| *t <= self.now)
                    .copied()
                    .collect();
                self.flight.retain(|(t, _, _)| *t > self.now);
                for (_, to_b, bytes) in landed {
                    let session = if to_b { &mut self.b } else { &mut self.a };
                    session.receive(&bytes, TTL, self.now).unwrap();
                }
                let next = [
                    self.a.next_deadline_ns(),
                    self.b.next_deadline_ns(),
                    self.flight
                        .iter()
                        .map(|(t, _, _)| *t)
                        .min()
                        .unwrap_or(u64::MAX),
                    until,
                ]
                .into_iter()
                .min()
                .unwrap();
                self.now = next.max(self.now + 1);
            }
        }
    }

    /// Every transition a session makes is one the state machine allows.
    fn transitions_are_legal(log: &Log) {
        for t in &log.transitions {
            let legal = matches!(
                (t.from, t.to),
                (State::Down, State::Init | State::Up)
                    | (State::Init, State::Up | State::Down)
                    | (State::Up, State::Down)
            );
            assert!(legal, "illegal transition {t:?}");
        }
    }

    #[test]
    fn packets_read_back_as_written() {
        bolero::check!()
            .with_type::<(u8, u8, bool, bool, u8, u32, u32, u32, u32)>()
            .for_each(|&(diag, state, poll, fin, mult, mine, yours, tx, rx)| {
                let packet = Packet {
                    diag: diag & 0x1f,
                    state: State::from_bits(state),
                    poll,
                    fin,
                    detect_mult: mult.max(1),
                    my_discriminator: mine.max(1),
                    your_discriminator: yours,
                    desired_min_tx_us: tx,
                    required_min_rx_us: rx,
                    required_min_echo_rx_us: 0,
                };
                assert_eq!(Packet::decode(&packet.encode()), Ok(packet));
            });
    }

    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //= type=test
    //# If the version number is not correct (1), the packet MUST be
    //# discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //= type=test
    //# If the Detect Mult field is zero, the packet MUST be discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //= type=test
    //# If the Multipoint (M) bit is nonzero, the packet MUST be
    //# discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //= type=test
    //# If the My Discriminator field is zero, the packet MUST be
    //# discarded.
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //= type=test
    //# If the A bit is set and no authentication is in use (bfd.AuthType
    //# is zero), the packet MUST be discarded.
    #[test]
    fn malformed_packets_are_discarded() {
        let good = Session::new(config(1), 0)
            .poll_transmit(0)
            .unwrap()
            .encode();
        let broken = |at: usize, value: u8| {
            let mut bytes = good;
            bytes[at] = value;
            Packet::decode(&bytes)
        };
        assert_eq!(broken(0, 2 << 5), Err(Discard::Version(2)));
        assert_eq!(broken(3, 23), Err(Discard::Length(23)));
        assert_eq!(broken(3, 30), Err(Discard::Short));
        assert_eq!(broken(2, 0), Err(Discard::DetectMult));
        assert_eq!(broken(1, good[1] | 0x01), Err(Discard::Multipoint));
        assert_eq!(broken(1, good[1] | 0x04), Err(Discard::Length(24)));
        let mut no_discriminator = good;
        no_discriminator[4..8].fill(0);
        assert_eq!(
            Packet::decode(&no_discriminator),
            Err(Discard::MyDiscriminator)
        );
        let mut authenticated = good;
        authenticated[1] |= 0x04;
        authenticated[3] = 26;
        let mut longer = authenticated.to_vec();
        longer.extend([0, 0]);
        assert_eq!(Packet::decode(&longer), Err(Discard::Authenticated));
    }

    //= https://www.rfc-editor.org/rfc/rfc5881#section-5
    //= type=test
    //# All received BFD Control packets that are
    //# demultiplexed to the session MUST be discarded if the received TTL or
    //# Hop Limit is not equal to 255.
    #[test]
    fn a_packet_that_crossed_a_router_is_discarded() {
        let packet = Session::new(config(1), 0)
            .poll_transmit(0)
            .unwrap()
            .encode();
        let mut session = Session::new(config(2), 0);
        assert_eq!(session.receive(&packet, 254, 0), Err(Discard::Ttl(254)));
        assert_eq!(session.log(0).discarded, 1);
        assert_eq!(session.log(0).received, 0);
    }

    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //= type=test
    //# If the Your Discriminator field is zero and the State field is not
    //# Down or AdminDown, the packet MUST be discarded.
    #[test]
    fn an_unaddressed_packet_from_a_session_already_up_is_discarded() {
        let mut packet = Session::new(config(1), 0).poll_transmit(0).unwrap();
        packet.state = State::Up;
        packet.your_discriminator = 0;
        let mut session = Session::new(config(2), 0);
        assert_eq!(
            session.receive(&packet.encode(), TTL, 0),
            Err(Discard::Unselected(State::Up))
        );
        packet.your_discriminator = 7;
        assert_eq!(
            session.receive(&packet.encode(), TTL, 0),
            Err(Discard::YourDiscriminator(7))
        );
    }

    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.7
    //= type=test
    //# If a BFD Control packet is received with the Poll (P) bit set to 1,
    //# the receiving system MUST transmit a BFD Control packet with the Poll
    //# (P) bit clear and the Final (F) bit set as soon as practicable,
    //# without respect to the transmission timer or any other transmission
    //# limitations, without respect to the session state, and without
    //# respect to whether Demand mode is active on either system.
    #[test]
    fn a_poll_is_answered_at_once() {
        let mut session = Session::new(config(2), 0);
        // Drain what the new session would send anyway.
        while session.poll_transmit(0).is_some() {}
        let mut poll = Session::new(config(1), 0).poll_transmit(0).unwrap();
        poll.poll = true;
        session.receive(&poll.encode(), TTL, 10).unwrap();
        // Long before the next periodic packet is due.
        let answer = session.poll_transmit(11).expect("a Final, at once");
        assert!(answer.fin && !answer.poll);
    }

    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.3
    //= type=test
    //# When bfd.SessionState is not Up, the system MUST set
    //# bfd.DesiredMinTxInterval to a value of not less than one second
    //# (1,000,000 microseconds).
    //
    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6
    //= type=test
    //# If a Poll Sequence is being transmitted by the local system and
    //# the Final (F) bit in the received packet is set, the Poll Sequence
    //# MUST be terminated.
    #[test]
    fn sessions_come_up_slowly_then_run_fast() {
        let mut pair = Pair::new();
        let first = pair.a.poll_transmit(0).unwrap();
        assert_eq!(first.state, State::Down);
        assert!(first.desired_min_tx_us >= 1_000_000, "not Up, not fast");
        pair.run(10_000 * MS, &mut |_, _| false);
        for session in [&pair.a, &pair.b] {
            assert_eq!(session.state(), State::Up);
            let log = session.log(pair.now);
            transitions_are_legal(&log);
            assert_eq!(log.flaps, 0, "{:?}", log.transitions);
            assert_eq!(log.gaps_over_half, 0, "a lossless link never comes close");
            assert!(
                log.first_up_ns.unwrap() < 10 * MS,
                "Up within a few packets"
            );
            assert!(
                !session.polling,
                "the poll for the faster interval was answered"
            );
            // Ten seconds at 50 ms, less up to a quarter for jitter: at least 200 packets.
            assert!(
                log.sent > 200,
                "sent only {} packets: never sped up",
                log.sent
            );
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc5880#section-6.8.4
    //= type=test
    //# If Demand mode is not active, and a period of time equal to the
    //# Detection Time passes without receiving a BFD Control packet from the
    //# remote system, and bfd.SessionState is Init or Up, the session has
    //# gone down -- the local system MUST set bfd.SessionState to Down and
    //# bfd.LocalDiag to 1 (Control Detection Time Expired).
    #[test]
    fn silence_for_a_detection_time_takes_a_session_down_and_it_recovers() {
        let mut pair = Pair::new();
        pair.run(2_000 * MS, &mut |_, _| false);
        assert_eq!(pair.a.state(), State::Up);
        // Half a second of silence: ten times the 150 ms Detection Time.
        pair.run(2_500 * MS, &mut |_, now| now >= 2_000 * MS);
        for session in [&pair.a, &pair.b] {
            assert_eq!(session.state(), State::Down);
            let down = session.log(pair.now).transitions.last().copied().unwrap();
            assert_eq!(down.diag, Diag::DetectionTimeExpired);
        }
        pair.run(10_000 * MS, &mut |_, _| false);
        for session in [&pair.a, &pair.b] {
            assert_eq!(session.state(), State::Up);
            let log = session.log(pair.now);
            transitions_are_legal(&log);
            assert_eq!(log.flaps, 1);
        }
    }

    /// Whatever packets are lost, every transition is legal, and the log's flaps are the session's
    /// departures from Up.
    #[test]
    fn under_any_loss_a_session_keeps_to_its_state_machine() {
        bolero::check!()
            .with_type::<Vec<u8>>()
            .for_each(|pattern: &Vec<u8>| {
                let mut pair = Pair::new();
                let mut lose = |n: u64, _| {
                    let at = usize::try_from(n).unwrap() % (pattern.len() * 8).max(1);
                    pattern
                        .get(at / 8)
                        .is_some_and(|byte| byte >> (at % 8) & 1 == 1)
                };
                pair.run(5_000 * MS, &mut lose);
                for session in [&pair.a, &pair.b] {
                    let log = session.log(pair.now);
                    transitions_are_legal(&log);
                    let departures = log
                        .transitions
                        .iter()
                        .filter(|t| t.from == State::Up)
                        .count() as u64;
                    assert_eq!(log.flaps, departures);
                }
            });
    }
}
