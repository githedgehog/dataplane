// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A heartbeat over a byte stream: a session that stands in for BGP's without speaking it.
//!
//! The gateway tells BGP from everything else by its addresses and TCP port alone: from a
//! neighbour, to a local address, to or from port 179. It never reads a BGP message. So a TCP
//! connection on port 179 that carries anything at all is, to the gateway, a BGP session: classed,
//! policed and given the control path as one. What a test wants to know of that session is whether
//! it would have survived -- whether anything arrived late enough to expire a BGP Hold Timer --
//! and that a heartbeat measures far more finely than BGP's keepalives, which come no oftener than
//! once a second.
//!
//! [`Session`] does no I/O: it is told when its connection comes up or goes down, given the bytes
//! that arrive, and asked for the bytes to send, all at times it is told. A
//! [`crate::tcp::Host`] with a heartbeat role carries it over smoltcp.
//!
//! Each end sends a beat every interval: a magic number, a sequence number, the time it was sent
//! on the sender's clock, and the send time of the last beat it heard, with how long it held that
//! before echoing it. So each end measures the round trip on its own clock alone, and the two ends
//! need not share one. An end that hears nothing for the hold time gives the connection up, as a
//! BGP speaker would at its Hold Timer's expiry.
//!
//! What a session reports: how often it came up and went down and why, beats each way, beats
//! mangled or out of sequence, and the gaps between beats and the round trips, by power of two.

use flowgen_report::Sample;
use serde::{Deserialize, Serialize};

/// The TCP port a heartbeat uses unless told otherwise: BGP's, so the gateway takes it for BGP.
pub const PORT: u16 = 179;

/// The port a heartbeat uses unless told otherwise.
#[must_use]
pub fn default_port() -> u16 {
    PORT
}

const MAGIC: [u8; 4] = *b"FGHB";
const BEAT_LEN: usize = 32;
/// An echo field that echoes nothing: no beat heard yet.
const NO_ECHO: u64 = u64::MAX;
const MS: u64 = 1_000_000;

/// How a session is to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Milliseconds between beats; at least one.
    pub interval_ms: u64,
    /// Milliseconds of silence after which the connection is given up, as a BGP speaker gives one
    /// up at its Hold Timer's expiry; zero never to.
    pub hold_ms: u64,
}

/// What a session saw: everything a report says about it.
#[derive(Debug, Clone)]
pub struct Log {
    /// Times a connection came up.
    pub up: u64,
    /// Times one went down, for whatever reason.
    pub down: u64,
    /// Times the session gave one up for silence longer than the hold time.
    pub expiries: u64,
    /// Beats sent.
    pub beats_sent: u64,
    /// Beats received.
    pub beats_received: u64,
    /// Beats received without the magic number: the stream is not what was sent, and the session
    /// gives the connection up, having lost its framing.
    pub mangled: u64,
    /// Beats received out of sequence on their connection.
    pub out_of_sequence: u64,
    /// Gaps between beats longer than two intervals: at least one beat was late.
    pub late: u64,
    /// The longest gap between beats on one connection, in nanoseconds.
    pub max_gap_ns: u64,
    /// The longest round trip, in nanoseconds.
    pub max_rtt_ns: u64,
    /// Gaps by power of two: bucket `k` holds gaps in `[2^(k-1), 2^k)`.
    pub gaps: [u64; 65],
    /// Round trips by power of two, bucketed as `gaps` is.
    pub rtts: [u64; 65],
    /// When a connection first came up, in nanoseconds.
    pub first_up_ns: Option<u64>,
    /// Time spent up, in nanoseconds, up to the last time the session was looked at.
    pub time_up_ns: u64,
}

impl Default for Log {
    fn default() -> Log {
        Log {
            up: 0,
            down: 0,
            expiries: 0,
            beats_sent: 0,
            beats_received: 0,
            mangled: 0,
            out_of_sequence: 0,
            late: 0,
            max_gap_ns: 0,
            max_rtt_ns: 0,
            gaps: [0; 65],
            rtts: [0; 65],
            first_up_ns: None,
            time_up_ns: 0,
        }
    }
}

fn bucket(ns: u64) -> usize {
    64 - ns.leading_zeros() as usize
}

/// A heartbeat over one connection at a time. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct Session {
    interval_ns: u64,
    hold_ns: u64,
    /// When the current connection came up, if one is up.
    up_since_ns: Option<u64>,
    /// Bytes received and not yet a whole beat.
    rx: Vec<u8>,
    /// Bytes to send.
    tx: Vec<u8>,
    /// When anything was last heard, or the connection came up.
    last_heard_ns: u64,
    /// When the last beat arrived, on this connection.
    last_beat_ns: Option<u64>,
    /// When the last beat was sent, on this connection.
    last_sent_ns: Option<u64>,
    next_seq: u32,
    expect_seq: u32,
    /// The last beat heard, to echo: its send time on the peer's clock, and when it arrived.
    echo: Option<(u64, u64)>,
    /// The connection should be given up.
    close: bool,
    log: Log,
}

impl Session {
    /// A session, down until its connection comes up.
    ///
    /// # Panics
    ///
    /// If `config`'s interval is zero.
    #[must_use]
    pub fn new(config: Config) -> Session {
        assert!(
            config.interval_ms > 0,
            "a heartbeat beats at least every so often"
        );
        Session {
            interval_ns: config.interval_ms.saturating_mul(MS),
            hold_ns: config.hold_ms.saturating_mul(MS),
            up_since_ns: None,
            rx: Vec::new(),
            tx: Vec::new(),
            last_heard_ns: 0,
            last_beat_ns: None,
            last_sent_ns: None,
            next_seq: 0,
            expect_seq: 0,
            echo: None,
            close: false,
            log: Log::default(),
        }
    }

    /// Whether a connection is up.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.up_since_ns.is_some()
    }

    /// Whether the session has given its connection up and wants it closed.
    #[must_use]
    pub fn wants_close(&self) -> bool {
        self.close
    }

    /// What the session has seen, with time up counted to `now_ns`.
    #[must_use]
    pub fn log(&self, now_ns: u64) -> Log {
        let mut log = self.log.clone();
        if let Some(since) = self.up_since_ns {
            log.time_up_ns += now_ns.saturating_sub(since);
        }
        log
    }

    /// The connection is up: start beating.
    pub fn connected(&mut self, now_ns: u64) {
        if self.is_up() {
            return;
        }
        self.up_since_ns = Some(now_ns);
        self.log.up += 1;
        self.log.first_up_ns.get_or_insert(now_ns);
        self.rx.clear();
        self.tx.clear();
        self.last_heard_ns = now_ns;
        self.last_beat_ns = None;
        self.last_sent_ns = None;
        self.next_seq = 0;
        self.expect_seq = 0;
        self.echo = None;
        self.close = false;
    }

    /// The connection is down.
    pub fn disconnected(&mut self, now_ns: u64) {
        if let Some(since) = self.up_since_ns.take() {
            self.log.down += 1;
            self.log.time_up_ns += now_ns.saturating_sub(since);
        }
        self.rx.clear();
        self.tx.clear();
        self.close = false;
    }

    /// Take `bytes` from the connection, at `now_ns`.
    pub fn receive(&mut self, bytes: &[u8], now_ns: u64) {
        if !self.is_up() || self.close {
            return;
        }
        self.last_heard_ns = now_ns;
        self.rx.extend_from_slice(bytes);
        let whole = self.rx.len() / BEAT_LEN * BEAT_LEN;
        let beats: Vec<u8> = self.rx.drain(..whole).collect();
        for beat in beats.as_chunks::<BEAT_LEN>().0 {
            if !self.beat(beat, now_ns) {
                self.log.mangled += 1;
                self.close = true;
                self.rx.clear();
                return;
            }
        }
    }

    /// Count one beat; false if it is not one.
    fn beat(&mut self, beat: &[u8; BEAT_LEN], now_ns: u64) -> bool {
        let field = |at: usize| {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&beat[at..at + 8]);
            u64::from_be_bytes(bytes)
        };
        if beat[..4] != MAGIC {
            return false;
        }
        let seq = u32::from_be_bytes([beat[4], beat[5], beat[6], beat[7]]);
        let (sent_ns, echo_ns, held_ns) = (field(8), field(16), field(24));
        self.log.beats_received += 1;
        if seq != self.expect_seq {
            self.log.out_of_sequence += 1;
        }
        self.expect_seq = seq.wrapping_add(1);
        if let Some(last) = self.last_beat_ns.replace(now_ns) {
            let gap = now_ns.saturating_sub(last);
            self.log.gaps[bucket(gap)] += 1;
            self.log.max_gap_ns = self.log.max_gap_ns.max(gap);
            if gap > 2 * self.interval_ns {
                self.log.late += 1;
            }
        }
        if echo_ns != NO_ECHO {
            let rtt = now_ns.saturating_sub(echo_ns).saturating_sub(held_ns);
            self.log.rtts[bucket(rtt)] += 1;
            self.log.max_rtt_ns = self.log.max_rtt_ns.max(rtt);
        }
        self.echo = Some((sent_ns, now_ns));
        true
    }

    /// The bytes to send at `now_ns`, if any: a beat when one is due. Gives the connection up if
    /// nothing has been heard for the hold time.
    pub fn transmit(&mut self, now_ns: u64) -> Option<Vec<u8>> {
        if !self.is_up() || self.close {
            return None;
        }
        if self.hold_ns != 0 && now_ns.saturating_sub(self.last_heard_ns) > self.hold_ns {
            self.log.expiries += 1;
            self.close = true;
            return None;
        }
        let due = self
            .last_sent_ns
            .is_none_or(|last| now_ns.saturating_sub(last) >= self.interval_ns);
        if due {
            let (echo_ns, held_ns) = self
                .echo
                .take()
                .map_or((NO_ECHO, 0), |(sent, at)| (sent, now_ns.saturating_sub(at)));
            self.tx.extend_from_slice(&MAGIC);
            self.tx.extend_from_slice(&self.next_seq.to_be_bytes());
            self.tx.extend_from_slice(&now_ns.to_be_bytes());
            self.tx.extend_from_slice(&echo_ns.to_be_bytes());
            self.tx.extend_from_slice(&held_ns.to_be_bytes());
            self.next_seq = self.next_seq.wrapping_add(1);
            self.last_sent_ns = Some(now_ns);
            self.log.beats_sent += 1;
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
        if !self.is_up() || self.close {
            return u64::MAX;
        }
        if !self.tx.is_empty() {
            return 0;
        }
        let beat = self
            .last_sent_ns
            .map_or(0, |last| last.saturating_add(self.interval_ns));
        if self.hold_ns == 0 {
            beat
        } else {
            beat.min(self.last_heard_ns.saturating_add(self.hold_ns + 1))
        }
    }

    /// `sample`, with the session's log under `heartbeat.<name>.` as of `now_ns`.
    #[must_use]
    pub fn sample(&self, name: &str, now_ns: u64, sample: Sample) -> Sample {
        let log = self.log(now_ns);
        let path = |what: &str| format!("heartbeat.{name}.{what}");
        let mut sample = [
            ("up", log.up),
            ("down", log.down),
            ("expiries", log.expiries),
            ("beats_sent", log.beats_sent),
            ("beats_received", log.beats_received),
            ("mangled", log.mangled),
            ("out_of_sequence", log.out_of_sequence),
            ("late", log.late),
        ]
        .into_iter()
        .fold(sample, |sample, (what, n)| sample.counter(path(what), n));
        for (what, buckets) in [("gap_ns", &log.gaps), ("rtt_ns", &log.rtts)] {
            for (k, &n) in buckets.iter().enumerate().filter(|(_, n)| **n > 0) {
                // Bucket `k` holds values below 2^k.
                let below = 1u128 << k;
                sample = sample.counter(path(&format!("{what}.lt_{below}")), n);
            }
        }
        let sample = sample
            .gauge(path("is_up"), u64::from(self.is_up()))
            .gauge(path("interval_ns"), self.interval_ns)
            .gauge(path("hold_ns"), self.hold_ns)
            .gauge(path("gap_ns.max"), log.max_gap_ns)
            .gauge(path("rtt_ns.max"), log.max_rtt_ns)
            .gauge(path("time_up_ns"), log.time_up_ns);
        match log.first_up_ns {
            Some(t) => sample.gauge(path("first_up_ns"), t),
            None => sample,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const CONFIG: Config = Config {
        interval_ms: 100,
        hold_ms: 1_000,
    };

    /// Two sessions over a link that takes `delay_ns` each way, stepped a millisecond at a time
    /// from `from` for `span`, delivering nothing while `dead`.
    fn run(a: &mut Session, b: &mut Session, from: u64, span: u64, delay_ns: u64, dead: bool) {
        let mut flight: Vec<(u64, bool, Vec<u8>)> = Vec::new();
        let mut now = from;
        while now < from + span {
            for (a_to_b, session) in [(true, &mut *a), (false, &mut *b)] {
                if let Some(bytes) = session.transmit(now)
                    && !dead
                {
                    flight.push((now + delay_ns, a_to_b, bytes));
                }
            }
            let (arrived, still): (Vec<_>, Vec<_>) =
                flight.into_iter().partition(|(at, ..)| *at <= now);
            flight = still;
            for (_, a_to_b, bytes) in arrived {
                if a_to_b {
                    b.receive(&bytes, now);
                } else {
                    a.receive(&bytes, now);
                }
            }
            now += MS;
        }
    }

    #[test]
    fn two_sessions_beat_and_measure_the_round_trip() {
        let (mut a, mut b) = (Session::new(CONFIG), Session::new(CONFIG));
        a.connected(0);
        b.connected(0);
        run(&mut a, &mut b, 0, 10_000 * MS, 5 * MS, false);
        for session in [&a, &b] {
            let log = session.log(10_000 * MS);
            assert!(session.is_up());
            assert!((99..=101).contains(&log.beats_received), "{log:?}");
            assert_eq!((log.mangled, log.out_of_sequence, log.late), (0, 0, 0));
            assert_eq!(log.expiries, 0);
            // Every gap is the interval, give or take the millisecond the test steps by.
            assert!((99 * MS..=101 * MS).contains(&log.max_gap_ns), "{log:?}");
            // Ten milliseconds there and back, however long each end held a beat before echoing.
            assert!((10 * MS..=11 * MS).contains(&log.max_rtt_ns), "{log:?}");
            assert!(log.rtts.iter().sum::<u64>() >= 98);
        }
    }

    #[test]
    fn silence_for_the_hold_time_gives_the_connection_up() {
        let (mut a, mut b) = (Session::new(CONFIG), Session::new(CONFIG));
        a.connected(0);
        b.connected(0);
        run(&mut a, &mut b, 0, 2_000 * MS, MS, false);
        run(&mut a, &mut b, 2_000 * MS, 1_500 * MS, MS, true);
        for session in [&mut a, &mut b] {
            assert!(session.wants_close());
            assert_eq!(session.log(3_500 * MS).expiries, 1);
            session.disconnected(3_500 * MS);
            let log = session.log(3_500 * MS);
            assert_eq!((log.up, log.down), (1, 1));
            assert!(!session.is_up());
            assert_eq!(session.next_deadline_ns(), u64::MAX);
        }
    }

    #[test]
    fn a_late_beat_is_counted() {
        let (mut a, mut b) = (Session::new(CONFIG), Session::new(CONFIG));
        a.connected(0);
        b.connected(0);
        run(&mut a, &mut b, 0, 1_000 * MS, MS, false);
        // Half a second lost: within the hold time, but four beats missed.
        run(&mut a, &mut b, 1_000 * MS, 500 * MS, MS, true);
        run(&mut a, &mut b, 1_500 * MS, 1_000 * MS, MS, false);
        let log = b.log(2_500 * MS);
        assert_eq!(log.late, 1);
        assert_eq!(log.expiries, 0);
        assert!(log.max_gap_ns >= 500 * MS);
        // The beats lost on the link are gone from the stream's sequence too: the session cannot
        // tell a lost beat from one never sent, which TCP never lets happen.
        assert_eq!(log.out_of_sequence, 1);
    }

    #[test]
    fn a_beat_without_the_magic_number_gives_the_connection_up() {
        let mut session = Session::new(CONFIG);
        session.connected(0);
        session.receive(&[0; BEAT_LEN], MS);
        assert!(session.wants_close());
        assert_eq!(session.log(MS).mangled, 1);
        assert_eq!(session.transmit(2 * MS), None);
    }

    #[test]
    fn beats_split_across_reads_are_whole_beats() {
        let (mut a, mut b) = (Session::new(CONFIG), Session::new(CONFIG));
        a.connected(0);
        b.connected(0);
        let mut bytes = a.transmit(0).unwrap();
        bytes.extend(a.transmit(100 * MS).unwrap());
        for chunk in bytes.chunks(7) {
            b.receive(chunk, 100 * MS);
        }
        let log = b.log(100 * MS);
        assert_eq!(
            (log.beats_received, log.mangled, log.out_of_sequence),
            (2, 0, 0)
        );
    }

    /// Whatever arrives, a session neither panics nor stops keeping time.
    #[test]
    fn any_bytes_are_survived() {
        bolero::check!()
            .with_type::<Vec<Vec<u8>>>()
            .for_each(|reads| {
                let mut session = Session::new(CONFIG);
                session.connected(0);
                for (n, bytes) in reads.iter().enumerate() {
                    let now = u64::try_from(n).unwrap() * MS;
                    session.receive(bytes, now);
                    let _ = session.transmit(now);
                    assert!(session.wants_close() || session.next_deadline_ns() > now);
                }
            });
    }
}
