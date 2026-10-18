// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a stream sends, and the sender that paces it and builds its frames.
//!
//! A [`Sender`] knows nothing of where its frames go: a [`Wire`](crate::drive::Wire) asks it which
//! packets to send now, has it stamp them, and tells it which were taken.

use std::collections::VecDeque;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::frame::{FrameSpec, Template};
use crate::ledger::Ledger;
use crate::schedule::{Schedule, Slot};
use crate::space::{self, FlowSpace};

/// The most packets a sender offers at once.
pub const BURST: usize = 64;

/// What a stream sends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stream {
    /// Its name, under which its counters are reported.
    pub name: String,
    /// The flows it draws from.
    pub space: FlowSpace,
    /// Which flows it sends to, when: flows `0..schedule.flows()` of the space.
    pub schedule: Schedule,
    /// How every frame is built.
    pub frame: FrameSpec,
    /// The most packets a second, or as fast as the queues take them if `None`.
    pub rate_pps: Option<u64>,
}

/// A clock both directions read, so that a packet's latency is one clock's difference.
#[derive(Debug, Clone, Copy)]
pub struct Clock(Instant);

impl Clock {
    /// A clock starting now.
    #[must_use]
    pub fn start() -> Clock {
        Clock(clock::now())
    }

    /// Nanoseconds since the clock started.
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        u64::try_from(clock::elapsed(self.0).as_nanos()).unwrap_or(u64::MAX)
    }
}

/// The templates of the flows in a stream's current window, built as flows enter it and dropped
/// as they leave, so that a stream of millions of flows holds only a window's worth.
struct Templates {
    frame: FrameSpec,
    space: FlowSpace,
    run: u32,
    queues: usize,
    /// The flow number of the front template.
    base: u64,
    window: VecDeque<(Template, usize)>,
    /// A retired flow's template, rebuilt for a retry.
    spare: Option<(Template, usize)>,
}

impl Templates {
    fn build(&self, flow: u64) -> (Template, usize) {
        let tuple = self.space.flow(flow);
        let queue = space::hash(&tuple) % self.queues.max(1) as u64;
        (
            Template::new(&self.frame, self.run, flow, &tuple),
            usize::try_from(queue).unwrap_or(0),
        )
    }

    /// Drop the templates of flows below `flow`.
    fn retire(&mut self, flow: u64) {
        while self.base < flow && self.window.pop_front().is_some() {
            self.base += 1;
        }
        self.base = self.base.max(flow);
    }

    /// Stamp `slot`'s flow's template as `slot`, sent at `tx_ns`; return the frame and its queue.
    ///
    /// A flow already retired -- a retry, refused by a full queue as the window moved on -- has
    /// its template built afresh.
    fn stamp(&mut self, slot: Slot, tx_ns: u64) -> (&[u8], usize) {
        let entry = if slot.flow < self.base {
            &mut *self.spare.insert(self.build(slot.flow))
        } else {
            while slot.flow >= self.base + self.window.len() as u64 {
                let next = self.build(self.base + self.window.len() as u64);
                self.window.push_back(next);
            }
            let at = usize::try_from(slot.flow - self.base).unwrap_or(usize::MAX);
            &mut self.window[at]
        };
        entry.0.stamp(slot.seq, tx_ns);
        (entry.0.bytes(), entry.1)
    }
}

/// Sends a [`Stream`], spreading its flows over transmit queues the way RSS would spread them
/// over a receiver's.
pub struct Sender {
    stream: Stream,
    run: u32,
    templates: Templates,
    /// The next packet to send.
    next: u64,
    /// Packets a full queue refused, to send before anything new.
    retry: Vec<Slot>,
    started: Option<Instant>,
}

impl Sender {
    /// A sender for `stream` in run `run`, over `queues` transmit queues.
    #[must_use]
    pub fn new(stream: Stream, run: u32, queues: usize) -> Sender {
        let templates = Templates {
            frame: stream.frame,
            space: stream.space,
            run,
            queues,
            base: 0,
            window: VecDeque::new(),
            spare: None,
        };
        Sender {
            stream,
            run,
            templates,
            next: 0,
            retry: Vec::new(),
            started: None,
        }
    }

    /// The stream being sent.
    #[must_use]
    pub fn stream(&self) -> &Stream {
        &self.stream
    }

    /// The run number its packets are signed with.
    #[must_use]
    pub fn run(&self) -> u32 {
        self.run
    }

    /// Whether every packet has been sent.
    #[must_use]
    pub fn done(&self) -> bool {
        self.retry.is_empty() && self.next >= self.stream.schedule.packets()
    }

    /// The next packets to send, at most `max`, retries first.
    fn take(&mut self, max: usize) -> Vec<Slot> {
        let mut out: Vec<_> = self.retry.drain(..self.retry.len().min(max)).collect();
        while out.len() < max {
            let Some(slot) = self.stream.schedule.slot(self.next) else {
                break;
            };
            out.push(slot);
            self.next += 1;
        }
        if let Some(window) = self.next.checked_div(self.stream.schedule.window) {
            self.templates
                .retire(self.stream.schedule.window_start(window));
        }
        out
    }

    /// The packets to send now: as many as the rate allows given `sent` so far, at most a burst,
    /// retries first. Each must be either [`accepted`](Self::accepted) or
    /// [`refused`](Self::refused) once offered.
    pub fn plan(&mut self, sent: u64) -> Vec<Slot> {
        let allowed = self.allowance(sent);
        self.take(allowed)
    }

    /// Stamp `slot`'s frame, sent at `tx_ns`, and return it with the queue its flow goes on.
    pub fn stamp(&mut self, slot: Slot, tx_ns: u64) -> (&[u8], usize) {
        self.templates.stamp(slot, tx_ns)
    }

    /// Count `slot` as sent in `ledger`.
    pub fn accepted(&mut self, slot: Slot, ledger: &mut Ledger) {
        ledger.sent(usize::try_from(slot.flow).unwrap_or(usize::MAX));
    }

    /// Send `slots` again before anything new: whatever they were offered to had no room.
    pub fn refused(&mut self, slots: &[Slot]) {
        self.retry.extend_from_slice(slots);
    }

    /// How many packets the rate allows sending now.
    fn allowance(&mut self, sent: u64) -> usize {
        let Some(rate) = self.stream.rate_pps else {
            return BURST;
        };
        let started = *self.started.get_or_insert_with(Instant::now);
        let due =
            u64::try_from(clock::elapsed(started).as_nanos() * u128::from(rate) / 1_000_000_000)
                .unwrap_or(u64::MAX);
        usize::try_from(due.saturating_sub(sent))
            .unwrap_or(BURST)
            .min(BURST)
    }
}
