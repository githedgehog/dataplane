// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Sending a stream on DPDK queues and accounting for what comes back on them.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dpdk::mem::{MBUF_BURST, MbufArray, Pool};
use dpdk::queue::rx::RxQueue;
use dpdk::queue::tx::TxQueue;
use net::buffer::Append;
use serde::{Deserialize, Serialize};

use crate::frame::{FrameSpec, Template};
use crate::ledger::Ledger;
use crate::schedule::{Schedule, Slot};
use crate::space::{self, FlowSpace};

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

    /// How many packets the rate allows sending now.
    fn allowance(&mut self, sent: u64) -> usize {
        let Some(rate) = self.stream.rate_pps else {
            return MBUF_BURST;
        };
        let started = *self.started.get_or_insert_with(Instant::now);
        let due =
            u64::try_from(clock::elapsed(started).as_nanos() * u128::from(rate) / 1_000_000_000)
                .unwrap_or(u64::MAX);
        usize::try_from(due.saturating_sub(sent))
            .unwrap_or(MBUF_BURST)
            .min(MBUF_BURST)
    }

    /// Send what the rate allows, at most one burst, on `queues`, from `pool`; count what the
    /// queues took in `ledger`. Returns how many were sent: none if `pool` has nothing to spare,
    /// which is back-pressure from frames still in flight, not an error.
    pub fn send<'d>(
        &mut self,
        queues: &mut [TxQueue<'d>],
        pool: &Pool<'d>,
        ledger: &mut Ledger,
        clock: &Clock,
    ) -> usize {
        let allowed = self.allowance(ledger.total_sent());
        let packets = self.take(allowed);
        if packets.is_empty() {
            return 0;
        }
        let Ok(mut mbufs) = pool.alloc_bulk(packets.len()) else {
            self.retry.extend(packets);
            return 0;
        };
        let mut by_queue: Vec<(MbufArray<'d>, Vec<Slot>)> = (0..queues.len())
            .map(|_| (MbufArray::new_empty(), Vec::new()))
            .collect();
        for (mbuf, &slot) in mbufs.drain_all().zip(&packets) {
            let mut mbuf = mbuf;
            let (bytes, queue) = self.templates.stamp(slot, clock.now_ns());
            let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
            match mbuf.append(len) {
                Ok(room) => room.copy_from_slice(bytes),
                Err(_) => continue, // the template outgrew the mbuf: a misconfigured stream
            }
            let queue = queue.min(queues.len().saturating_sub(1));
            let (batch, sent) = &mut by_queue[queue];
            if batch.try_push(mbuf).is_ok() {
                sent.push(slot);
            }
        }
        let mut total = 0;
        for (queue, (batch, packets)) in queues.iter_mut().zip(by_queue) {
            let offered = batch.len();
            let refused = queue.transmit(batch).len();
            let accepted = offered - refused;
            for slot in &packets[..accepted] {
                ledger.sent(usize::try_from(slot.flow).unwrap_or(usize::MAX));
            }
            self.retry.extend_from_slice(&packets[accepted..]);
            total += accepted;
        }
        total
    }
}

/// Receive whatever is waiting on `queues` and count it in `ledger`. Returns how many frames.
pub fn receive(queues: &mut [RxQueue<'_>], ledger: &mut Ledger, clock: &Clock) -> usize {
    let mut total = 0;
    for queue in queues {
        let burst = queue.receive();
        let now = clock.now_ns();
        for mbuf in &burst {
            ledger.receive(mbuf.raw_data(), now);
            total += 1;
        }
    }
    total
}

/// How a [`run`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Everything sent came back.
    AllBack,
    /// Everything was sent, and then nothing came back for the quiet period.
    Quiet,
    /// The time allowed ran out first.
    OutOfTime,
}

/// How long a [`run`] waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patience {
    /// How long, once everything is sent, to wait for the rest to come back after the last did.
    pub quiet: Duration,
    /// The longest the whole run may take.
    pub limit: Duration,
}

/// The queues a stream is sent and received on, and the pool its frames come from.
pub struct Queues<'q, 'd> {
    /// Where frames are sent.
    pub tx: &'q mut [TxQueue<'d>],
    /// Where they come back.
    pub rx: &'q mut [RxQueue<'d>],
    /// What they are built in.
    pub pool: &'q Pool<'d>,
}

/// Send `sender`'s stream and count what comes back, until everything sent has come back or
/// `patience` runs out. `sample` is shown the ledger every `every`, and once more at the end.
pub fn run(
    sender: &mut Sender,
    queues: &mut Queues<'_, '_>,
    ledger: &mut Ledger,
    clock: &Clock,
    patience: Patience,
    every: Duration,
    mut sample: impl FnMut(&Ledger),
) -> Ending {
    let started = clock::now();
    let mut last_heard = clock::now();
    let mut last_sample = clock::now();
    let ending = loop {
        sender.send(queues.tx, queues.pool, ledger, clock);
        if receive(queues.rx, ledger, clock) > 0 {
            last_heard = clock::now();
        }
        if clock::elapsed(last_sample) >= every {
            sample(ledger);
            last_sample = clock::now();
        }
        if sender.done() {
            if ledger.total_received() >= ledger.total_sent() {
                break Ending::AllBack;
            }
            if clock::elapsed(last_heard) > patience.quiet {
                break Ending::Quiet;
            }
        }
        if clock::elapsed(started) > patience.limit {
            break Ending::OutOfTime;
        }
    };
    sample(ledger);
    ending
}
