// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Sending a stream on DPDK queues and accounting for what comes back on them.

use std::time::{Duration, Instant};

use dpdk::mem::{MBUF_BURST, MbufArray, Pool};
use dpdk::queue::rx::RxQueue;
use dpdk::queue::tx::TxQueue;
use net::buffer::Append;
use serde::{Deserialize, Serialize};

use crate::frame::{FrameSpec, Template};
use crate::ledger::Ledger;
use crate::space::{self, FlowSpace};

/// What a stream sends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stream {
    /// Its name, under which its counters are reported.
    pub name: String,
    /// The flows it draws from.
    pub space: FlowSpace,
    /// How many of them it sends: flows `0..flows` of the space.
    pub flows: usize,
    /// How every frame is built.
    pub frame: FrameSpec,
    /// Packets sent per flow. Flows take turns: packet 0 of every flow, then packet 1, and so on.
    pub packets_per_flow: u64,
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

/// Sends a [`Stream`], spreading its flows over transmit queues the way RSS would spread them
/// over a receiver's.
pub struct Sender {
    stream: Stream,
    templates: Vec<Template>,
    /// Each flow's queue.
    queue_of: Vec<usize>,
    /// The next packet to send: `(seq, flow)`.
    next: (u64, usize),
    /// Packets a full queue refused, to send before anything new.
    retry: Vec<(u64, usize)>,
    started: Option<Instant>,
}

impl Sender {
    /// A sender for `stream` in run `run`, over `queues` transmit queues.
    #[must_use]
    pub fn new(stream: Stream, run: u32, queues: usize) -> Sender {
        let flows = stream.flows;
        let mut templates = Vec::with_capacity(flows);
        let mut queue_of = Vec::with_capacity(flows);
        for n in 0..flows {
            let tuple = stream.space.flow(n as u64);
            templates.push(Template::new(&stream.frame, run, n as u64, &tuple));
            let queue = space::hash(&tuple) % queues.max(1) as u64;
            queue_of.push(usize::try_from(queue).unwrap_or(0));
        }
        Sender {
            stream,
            templates,
            queue_of,
            next: (0, 0),
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
        self.retry.is_empty()
            && (self.stream.flows == 0 || self.next.0 >= self.stream.packets_per_flow)
    }

    /// The next packets to send, at most `max`, retries first.
    fn take(&mut self, max: usize) -> Vec<(u64, usize)> {
        let mut out: Vec<_> = self.retry.drain(..self.retry.len().min(max)).collect();
        while out.len() < max && self.next.0 < self.stream.packets_per_flow && self.stream.flows > 0
        {
            out.push(self.next);
            self.next.1 += 1;
            if self.next.1 == self.stream.flows {
                self.next = (self.next.0 + 1, 0);
            }
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
        let mut by_queue: Vec<(MbufArray<'d>, Vec<(u64, usize)>)> = (0..queues.len())
            .map(|_| (MbufArray::new_empty(), Vec::new()))
            .collect();
        for (mbuf, &(seq, flow)) in mbufs.drain_all().zip(&packets) {
            let mut mbuf = mbuf;
            let template = &mut self.templates[flow];
            template.stamp(seq, clock.now_ns());
            let bytes = template.bytes();
            let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
            match mbuf.append(len) {
                Ok(room) => room.copy_from_slice(bytes),
                Err(_) => continue, // the template outgrew the mbuf: a misconfigured stream
            }
            let queue = self.queue_of[flow].min(queues.len().saturating_sub(1));
            let (batch, sent) = &mut by_queue[queue];
            if batch.try_push(mbuf).is_ok() {
                sent.push((seq, flow));
            }
        }
        let mut total = 0;
        for (queue, (batch, packets)) in queues.iter_mut().zip(by_queue) {
            let offered = batch.len();
            let refused = queue.transmit(batch).len();
            let accepted = offered - refused;
            for &(_, flow) in &packets[..accepted] {
                ledger.sent(flow);
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

/// Send `sender`'s stream on `tx` and count what comes back on `rx`, until everything sent has
/// come back or `patience` runs out.
pub fn run<'d>(
    sender: &mut Sender,
    tx: &mut [TxQueue<'d>],
    rx: &mut [RxQueue<'d>],
    pool: &Pool<'d>,
    ledger: &mut Ledger,
    clock: &Clock,
    patience: Patience,
) -> Ending {
    let started = clock::now();
    let mut last_heard = clock::now();
    loop {
        sender.send(tx, pool, ledger, clock);
        if receive(rx, ledger, clock) > 0 {
            last_heard = clock::now();
        }
        if sender.done() {
            if ledger.total_received() >= ledger.total_sent() {
                return Ending::AllBack;
            }
            if clock::elapsed(last_heard) > patience.quiet {
                return Ending::Quiet;
            }
        }
        if clock::elapsed(started) > patience.limit {
            return Ending::OutOfTime;
        }
    }
}
