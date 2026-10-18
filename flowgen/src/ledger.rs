// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Accounting for what a stream sent and what came back.
//!
//! Every packet a stream sends is counted against its flow; every frame received is read, and if
//! it carries one of the stream's signatures, counted against the flow it names. From the two
//! come loss, reordering, latency, and whether each flow came back the same way every time --
//! a flow whose returning addresses change partway through has had its NAT mapping changed under
//! it.

use std::net::Ipv4Addr;

use flowgen_report::{Evidence, MAX_EVIDENCE, Sample};

use crate::frame::{self, ChecksumState, Received};
use crate::space::Tuple;

/// How a flow came back: its inner addresses and ports, and the tunnel, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Return {
    /// The inner packet's addresses and ports.
    pub tuple: Tuple,
    /// The tunnel's VNI and VTEPs, if it came in one.
    pub tunnel: Option<(u32, Ipv4Addr, Ipv4Addr)>,
}

impl Return {
    fn of(received: &Received) -> Return {
        Return {
            tuple: received.tuple,
            tunnel: received.tunnel.map(|t| (t.vni, t.src, t.dst)),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Flow {
    sent: u64,
    received: u64,
    /// The sequence number after the highest received.
    next_seq: u64,
    /// How the flow first came back.
    returned_as: Option<Return>,
}

/// What became of a received frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// One of this stream's packets, counted against its flow.
    Ours(Received),
    /// Not one of this stream's packets.
    Foreign,
}

/// A stream's account of what it sent and what came back. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct Ledger {
    run: u32,
    flows: Vec<Flow>,
    sent: u64,
    received: u64,
    /// Received with a sequence number below one already received: reordered or duplicated.
    late: u64,
    /// Received but not ours: unreadable, unsigned, or from another run.
    foreign: u64,
    /// Ours, but naming a flow the stream does not have.
    unknown_flow: u64,
    bad_ip_checksum: u64,
    bad_udp_checksum: u64,
    /// Ours, with the payload past the signature changed.
    corrupt: u64,
    /// Ours, but coming back differently from how its flow first came back.
    unstable: u64,
    /// Latency counts by power of two: bucket `k` holds latencies in `[2^(k-1), 2^k)`.
    latency: [u64; 65],
    max_latency_ns: u64,
    /// The first frames that showed something wrong, for a report's evidence.
    evidence: Vec<Evidence>,
    evidence_dropped: u64,
}

impl Ledger {
    /// An empty account for `flows` flows, of run `run`.
    #[must_use]
    pub fn new(run: u32, flows: usize) -> Ledger {
        Ledger {
            run,
            flows: vec![Flow::default(); flows],
            sent: 0,
            received: 0,
            late: 0,
            foreign: 0,
            unknown_flow: 0,
            bad_ip_checksum: 0,
            bad_udp_checksum: 0,
            corrupt: 0,
            unstable: 0,
            latency: [0; 65],
            max_latency_ns: 0,
            evidence: Vec::new(),
            evidence_dropped: 0,
        }
    }

    /// Count a packet of flow `flow` as sent.
    pub fn sent(&mut self, flow: usize) {
        self.sent += 1;
        if let Some(f) = self.flows.get_mut(flow) {
            f.sent += 1;
        }
    }

    /// Read `frame`, received at `now_ns`, and count it.
    pub fn receive(&mut self, frame: &[u8], now_ns: u64) -> Outcome {
        let received = match frame::parse(frame) {
            Ok(received) => received,
            Err(e) => {
                self.foreign += 1;
                self.keep(frame, &format!("unreadable: {e}"));
                return Outcome::Foreign;
            }
        };
        let Some(signature) = received.signature.filter(|s| s.run == self.run) else {
            self.foreign += 1;
            self.keep(frame, "not from this run");
            return Outcome::Foreign;
        };
        let Some(flow) = usize::try_from(signature.flow)
            .ok()
            .and_then(|n| self.flows.get_mut(n))
        else {
            self.unknown_flow += 1;
            self.keep(
                frame,
                &format!(
                    "names flow {}, which the stream does not have",
                    signature.flow
                ),
            );
            return Outcome::Foreign;
        };

        self.received += 1;
        flow.received += 1;
        let mut problems = Vec::new();
        if signature.seq < flow.next_seq {
            self.late += 1;
        } else {
            flow.next_seq = signature.seq + 1;
        }
        let returned = Return::of(&received);
        match flow.returned_as {
            None => flow.returned_as = Some(returned),
            Some(first) if first != returned => {
                self.unstable += 1;
                problems.push(format!(
                    "flow {} came back as {returned:?}, first as {first:?}",
                    signature.flow
                ));
            }
            Some(_) => {}
        }
        if received.ip_checksum == ChecksumState::Invalid {
            self.bad_ip_checksum += 1;
            problems.push("bad IPv4 header checksum".to_string());
        }
        if received.udp_checksum == ChecksumState::Invalid {
            self.bad_udp_checksum += 1;
            problems.push("bad UDP checksum".to_string());
        }
        if !received.payload_intact {
            self.corrupt += 1;
            problems.push("payload changed".to_string());
        }
        if !problems.is_empty() {
            self.keep(frame, &problems.join("; "));
        }

        let latency = now_ns.saturating_sub(signature.tx_ns);
        self.latency[64 - latency.leading_zeros() as usize] += 1;
        self.max_latency_ns = self.max_latency_ns.max(latency);
        Outcome::Ours(received)
    }

    /// Keep `frame` as evidence of `what`, if there is room.
    fn keep(&mut self, frame: &[u8], what: &str) {
        if self.evidence.len() < MAX_EVIDENCE {
            self.evidence.push(Evidence::frame(what, frame));
        } else {
            self.evidence_dropped += 1;
        }
    }

    /// Packets sent.
    #[must_use]
    pub fn total_sent(&self) -> u64 {
        self.sent
    }

    /// Packets of ours received.
    #[must_use]
    pub fn total_received(&self) -> u64 {
        self.received
    }

    /// Packets sent and not (yet) received, flow by flow.
    #[must_use]
    pub fn lost(&self) -> u64 {
        self.flows
            .iter()
            .map(|f| f.sent.saturating_sub(f.received))
            .sum()
    }

    /// Flows of which at least one packet came back.
    #[must_use]
    pub fn flows_returned(&self) -> u64 {
        self.flows.iter().filter(|f| f.received > 0).count() as u64
    }

    /// How flow `flow` first came back, if it has.
    #[must_use]
    pub fn returned_as(&self, flow: usize) -> Option<Return> {
        self.flows.get(flow).and_then(|f| f.returned_as)
    }

    /// The frames that showed something wrong, as evidence; at most [`MAX_EVIDENCE`].
    #[must_use]
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// `sample`, with this account's counters under `generator.<stream>.`.
    #[must_use]
    pub fn sample(&self, stream: &str, sample: Sample) -> Sample {
        let path = |counter: &str| format!("generator.{stream}.{counter}");
        let mut sample = [
            ("flows", self.flows.len() as u64),
            ("flows_returned", self.flows_returned()),
            ("sent", self.sent),
            ("received", self.received),
            ("lost", self.lost()),
            ("late", self.late),
            ("foreign", self.foreign),
            ("unknown_flow", self.unknown_flow),
            ("bad_ip_checksum", self.bad_ip_checksum),
            ("bad_udp_checksum", self.bad_udp_checksum),
            ("corrupt", self.corrupt),
            ("unstable", self.unstable),
        ]
        .into_iter()
        .fold(sample, |sample, (counter, n)| {
            sample.counter(path(counter), n)
        });
        for (k, &n) in self.latency.iter().enumerate().filter(|(_, n)| **n > 0) {
            // Bucket `k` holds latencies below 2^k.
            let below = 1u128 << k;
            sample = sample.counter(path(&format!("latency_ns.lt_{below}")), n);
        }
        sample.gauge(path("latency_ns.max"), self.max_latency_ns)
    }
}
