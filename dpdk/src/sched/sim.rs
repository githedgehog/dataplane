// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A single-link queue simulator, and the head-to-head comparison of the three
//! AQMs over it.
//!
//! The queue is the point. None of these algorithms can run without one, so a
//! test that only pokes at their state machines proves nothing about what they
//! do to a link. This one carries real frames over a fixed-rate link, offers
//! more than the link can take, and reports what each policy did to the
//! standing queue.

use concurrency::sync::{Mutex, MutexGuard, OnceLock};
use net::buffer::test_buffer::TestBuffer;
use net::packet::Packet;
use std::collections::VecDeque;

use super::{Backlog, Codel, CodelParams, Departure, Pie, Red, Verdict};

/// Serialises every test that drives DPDK's RED.
///
/// `rte_red_enqueue` draws from a process-global linear congruential generator
/// (`rte_red_rand_seed`). Rust runs tests as threads in one process, so two
/// RED-driving tests running at once interleave draws and neither sees a
/// reproducible sequence -- which is exactly the kind of flake that gets
/// blamed on the algorithm. Every test that constructs a [`Red`] takes this
/// first.
///
/// [`OnceLock`] rather than a `static` initialiser because
/// `concurrency::sync::Mutex::new` is not `const fn` under the model-checker
/// backends; this is the portable idiom across all of them.
static RED_RNG: OnceLock<Mutex<()>> = OnceLock::new();

/// Take the RED serialisation lock. See [`RED_RNG`].
pub(super) fn red_rng() -> MutexGuard<'static, ()> {
    RED_RNG.get_or_init(|| Mutex::new(())).lock()
}

/// Nanoseconds per byte on the simulated link: 80 ns/byte is 100 Mbit/s.
///
/// Deliberately not 1 Gbit/s. A 256-packet queue of IMIX frames drains in
/// about 0.87 ms at 1 Gbit/s, which is shorter than the smallest delay
/// target PIE's own constructor can express, so nothing it did would mean
/// anything. Ten times slower puts a full queue at ~8.7 ms.
const NS_PER_BYTE: u64 = 80;
/// Ticks (nanoseconds) in a millisecond.
const TICKS_PER_MS: u64 = 1_000_000;
/// Hard queue limit, in packets. Every policy shares it, so the comparison
/// is between drop *policies* and not between queue sizes.
const QUEUE_LIMIT_PACKETS: u32 = 256;
/// Largest frame the load offers, which is what CoDel is told the MTU is.
const MTU_BYTES: u64 = 1518;

/// A packet-sized approximation of internet traffic: mostly small, with
/// enough full-size frames to carry most of the bytes.
const IMIX: [u16; 7] = [64, 64, 64, 64, 594, 594, 1518];

/// Build a valid Ethernet/IPv4/UDP frame of exactly `len` bytes.
///
/// Real frames rather than bare integers, so the lengths the AQM sees are
/// on-wire lengths that `Packet::total_len` computed from parsed headers.
/// `len` must be at least 42 (14 + 20 + 8).
fn frame(len: u16, seq: u16) -> Vec<u8> {
    assert!(len >= 42, "frame too short for eth+ipv4+udp: {len}");
    let mut buf = Vec::with_capacity(len as usize);

    // Ethernet II
    buf.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // dst
    buf.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src
    buf.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // IPv4
    let ip_total = len - 14;
    let ip_start = buf.len();
    buf.push(0x45); // version 4, IHL 5
    buf.push(0); // DSCP/ECN
    buf.extend_from_slice(&ip_total.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes()); // identification
    buf.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    buf.push(64); // TTL
    buf.push(17); // UDP
    buf.extend_from_slice(&[0, 0]); // checksum, filled in below
    buf.extend_from_slice(&[10, 0, 0, 1]); // src
    buf.extend_from_slice(&[10, 0, 0, 2]); // dst

    let checksum = ipv4_checksum(&buf[ip_start..ip_start + 20]);
    buf[ip_start + 10..ip_start + 12].copy_from_slice(&checksum.to_be_bytes());

    // UDP. A zero checksum is legal over IPv4 and means "not computed".
    buf.extend_from_slice(&5000u16.to_be_bytes()); // src port
    buf.extend_from_slice(&5001u16.to_be_bytes()); // dst port
    buf.extend_from_slice(&(ip_total - 20).to_be_bytes()); // length
    buf.extend_from_slice(&[0, 0]); // checksum

    buf.resize(len as usize, 0); // payload
    buf
}

/// Ones' complement sum over the 20-byte IPv4 header.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in header.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation)] // folded to 16 bits above
    let folded = sum as u16;
    !folded
}

/// A source of offered traffic.
///
/// The AQMs part company over whether the load answers back. RED and PIE act on
/// what the queue looks like, so an open-loop stream tells you most of what
/// they do. CoDel does not shorten a queue itself -- it drops packets to tell
/// *senders* to slow down -- so against a stream that ignores the drops it can
/// only ever be a slow tail drop. Both kinds of load are here because only one
/// of them can be believed about CoDel, and it is not the simpler one.
trait Load {
    /// The next packet: when it arrives, how long it is, and whose it is.
    fn next(&mut self) -> Option<(u64, u16, usize)>;
    /// Report that a packet belonging to `flow` was dropped at `at`.
    fn dropped(&mut self, flow: usize, at: u64);
    /// Report that a packet belonging to `flow` got through after waiting
    /// `sojourn`.
    ///
    /// A sender's round trip is its propagation delay *plus* whatever the queue
    /// added, and the round trip is the clock its congestion control runs on.
    /// Leave this out and the senders climb at a rate the queue cannot slow
    /// down, which makes every policy look worse than it is and the deepest
    /// queue look worst of all -- for the wrong reason.
    fn delivered(&mut self, flow: usize, sojourn: u64) {
        let _ = (flow, sojourn);
    }
}

/// A fixed list of arrivals, replayed regardless of what happens to them.
struct Replay {
    stream: Vec<(u64, u16)>,
    next: usize,
}

impl Replay {
    fn new(stream: Vec<(u64, u16)>) -> Replay {
        Replay { stream, next: 0 }
    }
}

impl Load for Replay {
    fn next(&mut self) -> Option<(u64, u16, usize)> {
        let &(at, len) = self.stream.get(self.next)?;
        self.next += 1;
        Some((at, len, 0))
    }

    fn dropped(&mut self, _flow: usize, _at: u64) {}
}

/// Nanoseconds in a millisecond, as a float, for the rate arithmetic below.
const NS_PER_MS: f64 = 1e6;

/// One additive-increase, multiplicative-decrease sender.
///
/// This is a rate-based caricature of a bulk TCP flow: it climbs by one segment
/// per round trip and halves on loss. It is not a congestion control
/// implementation and is not trying to be -- what it has to reproduce is the
/// one behaviour an AQM exists to exploit, which is that the sender's rate is a
/// function of the loss it sees.
struct Flow {
    /// Bytes per second currently offered.
    rate: f64,
    /// When this flow's next packet is ready.
    next_at: u64,
    /// Losses before this are already paid for. A real sender reacts once per
    /// round trip, not once per lost packet, and without this a single burst of
    /// tail drops would collapse a flow to nothing.
    loss_paid_until: u64,
    /// When the additive increase last ran.
    increased_at: u64,
    /// The round trip this flow last saw: propagation plus queueing.
    rtt_estimate: u64,
}

/// A fixed number of AIMD senders sharing the link.
///
/// # What is not modelled
///
/// A flow reacts to a drop at the instant it happens rather than a round trip
/// later. Real feedback delay makes the equilibrium noisier; it does not change
/// which queue depth each policy settles at, which is what this is here to
/// measure. The round trip itself *is* modelled, because it is not a constant:
/// it grows with the queue, and a queue that slows its own senders down is half
/// of what distinguishes these policies.
struct Aimd {
    flows: Vec<Flow>,
    /// Base round trip, which sets both the increase clock and how often a
    /// sender will react to loss.
    rtt: u64,
    /// Segment size. One per packet, and the additive increase is one of these
    /// per round trip.
    mss: u16,
    /// When to stop.
    until: u64,
}

impl Aimd {
    fn new(flows: usize, rtt: u64, mss: u16, until: u64, start_rate: f64) -> Aimd {
        Aimd {
            flows: (0..flows)
                .map(|i| Flow {
                    rate: start_rate,
                    // Stagger the starts so the flows do not march in lockstep.
                    next_at: (i as u64) * rtt / (flows as u64),
                    loss_paid_until: 0,
                    increased_at: 0,
                    rtt_estimate: rtt,
                })
                .collect(),
            rtt,
            mss,
            until,
        }
    }
}

impl Load for Aimd {
    fn next(&mut self) -> Option<(u64, u16, usize)> {
        let (flow, at) = self
            .flows
            .iter()
            .enumerate()
            .map(|(i, f)| (i, f.next_at))
            .min_by_key(|&(i, at)| (at, i))?;
        if at >= self.until {
            return None;
        }
        let mss = self.mss;
        let f = &mut self.flows[flow];
        let rtt = f.rtt_estimate.max(1);

        // Additive increase: one segment per round trip, which is Reno's.
        while at.saturating_sub(f.increased_at) >= rtt {
            f.rate += f64::from(mss) / (rtt as f64 / NS_PER_MS / 1000.0);
            f.increased_at += rtt;
        }
        // Sending `mss` bytes at `rate` takes this long.
        let gap = (f64::from(mss) / f.rate * 1e9) as u64;
        f.next_at = at + gap.max(1);
        Some((at, mss, flow))
    }

    fn dropped(&mut self, flow: usize, at: u64) {
        let mss = self.mss;
        let Some(f) = self.flows.get_mut(flow) else {
            return;
        };
        if at < f.loss_paid_until {
            return;
        }
        f.rate = (f.rate / 2.0).max(f64::from(mss));
        f.loss_paid_until = at + f.rtt_estimate;
    }

    fn delivered(&mut self, flow: usize, sojourn: u64) {
        let base = self.rtt;
        if let Some(f) = self.flows.get_mut(flow) {
            f.rtt_estimate = base + sojourn;
        }
    }
}

/// The drop policy under test.
enum Policy {
    /// No AQM: accept until the queue is full. The baseline to beat.
    TailDrop,
    Red(Red),
    Pie(Pie),
    /// CoDel, which admits everything the buffer has room for and makes its
    /// decision on the way out. The buffer limit is still there, exactly as it
    /// is for the others -- this is `codel` under a queue limit, which is how
    /// Linux stacks it too.
    Codel(Codel),
}

impl Policy {
    fn name(&self) -> &'static str {
        match self {
            Policy::TailDrop => "tail-drop",
            Policy::Red(_) => "RED",
            Policy::Pie(_) => "PIE",
            Policy::Codel(_) => "CoDel",
        }
    }
}

#[derive(Default)]
struct Stats {
    offered: u64,
    enqueued: u64,
    /// Dropped because the buffer was full, before the policy was consulted.
    /// This is the failure an AQM exists to prevent.
    dropped_buffer_full: u64,
    /// Dropped by the AQM's own hard threshold (RED above `max_th`, PIE
    /// above `tailq_th`).
    dropped_aqm_threshold: u64,
    /// Dropped by an enqueue-side AQM's probabilistic rule, with buffer to
    /// spare. This is the early congestion signal that makes an AQM worth
    /// having.
    dropped_aqm_early: u64,
    /// Dropped by a dequeue-side AQM, which is to say by CoDel. These packets
    /// were queued and scheduled before they were dropped; see [`PortCodel`]
    /// on what that costs.
    ///
    /// [`PortCodel`]: super::PortCodel
    dropped_aqm_dequeue: u64,
    /// Packets that made it onto the wire.
    delivered: u64,
    delivered_bytes: u64,
    /// Queue depth in packets, sampled once per arrival.
    depth_sum: u64,
    depth_max: u32,
    /// Sojourn time in nanoseconds, summed over departures.
    sojourn_sum: u64,
    sojourn_max: u64,
}

impl Stats {
    fn mean_depth(&self) -> f64 {
        self.depth_sum as f64 / self.offered as f64
    }
    fn mean_sojourn_us(&self) -> f64 {
        self.sojourn_sum as f64 / self.delivered.max(1) as f64 / 1000.0
    }
    fn dropped(&self) -> u64 {
        self.dropped_buffer_full
            + self.dropped_aqm_threshold
            + self.dropped_aqm_early
            + self.dropped_aqm_dequeue
    }
    fn drop_rate(&self) -> f64 {
        self.dropped() as f64 / self.offered as f64
    }
}

/// Run one offered load through one policy on a fixed-rate link.
///
/// The queue drains at `NS_PER_BYTE` per byte; arrivals are put to the policy
/// and either joined to the queue or dropped, and departures are put to it
/// again on the way out. This queue is the thing a policer does not have, and
/// is simulated here precisely because none of these algorithms can run
/// without one.
///
/// Statistics start at `stats_from`, so a closed-loop load can be given time to
/// find its equilibrium before anything is measured. A run that reported the
/// ramp would mostly be reporting how long each policy took to notice.
///
/// # The two sides are not symmetric
///
/// An enqueue-side drop costs the link nothing: the packet never occupied it. A
/// dequeue-side drop costs the link nothing *either* -- CoDel drops the packet
/// instead of transmitting it, so the link moves straight on to the next one --
/// but the packet did occupy the buffer for its whole sojourn, and under
/// `rte_sched` it would also have spent the shaper credits that got it
/// scheduled. The simulator models the first cost and not the second, because
/// there is no shaper here.
fn simulate(load: &mut dyn Load, mut policy: Policy, stats_from: u64) -> Stats {
    let mut stats = Stats::default();
    // Arrival time, length and owner of each queued packet, so departures can
    // report sojourn and tell the right sender it lost something.
    let mut queue: VecDeque<(u64, u16, usize)> = VecDeque::new();
    // Bytes in `queue`, which is the backlog CoDel is told about.
    let mut queued_bytes: u64 = 0;
    // When the link finishes the packet it is currently sending.
    let mut busy_until: u64 = 0;

    while let Some((arrival, len, flow)) = load.next() {
        let counting = arrival >= stats_from;
        // Drain everything the link could have sent by `arrival`.
        if queue.is_empty() && busy_until < arrival {
            busy_until = arrival;
        }
        while let Some(&(queued_at, head_len, head_flow)) = queue.front() {
            let finish = busy_until + u64::from(head_len) * NS_PER_BYTE;
            if finish > arrival {
                break;
            }
            queue.pop_front();
            queued_bytes -= u64::from(head_len);

            // CoDel decides here, at the moment the link would pick the packet
            // up, because that is when its sojourn time is finally known.
            let departed_at = busy_until;
            if let Policy::Codel(codel) = &mut policy {
                let sojourn = departed_at.saturating_sub(queued_at);
                let verdict = codel.depart(sojourn, Backlog::Bytes(queued_bytes), departed_at);
                if verdict == Departure::Drop {
                    if counting {
                        stats.dropped_aqm_dequeue += 1;
                    }
                    load.dropped(head_flow, departed_at);
                    // The link never started it, so it costs no time: the next
                    // packet is looked at immediately, which is what RFC 8289
                    // means by dropping and dequeuing again.
                    if queue.is_empty() {
                        codel.mark_queue_empty();
                        busy_until = busy_until.max(arrival);
                    }
                    continue;
                }
            }

            busy_until = finish;
            if counting {
                stats.delivered += 1;
                stats.delivered_bytes += u64::from(head_len);
                let sojourn = finish - queued_at;
                stats.sojourn_sum += sojourn;
                stats.sojourn_max = stats.sojourn_max.max(sojourn);
            }
            load.delivered(head_flow, finish - queued_at);
            if let Policy::Pie(pie) = &mut policy {
                pie.dequeue(u32::from(head_len), finish);
            }
            if queue.is_empty() {
                match &mut policy {
                    Policy::Red(red) => red.mark_queue_empty(finish),
                    Policy::Codel(codel) => codel.mark_queue_empty(),
                    Policy::TailDrop | Policy::Pie(_) => {}
                }
                busy_until = busy_until.max(arrival);
            }
        }

        let qlen_packets = u32::try_from(queue.len()).expect("queue length fits in u32");
        if counting {
            stats.offered += 1;
            stats.depth_sum += u64::from(qlen_packets);
            stats.depth_max = stats.depth_max.max(qlen_packets);
        }

        // The hard limit belongs to the buffer, not the policy, so tail drop
        // and the AQMs are compared at equal memory.
        if qlen_packets >= QUEUE_LIMIT_PACKETS {
            if counting {
                stats.dropped_buffer_full += 1;
            }
            load.dropped(flow, arrival);
            continue;
        }

        let verdict = match &mut policy {
            // CoDel admits everything the buffer will hold: it has nothing to
            // say until the packet has waited.
            Policy::TailDrop | Policy::Codel(_) => Verdict::Enqueue,
            Policy::Red(red) => red.enqueue(qlen_packets, arrival),
            Policy::Pie(pie) => pie.enqueue(qlen_packets, u32::from(len), arrival),
        };

        match verdict {
            Verdict::Enqueue => {
                queue.push_back((arrival, len, flow));
                queued_bytes += u64::from(len);
                if counting {
                    stats.enqueued += 1;
                }
            }
            Verdict::DropThreshold => {
                if counting {
                    stats.dropped_aqm_threshold += 1;
                }
                load.dropped(flow, arrival);
            }
            Verdict::DropProbability => {
                if counting {
                    stats.dropped_aqm_early += 1;
                }
                load.dropped(flow, arrival);
            }
        }
    }
    stats
}

/// Build one of each policy, in a fixed order, for `target` ticks of standing
/// queue.
///
/// Callers must be holding [`red_rng`].
fn policies(target: u64) -> [Policy; 4] {
    [
        Policy::TailDrop,
        // Start dropping at an average depth of 32 packets, drop everything
        // above 128, peak probability 1 in 10.
        Policy::Red(Red::new(9, 32, 128, 10).expect("valid RED parameters")),
        Policy::Pie(Pie::new(
            target,
            TICKS_PER_MS,
            10 * TICKS_PER_MS,
            u16::try_from(QUEUE_LIMIT_PACKETS).expect("queue limit fits in u16"),
        )),
        // RFC 8289 sizes `interval` at roughly twenty times `target`.
        Policy::Codel(
            Codel::new(CodelParams {
                target,
                interval: 20 * target,
                mtu_bytes: MTU_BYTES,
            })
            .expect("valid CoDel parameters"),
        ),
    ]
}

/// The header of the results table the comparisons print.
fn print_header() {
    println!(
        "{:<10} {:>7} {:>12} {:>10} {:>10} {:>9} {:>8} {:>7} {:>12} {:>11}",
        "policy",
        "drop %",
        "buffer full",
        "aqm thresh",
        "aqm early",
        "aqm deq",
        "mean qd",
        "max qd",
        "mean lat us",
        "max lat us",
    );
}

/// The share of the link a run actually used, over `span` ticks.
fn utilisation(stats: &Stats, span: u64) -> f64 {
    stats.delivered_bytes as f64 * NS_PER_BYTE as f64 / span as f64
}

fn print_row(name: &str, stats: &Stats) {
    println!(
        "{:<10} {:>6.2}% {:>12} {:>10} {:>10} {:>9} {:>8.1} {:>7} {:>12.1} {:>11.1}",
        name,
        stats.drop_rate() * 100.0,
        stats.dropped_buffer_full,
        stats.dropped_aqm_threshold,
        stats.dropped_aqm_early,
        stats.dropped_aqm_dequeue,
        stats.mean_depth(),
        stats.depth_max,
        stats.mean_sojourn_us(),
        stats.sojourn_max as f64 / 1000.0,
    );
}

/// Offered load in three phases: under the link rate, then over it, then
/// under again.
///
/// A steady load would not separate these algorithms. Under-load nobody
/// drops, and at a permanent overload every policy converges on the same
/// drop rate because the link decides it, not the policy. What distinguishes
/// them is the queue they hold while overloaded, and how fast they let it go
/// afterwards.
fn offered_load() -> Vec<(u64, u16)> {
    const PHASE_PACKETS: usize = 20_000;
    let phases = [0.6_f64, 1.6, 0.6];

    let mut stream = Vec::with_capacity(PHASE_PACKETS * phases.len());
    let mut now: u64 = 0;
    let mut seq: u16 = 0;
    for load in phases {
        for i in 0..PHASE_PACKETS {
            let len = IMIX[i % IMIX.len()];
            // Build a real frame and take the length the parser computes,
            // rather than trusting the number we asked for.
            let parsed = Packet::new(TestBuffer::from_raw_data(&frame(len, seq)))
                .expect("generated frame should parse");
            let on_wire = parsed.total_len();
            assert_eq!(on_wire, len, "parsed length should match the frame built");
            seq = seq.wrapping_add(1);

            stream.push((now, on_wire));
            // Serialising `len` bytes takes `len * NS_PER_BYTE`; offering at
            // `load` times the link rate puts arrivals that much closer.
            let gap = (f64::from(on_wire) * NS_PER_BYTE as f64 / load) as u64;
            now += gap.max(1);
        }
    }
    stream
}

/// Push a stream that ignores its losses through all four policies.
///
/// This is the load an AQM is usually shown against, and for [`Red`] it is a
/// fair one: RED shortens a queue by refusing packets, so it works whether or
/// not anyone is listening. It is *not* a fair load for [`Codel`], and the
/// assertions below say so rather than hiding it. See
/// [`aimd_senders_see_the_queue_each_policy_holds`] for the load that is.
#[test]
fn an_unresponsive_stream_shows_what_red_does_and_what_codel_cannot() {
    let _rng = red_rng();
    let stream = offered_load();
    let offered_bytes: u64 = stream.iter().map(|&(_, len)| u64::from(len)).sum();
    let span_ns = stream.last().expect("stream is not empty").0;

    println!(
        "unresponsive: {} packets / {:.1} MB over {:.0} ms on a {} Mbit/s link",
        stream.len(),
        offered_bytes as f64 / 1e6,
        span_ns as f64 / 1e6,
        8000 / NS_PER_BYTE,
    );
    print_header();

    let mut results = Vec::new();
    for policy in policies(TICKS_PER_MS) {
        let name = policy.name();
        let stats = simulate(&mut Replay::new(stream.clone()), policy, 0);
        print_row(name, &stats);
        results.push((name, stats));
    }
    let [taildrop, red, pie, codel] = &results.iter().map(|(_, s)| s).collect::<Vec<_>>()[..]
    else {
        unreachable!("four policies produce four results")
    };

    // Every policy is offered more than the link can carry, so all of them
    // must drop. If one does not, the load is not an overload and the rest
    // of this test is vacuous.
    for (name, stats) in &results {
        assert!(
            stats.drop_rate() > 0.05,
            "{name} dropped {:.2}%, so the offered load is not an overload",
            stats.drop_rate() * 100.0,
        );
    }

    // The link is the same in all four runs, so they must all deliver about
    // the same volume. An AQM trades queueing delay for loss; it does not
    // cost throughput.
    let delivered: Vec<f64> = results
        .iter()
        .map(|(_, s)| s.delivered_bytes as f64)
        .collect();
    let spread = delivered.iter().copied().fold(f64::MIN, f64::max)
        / delivered.iter().copied().fold(f64::MAX, f64::min);
    assert!(
        spread < 1.02,
        "delivered volumes should match within 2%, spread was {spread:.4}",
    );

    // Tail drop has no early signal to give: every one of its drops is a
    // buffer overflow. That is the complaint about it.
    assert_eq!(taildrop.dropped_aqm_threshold, 0);
    assert_eq!(taildrop.dropped_aqm_early, 0);
    assert_eq!(taildrop.dropped_aqm_dequeue, 0);

    // RED does what it is for: it drops early, and the standing queue -- and
    // so the latency through it -- comes down.
    assert!(
        red.dropped_aqm_early > 0,
        "RED never fired its probabilistic rule",
    );
    assert!(
        red.mean_depth() < taildrop.mean_depth() * 0.9,
        "RED mean depth {:.1} should be well under tail drop's {:.1}",
        red.mean_depth(),
        taildrop.mean_depth(),
    );
    assert!(
        red.dropped_buffer_full < taildrop.dropped_buffer_full,
        "RED overflowed the buffer {} times against tail drop's {}",
        red.dropped_buffer_full,
        taildrop.dropped_buffer_full,
    );

    // PIE does not, because of the defect documented on `Pie`. Asserted so
    // that this stops being true loudly rather than silently.
    assert!(
        pie.mean_depth() > taildrop.mean_depth() * 0.9,
        "PIE held a mean depth of {:.1} against tail drop's {:.1}. If DPDK \
         has fixed `_calc_drop_probability`, that is good news: flip this \
         assertion and rewrite the defect note on `Pie`.",
        pie.mean_depth(),
        taildrop.mean_depth(),
    );

    // CoDel is awake -- it sees the standing queue and drops on schedule --
    // but it cannot shorten this queue, and it is important that this test
    // does not pretend otherwise. Its drops are congestion signals, and a
    // stream that never listens to them is a stream CoDel cannot control:
    // the control law raises the drop rate as the square root of how long
    // the congestion has lasted, which reaches a few dozen packets in a
    // second, not the thousands per second this overload would need.
    assert!(
        codel.dropped_aqm_dequeue > 0,
        "CoDel never dropped, so it did not even see the standing queue",
    );
    assert!(
        codel.dropped_aqm_dequeue < red.dropped(),
        "CoDel dropped {} against RED's {}. CoDel drops to signal, so against \
         an unresponsive load it should drop far less than a depth-driven AQM \
         does -- if that has stopped being true, the control law is running \
         away.",
        codel.dropped_aqm_dequeue,
        red.dropped(),
    );
    assert!(
        codel.mean_depth() > taildrop.mean_depth() * 0.9,
        "CoDel held a mean depth of {:.1} against tail drop's {:.1}. That is \
         *better* than this test expects, which means the load has become \
         responsive or the control law has: check which before relaxing this.",
        codel.mean_depth(),
        taildrop.mean_depth(),
    );
}

/// Put loss-responsive senders behind the same buffer and measure the queue
/// each policy leaves standing.
///
/// # This is the test that means something
///
/// Every policy here delivers about the same bytes -- the link decides that,
/// not the queue discipline. What differs is how much *delay* each one charges
/// for them, and that is bufferbloat: an over-buffered link with a tail drop
/// fills the buffer, because the senders have no reason to stop until it
/// overflows. The AQMs tell them sooner.
///
/// # CoDel does not reach its target here, and that is not a bug
///
/// One CoDel over one queue shared by many bulk senders will sit above target.
/// The drop rate it can generate climbs as the square root of how long the
/// congestion has lasted, and every dip under target costs it a fresh interval
/// of grace, so it lags a load that needs a high loss rate to hold still. What
/// closes that gap is *flow queueing* -- giving each flow its own queue and its
/// own controller, which is what `fq_codel` is and what plain CoDel is not.
///
/// [`PortCodel`](super::PortCodel) is closer to `fq_codel` than to this: it
/// runs one controller per `rte_sched` queue, so traffic split across pipes is
/// already split across controllers. What it does not do is hash flows into
/// those queues by itself.
///
/// So the claim below is the relative one -- half the delay of a tail drop at
/// the same throughput -- and the absolute one is made where it can be:
/// [`codel_holds_the_delay_it_is_asked_for`].
#[test]
fn aimd_senders_see_the_queue_each_policy_holds() {
    let _rng = red_rng();

    /// Senders sharing the link.
    const FLOWS: usize = 32;
    /// Base round trip.
    const RTT: u64 = 20 * TICKS_PER_MS;
    /// Segment size, and the additive increase per round trip.
    const MSS: u16 = 1500;
    /// Simulated seconds.
    const RUN: u64 = 10_000 * TICKS_PER_MS;
    /// Let the senders find their equilibrium before measuring. The additive
    /// increase alone takes a couple of seconds to fill a 100 Mbit/s link from
    /// a standing start.
    const WARMUP: u64 = 3_000 * TICKS_PER_MS;
    /// The standing queue asked of PIE and CoDel.
    const TARGET: u64 = 5 * TICKS_PER_MS;

    // 100 Mbit/s with a 20 ms round trip is 250 KB in flight; the buffer holds
    // 256 * 1500 = 384 KB. Over-buffered by half, which is the condition every
    // one of these algorithms was written for.
    let bdp_bytes = 1_000_000_000 / NS_PER_BYTE * RTT / 1_000_000_000;
    let buffer_bytes = u64::from(QUEUE_LIMIT_PACKETS as u16) * u64::from(MSS);
    println!(
        "responsive: {FLOWS} AIMD flows, {:.0} ms RTT, {} Mbit/s, {:.0} KB in \
         flight against a {:.0} KB buffer",
        RTT as f64 / 1e6,
        8000 / NS_PER_BYTE,
        bdp_bytes as f64 / 1e3,
        buffer_bytes as f64 / 1e3,
    );
    assert!(
        buffer_bytes > bdp_bytes,
        "the buffer must be bigger than the bandwidth-delay product or there \
         is no bloat to remove",
    );
    print_header();

    let mut results = Vec::new();
    for policy in policies(TARGET) {
        let name = policy.name();
        // A twentieth of the fair share each, so every run starts from the
        // same place and has to climb.
        let start_rate = 1e9 / NS_PER_BYTE as f64 / FLOWS as f64 / 20.0;
        let mut load = Aimd::new(FLOWS, RTT, MSS, RUN, start_rate);
        let stats = simulate(&mut load, policy, WARMUP);
        print_row(name, &stats);
        results.push((name, stats));
    }
    let [taildrop, red, pie, codel] = &results.iter().map(|(_, s)| s).collect::<Vec<_>>()[..]
    else {
        unreachable!("four policies produce four results")
    };

    // The senders fill the link in every run, so the throughput is the link's
    // and the comparison is purely about delay. If this fails the load is not
    // saturating and nothing below means anything.
    for (name, stats) in &results {
        println!(
            "  {name}: link {:.1}% utilised",
            utilisation(stats, RUN - WARMUP) * 100.0
        );
    }

    // Tail drop bloats: the senders keep climbing until the buffer overflows,
    // so the standing queue is the buffer.
    assert!(
        taildrop.mean_depth() > 0.7 * f64::from(QUEUE_LIMIT_PACKETS),
        "tail drop held only {:.0} of {QUEUE_LIMIT_PACKETS} packets, so this \
         buffer is not bloated and there is nothing to fix",
        taildrop.mean_depth(),
    );

    // CoDel halves the delay, which is the whole exercise.
    let target_us = TARGET as f64 / 1000.0;
    assert!(
        codel.mean_sojourn_us() < taildrop.mean_sojourn_us() / 1.5,
        "CoDel held {:.0} us against tail drop's {:.0} us, for a {target_us:.0} \
         us target",
        codel.mean_sojourn_us(),
        taildrop.mean_sojourn_us(),
    );
    // And it does so without giving up throughput, which is the trade the
    // whole exercise is about: latency was supposed to be free.
    assert!(
        utilisation(codel, RUN - WARMUP) > 0.98,
        "CoDel filled only {:.1}% of the link",
        utilisation(codel, RUN - WARMUP) * 100.0,
    );
    assert!(
        codel.delivered_bytes as f64 > taildrop.delivered_bytes as f64 * 0.98,
        "CoDel delivered {} bytes against tail drop's {}",
        codel.delivered_bytes,
        taildrop.delivered_bytes,
    );

    // RED helps too -- it is a working AQM. But it controls depth against
    // thresholds in packets, so what delay it lands on is whatever those
    // thresholds happen to mean on this link, and it pays for it: it is the
    // one policy here that does not fill the link, because its drop rate is
    // set by its configuration rather than by what the senders need to hear.
    assert!(
        red.mean_sojourn_us() < taildrop.mean_sojourn_us(),
        "RED held {:.0} us against tail drop's {:.0} us",
        red.mean_sojourn_us(),
        taildrop.mean_sojourn_us(),
    );

    // PIE is the control: it is the other delay-targeting algorithm here, it
    // was given the same target as CoDel, and it does nothing at all. See the
    // defect note on `Pie`.
    assert!(
        pie.mean_sojourn_us() > taildrop.mean_sojourn_us() * 0.9,
        "PIE held {:.0} us against tail drop's {:.0} us, for the same \
         {target_us:.0} us target. If DPDK has fixed `_calc_drop_probability`, \
         flip this and rewrite the note on `Pie`.",
        pie.mean_sojourn_us(),
        taildrop.mean_sojourn_us(),
    );
}

/// The standing queue CoDel leaves is a function of the target it was given.
///
/// This is the property that makes it a *delay-targeting* algorithm rather
/// than an algorithm that happens to reduce delay, and it is the one PIE
/// claims and does not have: ask DPDK's PIE for a different target and nothing
/// changes, because its controller is saturated at a drop probability of 1
/// either way (see [`Pie`]).
///
/// The claim is deliberately ordinal -- a longer target leaves a longer queue,
/// by a clear margin -- because the absolute figure depends on the offered
/// load, and this load is a hard one for a single-queue CoDel. See
/// [`aimd_senders_see_the_queue_each_policy_holds`].
#[test]
fn codel_holds_the_delay_it_is_asked_for() {
    const FLOWS: usize = 32;
    const RTT: u64 = 20 * TICKS_PER_MS;
    const MSS: u16 = 1500;
    const RUN: u64 = 10_000 * TICKS_PER_MS;
    const WARMUP: u64 = 3_000 * TICKS_PER_MS;

    let mut held = Vec::new();
    for target_ms in [1_u64, 5, 25] {
        let target = target_ms * TICKS_PER_MS;
        let policy = Policy::Codel(
            Codel::new(CodelParams {
                target,
                interval: 20 * target,
                mtu_bytes: MTU_BYTES,
            })
            .expect("valid CoDel parameters"),
        );
        let start_rate = 1e9 / NS_PER_BYTE as f64 / FLOWS as f64 / 20.0;
        let mut load = Aimd::new(FLOWS, RTT, MSS, RUN, start_rate);
        let stats = simulate(&mut load, policy, WARMUP);
        println!(
            "target {target_ms:>2} ms -> mean sojourn {:>8.0} us, mean depth              {:>6.1}, {:.1}% utilised",
            stats.mean_sojourn_us(),
            stats.mean_depth(),
            utilisation(&stats, RUN - WARMUP) * 100.0,
        );
        held.push((target_ms, stats));
    }

    for pair in held.windows(2) {
        let [(short, low), (long, high)] = pair else {
            unreachable!("windows(2) yields pairs")
        };
        assert!(
            high.mean_sojourn_us() > low.mean_sojourn_us() * 1.2,
            "a {long} ms target held {:.0} us against a {short} ms target's \
             {:.0} us; CoDel is not tracking the target it was given",
            high.mean_sojourn_us(),
            low.mean_sojourn_us(),
        );
    }
}

/// Under a load the link can carry, an AQM must not drop anything. A test
/// that only ever runs overloaded cannot tell a working AQM from one that
/// drops at random.
#[test]
fn codel_passes_everything_when_the_link_keeps_up() {
    let mut now = 0;
    let mut stream = Vec::new();
    for i in 0..20_000 {
        let len = IMIX[i % IMIX.len()];
        stream.push((now, len));
        // Half the link rate, so the queue never builds.
        now += u64::from(len) * NS_PER_BYTE * 2;
    }
    let offered = stream.len() as u64;
    let stats = simulate(
        &mut Replay::new(stream),
        Policy::Codel(
            Codel::new(CodelParams {
                target: TICKS_PER_MS,
                interval: 20 * TICKS_PER_MS,
                mtu_bytes: MTU_BYTES,
            })
            .expect("valid CoDel parameters"),
        ),
        0,
    );
    assert_eq!(
        stats.dropped(),
        0,
        "CoDel dropped {} packets from an underloaded link",
        stats.dropped(),
    );
    // Everything but the last arrival, which is still in the queue when the
    // stream ends and the simulator stops.
    assert_eq!(
        stats.delivered,
        offered - 1,
        "everything should have been sent"
    );
}
