// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Admission: slice 1 of the match-action/DAG rework, hosted as one stage of the legacy pipeline.
//!
//! The overlay's first stages, from the arrived meter to the accepted meter, run as a typed DAG
//! (`dag`, `notes/match-action-dag/DAG.md`):
//!
//! ```text
//! live overlay packets ── import ──┬─ SrcVpc ──▶ arrived meter ─┐
//!                                  └─ no SrcVpc ────────────────┴▶ join ▶ [pre] ─┐
//!   ┌────────────────────────────────────────────────────────────────────────────┘
//!   ├─ no DstVpc ──▶ flow filter ──┐
//!   └─ DstVpc (set by pre) ────────┴▶ join ▶ [mid] ─┬─ SrcVpc ∧ DstVpc ──▶ ACL ──▶ accepted meter ──▶ export
//!                                                    └─ otherwise ──▶ drop (Unroutable)
//! ```
//!
//! `[pre]` and `[mid]` are legacy stages hosted as nodes (ICMP errors and the flow lookup; the
//! SYN cookie checker). Every drop is an outcome, and the outcomes partition the input
//! (checked in debug builds). The legacy pipeline with the same stages is the oracle: see the
//! differential test in `fuzz.rs`.
//!
//! **Generations** (`dag::generation`, slice 1 step 2). The typed nodes do not load their tables:
//! a [`Source`] hands the composite one [`AdmissionTables`] per live generation, each packet runs
//! under the one its stamp names, and a node with packets of both runs once per generation. The
//! production source reads today's per-NF readers as a single generation; tests publish through
//! [`dag::generation::Generations`]. The hosted legacy stages still read their own state.

use acl_filter::{AclFilter, AclFilterContext, AclFilterContextReader};
use concurrency::sync::Arc;
use dag::generation::{Reader, Seen, Snapshot, Tables};
use dag::{Drops, Kind, MAX_BURST, Presence, kind};
use flow_filter::{FlowFilter, FlowFilterContext, FlowFilterContextReader};
use net::buffer::PacketBufferMut;
use net::packet::{Bank, DoneReason, Packet};
use pipeline::{NetworkFunction, PipelineData, SchedRun};
use rate_limit::{IngressRules, PeeringRules, Policed, RateLimitReader, RateLimiter, RateLimits};

/// How the production pipeline runs the admission stages: `DATAPLANE_ADMISSION_FRAME` =
/// `legacy` (default: one stage each), `chained` (the same stages chained into one: the control
/// for code layout), or `admission` (the typed DAG). For the slice-1 A/B; it goes once one frame
/// has won.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Legacy,
    Chained,
    Admission,
}

impl Frame {
    pub(crate) fn from_env() -> Frame {
        let frame = match std::env::var("DATAPLANE_ADMISSION_FRAME").as_deref() {
            Ok("chained") => Frame::Chained,
            Ok("admission") => Frame::Admission,
            _ => Frame::Legacy,
        };
        tracing::info!("admission frame: {frame:?}");
        frame
    }
}

/// The kinds the hosted legacy stages may change: the ICMP error handler and the SYN cookie
/// checker set the destination VPC. Debug builds check that they change no other.
const LEGACY_WRITES: Presence = <kind::DstVpc as Kind>::BIT;

/// What the admission slice's typed nodes read, for one generation. A meter's rules are absent
/// when it has none: it passes everything.
#[derive(Debug)]
pub(crate) struct AdmissionTables {
    pub(crate) arrived: Option<Arc<RateLimits<IngressRules>>>,
    pub(crate) flow_filter: Arc<FlowFilterContext>,
    pub(crate) acl: Arc<AclFilterContext>,
    pub(crate) accepted: Option<Arc<RateLimits<PeeringRules>>>,
}

/// Where the composite gets its tables: once per burst, then told what the burst showed.
pub(crate) trait Source {
    /// The live generations' tables, for one burst.
    fn tables(&mut self) -> Tables<'_, AdmissionTables>;
    /// After a burst.
    fn settle(&mut self, seen: Seen);
    /// After an empty poll: the pipeline ran with no packets (a scheduled run, which the worker
    /// makes only when its queues were empty).
    fn idle(&mut self);
    /// Whether the composite should keep running on empty polls: it owes a generation an
    /// acknowledgement.
    fn awaiting(&self) -> bool;
}

/// Today's tables, read from each NF's own reader, as a single generation. What production runs
/// until a publisher owns the slice's tables (slice 1, step 3).
pub(crate) struct Current {
    arrived: Option<RateLimitReader<IngressRules>>,
    flow_filter: FlowFilterContextReader,
    acl: AclFilterContextReader,
    accepted: Option<RateLimitReader<PeeringRules>>,
    snapshot: Option<Snapshot<AdmissionTables>>,
}

impl Source for Current {
    fn tables(&mut self) -> Tables<'_, AdmissionTables> {
        let tables = AdmissionTables {
            arrived: self.arrived.as_ref().map(RateLimitReader::load),
            flow_filter: self.flow_filter.load(),
            acl: self.acl.load(),
            accepted: self.accepted.as_ref().map(RateLimitReader::load),
        };
        Tables::only(self.snapshot.insert(Snapshot::new(0, Bank::A, tables)))
    }

    fn settle(&mut self, _: Seen) {}

    fn idle(&mut self) {}

    fn awaiting(&self) -> bool {
        false
    }
}

impl Source for Reader<'_, AdmissionTables> {
    fn tables(&mut self) -> Tables<'_, AdmissionTables> {
        self.live().tables()
    }

    fn settle(&mut self, seen: Seen) {
        Reader::settle(self, seen);
    }

    fn idle(&mut self) {
        let _ = self.live();
        Reader::idle(self);
    }

    fn awaiting(&self) -> bool {
        Reader::awaiting(self)
    }
}

/// Every worker's scheduled-run handle, for the publisher to wake idle workers after a step:
/// a worker that receives nothing never runs its pipeline, so it would never observe a new
/// generation, nor acknowledge one.
#[derive(Clone, Debug, Default)]
pub(crate) struct Wakers(Arc<concurrency::sync::Mutex<Vec<SchedRun>>>);

impl Wakers {
    fn register(&self, sched: SchedRun) {
        self.0.lock().push(sched);
    }

    /// Run every worker's pipeline at its next empty poll.
    pub(crate) fn wake(&self) {
        for sched in self.0.lock().iter() {
            sched.asap();
        }
    }
}

impl From<mgmt::AdmissionUpdate> for AdmissionTables {
    fn from(update: mgmt::AdmissionUpdate) -> Self {
        AdmissionTables {
            arrived: Some(update.ingress),
            flow_filter: update.flow_filter,
            acl: update.acl,
            accepted: Some(update.peering),
        }
    }
}

/// What a worker's pipeline needs from the admission publisher.
#[derive(Clone, Copy)]
pub(crate) struct Publication<'p> {
    pub(crate) readers: dag::generation::ReaderFactory<'p, AdmissionTables>,
    pub(crate) wakers: &'p Wakers,
}

/// The admission publisher's loop, on the thread that owns the workers' scope (it outlives
/// their readers): take each applied generation's tables from management (the latest, if
/// several arrived), and step them through begin, flip and retire, waking the workers at each
/// step. Returns when `cancelled`.
pub(crate) fn publish(
    generations: &dag::generation::Generations<AdmissionTables>,
    updates: &std::sync::mpsc::Receiver<mgmt::AdmissionUpdate>,
    wakers: &Wakers,
    cancelled: impl Fn() -> bool,
) {
    use dag::generation::Stepped;
    use std::time::Duration;
    let mut busy = false;
    let mut waiting_since: Option<std::time::Instant> = None;
    let mut warned = false;
    while !cancelled() {
        // Short waits while a generation is in flight, longer ones while idle.
        let wait = if busy {
            Duration::from_micros(200)
        } else {
            Duration::from_millis(20)
        };
        // Timed out, or management is gone: either way, keep stepping what is in flight.
        let mut latest = updates.recv_timeout(wait).ok();
        while let Ok(update) = updates.try_recv() {
            latest = Some(update);
        }
        if let Some(update) = latest {
            tracing::debug!("admission: generation {} offered", update.genid);
            generations.offer(update.into());
        }
        match generations.step() {
            Stepped::Idle => {
                busy = false;
                waiting_since = None;
                warned = false;
            }
            Stepped::Waiting(why) => {
                busy = true;
                wakers.wake();
                let since = *waiting_since.get_or_insert_with(std::time::Instant::now);
                // A stuck worker is the watchdog's fault; say what is waiting, once.
                if !warned && since.elapsed() > Duration::from_secs(1) {
                    tracing::warn!(
                        "admission: generation {} waiting on workers: {why:?}",
                        generations.newest()
                    );
                    warned = true;
                }
            }
            step @ (Stepped::Began(_) | Stepped::Flipped(_) | Stepped::Retired(_)) => {
                if let Stepped::Retired(generation) = step {
                    tracing::info!("admission: generation {generation} is the only one live");
                } else {
                    tracing::debug!("admission: {step:?}");
                }
                busy = true;
                waiting_since = None;
                warned = false;
                wakers.wake();
            }
        }
    }
}

/// The admission slice as one stage: arrived meter → (pre) → flow filter → (mid) → ACL →
/// accepted meter.
pub(crate) struct Admission<Pre, Mid, Src = Current> {
    arrived: Option<RateLimiter<IngressRules>>,
    pre: Pre,
    flow_filter: FlowFilter,
    mid: Mid,
    acl: AclFilter,
    accepted: Option<RateLimiter<PeeringRules>>,
    source: Src,
    /// This worker's scheduled runs: requested while the source awaits an acknowledgement.
    sched: Option<SchedRun>,
    /// Where to register `sched` for the publisher to wake, if a publisher owns the tables.
    wakers: Option<Wakers>,
}

impl<Pre, Mid> Admission<Pre, Mid> {
    /// The slice, reading today's tables through its NFs' own readers.
    pub(crate) fn new(
        arrived: Option<RateLimiter<IngressRules>>,
        pre: Pre,
        flow_filter: FlowFilter,
        mid: Mid,
        acl: AclFilter,
        accepted: Option<RateLimiter<PeeringRules>>,
    ) -> Self {
        let source = Current {
            arrived: arrived.as_ref().map(|m| m.reader().clone()),
            flow_filter: flow_filter.tables_reader().clone(),
            acl: acl.tables_reader().clone(),
            accepted: accepted.as_ref().map(|m| m.reader().clone()),
            snapshot: None,
        };
        Admission {
            arrived,
            pre,
            flow_filter,
            mid,
            acl,
            accepted,
            source,
            sched: None,
            wakers: None,
        }
    }
}

impl<Pre, Mid, Src> Admission<Pre, Mid, Src> {
    /// The same slice, with its tables from `source` instead, and `wakers` to register its
    /// scheduled runs with, if any.
    pub(crate) fn with_source<New: Source>(
        self,
        source: New,
        wakers: Option<Wakers>,
    ) -> Admission<Pre, Mid, New> {
        let Admission {
            arrived,
            pre,
            flow_filter,
            mid,
            acl,
            accepted,
            source: _,
            sched,
            wakers: _,
        } = self;
        Admission {
            arrived,
            pre,
            flow_filter,
            mid,
            acl,
            accepted,
            source,
            sched,
            wakers,
        }
    }
}

/// A meter run under one generation's rules: none means none, and it passes everything.
fn police<'b, Buf, S, C>(
    meter: &mut RateLimiter<C>,
    burst: &mut dag::Burst<'b, Buf>,
    sel: dag::Sel<'b, S>,
    limits: Option<&'b Arc<RateLimits<C>>>,
    run: impl FnOnce(
        &mut RateLimiter<C>,
        &mut dag::Burst<'b, Buf>,
        dag::Sel<'b, S>,
        &'b Arc<RateLimits<C>>,
    ) -> Policed<'b, S>,
) -> Policed<'b, S>
where
    Buf: PacketBufferMut,
    S: dag::State,
{
    match limits {
        Some(limits) => run(meter, burst, sel, limits),
        None => Policed {
            passed: sel,
            dropped: Drops::none(),
        },
    }
}

impl<Pre, Mid, Src: Source> Admission<Pre, Mid, Src> {
    /// One burst of at most [`MAX_BURST`] packets.
    fn chunk<Buf>(&mut self, packets: &mut Vec<Packet<Buf>>)
    where
        Buf: PacketBufferMut,
        Pre: NetworkFunction<Buf>,
        Mid: NetworkFunction<Buf>,
    {
        let Admission {
            arrived,
            pre,
            flow_filter,
            mid,
            acl,
            accepted,
            source,
            ..
        } = self;
        let tables = source.tables();
        let seen = dag::scope_with(packets, tables, |mut burst, all, tables| {
            let tables = *tables;
            // Packets done or not from a VPC are not ours: they are in no edge, and untouched.
            let (live, _) = burst.scan_where(all, |p| !p.is_done() && p.meta().is_overlay());
            let live_bits = live.bits();
            // Each packet runs under the generation its stamp names; a stale stamp is dropped.
            let (live, mut dropped, seen) = burst.resolve(live, tables);

            // The arrived meter, on packets whose source VPC is known.
            let (known, unknown) = burst.split::<kind::SrcVpc, _>(live);
            let arrived_out = match arrived {
                Some(meter) => {
                    let policed = burst.per_generation(
                        known,
                        tables,
                        |t| &t.arrived,
                        |burst, sel, limits| {
                            police(meter, burst, sel, limits.as_ref(), |m, b, s, l| {
                                m.process_sel(b, s, l)
                            })
                        },
                    );
                    dropped = dropped.join(policed.dropped);
                    policed.passed
                }
                None => known,
            };
            let arrived_out = arrived_out.join(unknown);

            // Legacy: ICMP errors, flow lookup. Hosted at a join, so it sees every live packet.
            let (looked_up, lost) = burst.legacy(arrived_out, LEGACY_WRITES, |packets| {
                pre.process_burst(packets);
            });
            dropped = dropped.join(lost);

            // The flow filter, on packets no earlier stage gave a destination.
            let (placed, unplaced) = burst.split::<kind::DstVpc, _>(looked_up);
            let routed = burst.per_generation(
                unplaced,
                tables,
                |t| &*t.flow_filter,
                |burst, sel, tables| flow_filter.process_sel(burst, sel, tables),
            );
            dropped = dropped.join(routed.dropped);
            let placed = routed.routed.join(placed);

            // Legacy: the SYN cookie checker.
            let (checked, lost) =
                burst.legacy(placed, LEGACY_WRITES, |packets| mid.process_burst(packets));
            dropped = dropped.join(lost);

            // The ACL, on packets whose VPCs are both known; the legacy ACL drops the others first.
            let (with_src, no_src) = burst.split::<kind::SrcVpc, _>(checked);
            let (acl_in, no_dst) = burst.split::<kind::DstVpc, _>(with_src);
            let mut unroutable = Drops::none();
            for i in no_src {
                burst.drop(&mut unroutable, i, DoneReason::Unroutable);
            }
            for i in no_dst {
                burst.drop(&mut unroutable, i, DoneReason::Unroutable);
            }
            dropped = dropped.join(unroutable);
            let filtered = burst.per_generation(
                acl_in,
                tables,
                |t| &*t.acl,
                |burst, sel, context| acl.process_sel(burst, sel, context),
            );
            dropped = dropped.join(filtered.dropped);

            // The accepted meter.
            let admitted = match accepted {
                Some(meter) => {
                    let policed = burst.per_generation(
                        filtered.allowed,
                        tables,
                        |t| &t.accepted,
                        |burst, sel, limits| {
                            police(meter, burst, sel, limits.as_ref(), |m, b, s, l| {
                                m.process_sel(b, s, l)
                            })
                        },
                    );
                    dropped = dropped.join(policed.dropped);
                    policed.passed
                }
                None => filtered.allowed,
            };

            debug_assert!(
                dag::partitions(live_bits, &[admitted.bits(), dropped.bits()]),
                "admission's outcomes do not partition its input"
            );
            seen
        });
        source.settle(seen);
    }
}

impl<Buf, Pre, Mid, Src> NetworkFunction<Buf> for Admission<Pre, Mid, Src>
where
    Buf: PacketBufferMut,
    Pre: NetworkFunction<Buf>,
    Mid: NetworkFunction<Buf>,
    Src: Source,
{
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        if burst.is_empty() {
            // A scheduled run on an empty poll: observe, and count it towards acknowledging.
            self.source.idle();
        } else if burst.len() <= MAX_BURST {
            self.chunk(burst);
        } else {
            self.chunks(burst);
        }
        // Owing an acknowledgement: run again at the next empty poll.
        if self.source.awaiting()
            && let Some(sched) = &self.sched
        {
            sched.asap();
        }
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        NetworkFunction::<Buf>::set_data(&mut self.flow_filter, data.clone());
        NetworkFunction::<Buf>::set_data(&mut self.acl, data.clone());
        self.pre.set_data(data.clone());
        self.mid.set_data(data);
    }

    fn set_sched_run(&mut self, sched: SchedRun) {
        if let Some(wakers) = &self.wakers {
            wakers.register(sched.clone());
        }
        self.sched = Some(sched.clone());
        self.pre.set_sched_run(sched.clone());
        self.mid.set_sched_run(sched);
    }
}

impl<Pre, Mid, Src: Source> Admission<Pre, Mid, Src> {
    /// Bursts larger than [`MAX_BURST`] (tests only: production bursts are at most
    /// `MBUF_BURST`), in order, chunk by chunk.
    fn chunks<Buf>(&mut self, burst: &mut Vec<Packet<Buf>>)
    where
        Buf: PacketBufferMut,
        Pre: NetworkFunction<Buf>,
        Mid: NetworkFunction<Buf>,
    {
        let mut rest = burst.split_off(MAX_BURST);
        self.chunk(burst);
        while !rest.is_empty() {
            let tail = rest.split_off(rest.len().min(MAX_BURST));
            self.chunk(&mut rest);
            burst.append(&mut rest);
            rest = tail;
        }
    }
}

/// The bridge's fixed cost, for measurement only: a legacy stage hosted as the one node of a
/// composite (scan the live packets, run it, rescan). `Admission` minus this is what the typed nodes
/// cost; this minus the bare stage is what entering and leaving typed code costs.
#[cfg(test)]
pub(crate) struct Hosted<N> {
    stage: N,
}

#[cfg(test)]
impl<N> Hosted<N> {
    pub(crate) fn new(stage: N) -> Self {
        Hosted { stage }
    }
}

#[cfg(test)]
impl<Buf: PacketBufferMut, N: NetworkFunction<Buf>> NetworkFunction<Buf> for Hosted<N> {
    fn process_burst(&mut self, packets: &mut Vec<Packet<Buf>>) {
        assert!(packets.len() <= MAX_BURST, "measurement bursts only");
        let Hosted { stage } = self;
        dag::scope(packets, |mut burst, all| {
            let (live, _) = burst.scan_where(all, |p| !p.is_done() && p.meta().is_overlay());
            let (_passed, _dropped) =
                burst.legacy(live, Presence::ALL, |packets| stage.process_burst(packets));
        });
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.stage.set_data(data);
    }

    fn set_sched_run(&mut self, sched: SchedRun) {
        self.stage.set_sched_run(sched);
    }
}
