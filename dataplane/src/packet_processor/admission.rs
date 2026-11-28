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
//!
//! **Traps** (slice 1 step 4, `notes/match-action-dag/TRAP-RESUME.md`). Hardware may have run a
//! prefix of the slice: a packet it trapped enters at a declared target ([`node`]), as one more
//! inbound edge of that node, with the edge's metadata decoded under the packet's generation.
//! Hardware is emulated by this same composite, stopped at a [`Cut`]: T8, the equivalence of a
//! whole run and a trapped-and-resumed one, is tested in `fuzz.rs`.

use acl_filter::{AclFilter, AclFilterContext, AclFilterContextReader};
use concurrency::sync::Arc;
use dag::generation::{Reader, Seen, Snapshot, Tables};
use dag::trap::Entries;
use dag::{Assign, Burst, Drops, Edit, Emit, Forget, Keep, Kind, MAX_BURST, Presence, Sel, kind};
use flow_filter::{FlowFilter, FlowFilterContext, FlowFilterContextReader};
use net::buffer::PacketBufferMut;
use net::packet::{Bank, DoneReason, Mark, Packet, PacketMeta, Trap, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::{NetworkFunction, PipelineData, SchedRun};
use rate_limit::{IngressRules, PeeringRules, Policed, RateLimitReader, RateLimiter, RateLimits};
use std::num::NonZero;

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
    /// Each VPC's peers, as trap edges number them.
    pub(crate) peers: Peers,
}

impl AdmissionTables {
    /// What NIC offload compiles of this generation: its policy, with no rate limits for a
    /// meter that has none.
    pub(crate) fn inputs(&self) -> nic_offload::Inputs {
        nic_offload::Inputs {
            acls: Arc::clone(&self.acl),
            routing: Arc::clone(&self.flow_filter),
            rate_limits: self
                .accepted
                .clone()
                .unwrap_or_else(|| Arc::new(RateLimits::empty())),
            ingress: self
                .arrived
                .clone()
                .unwrap_or_else(|| Arc::new(RateLimits::empty())),
        }
    }
}

/// The admission slice's trap targets: static ids (TRAP-RESUME §4), each where hardware may
/// leave a packet to software, and each named for the node it enters at, which has not executed.
/// No trap is the root: the arrived meter.
///
/// The hosted legacy stages (ICMP errors and the flow lookup; the SYN cookie checker) run in
/// software only. A packet past them was one they would leave alone, which hardware ensures with
/// guards (a flow-cache miss, not an ICMP error, …): T2 holds because they would not have acted.
pub(crate) mod node {
    use std::num::NonZero;

    /// The legacy `pre` stages: the arrived meter executed.
    pub(crate) const PRE: NonZero<u8> = NonZero::new(1).unwrap();
    /// The ACL: the flow filter executed. The edge carries its verdict ([`super::Routed`]).
    pub(crate) const ACL: NonZero<u8> = NonZero::new(2).unwrap();
    /// The accepted meter: the ACL executed. The verdict, as the ACL left it.
    pub(crate) const ACCEPTED: NonZero<u8> = NonZero::new(3).unwrap();
    /// Past the slice: every node executed. The verdict, as the ACL left it.
    pub(crate) const EXPORT: NonZero<u8> = NonZero::new(4).unwrap();

    /// All of them, in topological order.
    pub(crate) const ALL: [NonZero<u8>; 4] = [PRE, ACL, ACCEPTED, EXPORT];
}

/// Each VPC's peers in one generation, numbered for trap edges: a destination VPC is a 10-bit
/// id there, its rank among its source VPC's peers (the source VPC is known from decapsulation),
/// valid under the packet's generation only (its stamp says which). This bounds peers per VPC,
/// not VPCs: a VPC with more peers than ids keeps the rest off the trap edges past the flow
/// filter, which can't be cut there for it (R4, load time). Numbering is compiler state
/// (TRAP-RESUME §3), per generation; ids need not be stable across generations, since a trap is
/// always decoded under the generation it was encoded under.
#[derive(Debug, Default)]
pub(crate) struct Peers(std::collections::HashMap<Vni, Vec<Vni>>);

impl Peers {
    /// Ids are 1..=MAX; 0 is no VPC.
    const MAX: usize = (1 << Routed::DST_BITS) - 1;

    pub(crate) fn new(peers: impl IntoIterator<Item = (Vni, Vec<Vni>)>) -> Self {
        Peers(
            peers
                .into_iter()
                .map(|(vpc, mut peers)| {
                    peers.sort_unstable();
                    peers.dedup();
                    (vpc, peers)
                })
                .collect(),
        )
    }

    fn id(&self, src: VpcDiscriminant, dst: VpcDiscriminant) -> Option<u16> {
        let (VpcDiscriminant::VNI(src), VpcDiscriminant::VNI(dst)) = (src, dst);
        let k = self.0.get(&src)?.binary_search(&dst).ok()?;
        (k < Self::MAX).then(|| u16::try_from(k + 1).ok()).flatten()
    }

    fn get(&self, src: VpcDiscriminant, id: u16) -> Option<VpcDiscriminant> {
        let VpcDiscriminant::VNI(src) = src;
        let k = usize::from(id).checked_sub(1)?;
        (k < Self::MAX)
            .then(|| self.0.get(&src)?.get(k))
            .flatten()
            .map(|vni| VpcDiscriminant::VNI(*vni))
    }
}

/// The flow filter's verdict, as the trap edges past it carry it in 15 bits: the destination
/// VPC ([`Peers`] id, 0 for none) above five flags, the NAT requirements and forced tracking.
/// What else the flow filter and the ACL leave on a packet is recomputed from the bytes on entry
/// (pure replays, TRAP-RESUME Q6): the pre-NAT flow key, the opening TCP flags.
struct Routed;

impl Routed {
    const DST_BITS: u32 = 10;
    const FLAGS: u32 = 5;

    /// What the edge carries for `meta`, under `peers`; `None` if its destination VPC has no id.
    fn encode(meta: &PacketMeta, peers: &Peers) -> Option<u16> {
        let dst = match meta.dst_vpcd {
            None => 0,
            Some(dst) => peers.id(meta.src_vpcd?, dst)?,
        };
        let flags = [
            meta.requires_masquerade(),
            meta.requires_port_forwarding(),
            meta.requires_static_nat_src(),
            meta.requires_static_nat_dst(),
            meta.has_forced_flow_tracking(),
        ]
        .iter()
        .enumerate()
        .fold(0u16, |bits, (k, &on)| bits | (u16::from(on) << k));
        Some((dst << Self::FLAGS) | flags)
    }

    /// Back onto `meta`: the flags; the destination VPC (if any) is returned, for a typed
    /// write.
    ///
    /// # Errors
    ///
    /// For an id with no VPC among the source VPC's peers, or no source VPC: a lowering bug.
    fn decode(
        payload: u16,
        peers: &Peers,
        meta: &mut PacketMeta,
    ) -> Result<Option<VpcDiscriminant>, Undecodable> {
        let id = payload >> Self::FLAGS;
        let dst = match id {
            0 => None,
            id => {
                let src = meta.src_vpcd.ok_or(Undecodable)?;
                Some(peers.get(src, id).ok_or(Undecodable)?)
            }
        };
        let flag = |k: u32| payload & (1 << k) != 0;
        meta.set_masquerade(flag(0));
        meta.set_port_forwarding(flag(1));
        meta.set_static_nat_src(flag(2));
        meta.set_static_nat_dst(flag(3));
        meta.set_forced_flow_tracking(flag(4));
        Ok(dst)
    }
}

/// A trap edge's payload its node can't decode (T7, `TrapDecode`).
struct Undecodable;

const _: () = assert!(Routed::DST_BITS + Routed::FLAGS == Mark::PAYLOAD_BITS);

/// The payload of `node`'s trap edge for a packet with `meta`, under `peers`.
///
/// # Panics
///
/// If the packet's destination VPC has no id: a cut the lowering would have refused (emulation
/// only).
fn edge_payload(node: NonZero<u8>, meta: &PacketMeta, peers: &Peers) -> u16 {
    if node == self::node::PRE {
        0
    } else {
        Routed::encode(meta, peers).unwrap_or_else(|| {
            unreachable!("a VPC beyond the trap edge's ids, cut past the flow filter")
        })
    }
}

/// Packets each node of the slice executed (T3: a node's side effects, its counts included,
/// belong to the tier that ran it). With traps, a whole run's counts are the sum of hardware's
/// and software's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Executed {
    pub(crate) arrived: u64,
    pub(crate) pre: u64,
    pub(crate) flow_filter: u64,
    pub(crate) mid: u64,
    pub(crate) acl: u64,
    pub(crate) accepted: u64,
}

impl std::ops::Add for Executed {
    type Output = Executed;

    fn add(self, other: Executed) -> Executed {
        Executed {
            arrived: self.arrived + other.arrived,
            pre: self.pre + other.pre,
            flow_filter: self.flow_filter + other.flow_filter,
            mid: self.mid + other.mid,
            acl: self.acl + other.acl,
            accepted: self.accepted + other.accepted,
        }
    }
}

/// Where emulated hardware stops: the composite, run as the NIC, leaves a packet to software at
/// the first trap target the cut chooses for it, with that target's trap written on it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) trait Cut<Buf: PacketBufferMut> {
    /// Whether `packet`, about to enter `node`, traps there instead.
    fn exit(&mut self, node: NonZero<u8>, packet: &Packet<Buf>) -> bool;
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
            peers: Peers::default(),
        };
        // Generation 1 in bank A: what hardware stamps when no publisher flips (`nic_offload`'s
        // ports start there, as `Generations` does).
        Tables::only(self.snapshot.insert(Snapshot::new(1, Bank::A, tables)))
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
            peers: Peers::new(update.peers),
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
    /// What each node executed.
    executed: Executed,
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
            executed: Executed::default(),
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
            executed,
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
            executed,
        }
    }

    /// What each node executed so far.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn executed(&self) -> Executed {
        self.executed
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

/// Packets trapped at a target after the flow filter: the verdict back on them, under their
/// generation, and their destination VPC written; those whose payload names no VPC, dropped.
fn enter_routed<'b, Buf, S>(
    burst: &mut Burst<'b, Buf>,
    sel: Sel<'b, S>,
    tables: Tables<'b, AdmissionTables>,
) -> (Sel<'b, Forget<S, kind::DstVpc>>, Drops<'b>)
where
    Buf: PacketBufferMut,
    S: Edit<kind::DstVpc>,
{
    burst.per_generation(
        sel,
        tables,
        |t| &t.peers,
        |burst, sel, peers| {
            let mut routed = Emit::<S, Assign<kind::DstVpc>>::new();
            let mut bad = Drops::none();
            for i in sel {
                let packet = burst.packet_mut(&i);
                let payload = packet.meta().trap().map_or(0, Trap::payload);
                match Routed::decode(payload, peers, packet.meta_mut()) {
                    Ok(dst) => {
                        FlowFilter::keep_flow_key(packet);
                        routed.push(burst, i, dst);
                    }
                    Err(Undecodable) => burst.drop(&mut bad, i, DoneReason::TrapDecode),
                }
            }
            (routed.finish(), bad)
        },
    )
}

/// Packets trapped past the ACL: its opening TCP flags back on them.
fn enter_allowed<'b, Buf, S>(
    burst: &mut Burst<'b, Buf>,
    sel: Sel<'b, S>,
) -> Sel<'b, Forget<S, kind::OpeningTcpFlags>>
where
    Buf: PacketBufferMut,
    S: Edit<kind::OpeningTcpFlags>,
{
    let mut allowed = Emit::<S, Assign<kind::OpeningTcpFlags>>::new();
    for i in sel {
        let flags = acl_filter::opening_tcp_flags(burst.packet(&i));
        allowed.push(burst, i, flags);
    }
    allowed.finish()
}

/// Emulated hardware only: the packets of `sel` that `cut` stops at `node` get `node`'s trap,
/// encoded under their generation, and leave (into `trapped`); the rest go on.
fn exit<'b, Buf, S>(
    burst: &mut Burst<'b, Buf>,
    sel: Sel<'b, S>,
    node: NonZero<u8>,
    tables: Tables<'b, AdmissionTables>,
    cut: &mut Option<&mut dyn Cut<Buf>>,
    trapped: &mut u64,
) -> Sel<'b, S>
where
    Buf: PacketBufferMut,
    S: dag::State,
{
    let Some(cut) = cut.as_deref_mut() else {
        return sel;
    };
    let (out, stay) = burst.filter(sel, |packet| cut.exit(node, packet));
    let out = burst.per_generation(
        out,
        tables,
        |t| &t.peers,
        |burst, sel, peers| {
            let mut left = Emit::<S, Keep>::new();
            for i in sel {
                let meta = burst.packet(&i).meta();
                let stamp = meta
                    .stamp()
                    .unwrap_or_else(|| unreachable!("hardware stamps every packet it runs"));
                let mark = Mark::new(
                    stamp,
                    Some(Trap::new(node, edge_payload(node, meta, peers))),
                );
                burst.packet_mut(&i).meta_mut().set_mark(Some(mark));
                left.push(i);
            }
            left.finish()
        },
    );
    *trapped |= out.bits();
    stay
}

impl<Pre, Mid, Src: Source> Admission<Pre, Mid, Src> {
    /// One burst of at most [`MAX_BURST`] packets. With a `cut`, the composite is emulated
    /// hardware: packets the cut stops leave with a trap, and are not done.
    #[allow(clippy::too_many_lines)] // one topology, read top to bottom
    fn chunk<Buf>(&mut self, packets: &mut Vec<Packet<Buf>>, mut cut: Option<&mut dyn Cut<Buf>>)
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
            executed,
            ..
        } = self;
        let tables = source.tables();
        let seen = dag::scope_with(packets, tables, |mut burst, all, tables| {
            let tables = *tables;
            // Packets done or not from a VPC are not ours: they are in no edge, and untouched,
            // unless hardware trapped one into the slice (T7: a lowering bug).
            let (live, rest) = burst.scan_where(all, |p| !p.is_done() && p.meta().is_overlay());
            let (misshapen, _) = burst.filter(rest, |p| !p.is_done() && p.meta().trap().is_some());
            let mut misfits = Drops::none();
            for i in misshapen {
                burst.drop(&mut misfits, i, DoneReason::TrapShape);
            }
            let live_bits = live.bits();
            // Each packet runs under the generation its stamp names; a stale stamp is dropped,
            // trapped or not (T5).
            let (live, mut dropped, seen) = burst.resolve(live, tables);
            // Where each packet enters (T1, T6); those trapped past the flow filter get its
            // verdict back. Emulated hardware leaves packets at its cut (`trapped`).
            let mut trapped = 0u64;
            let Entries {
                root,
                at: [pre_entry, acl_entry, accepted_entry, export_entry],
                unknown,
            } = burst.enter(live, node::ALL);
            for i in unknown {
                burst.drop(&mut dropped, i, DoneReason::TrapUnknownNode);
            }
            let (pre_entry, undecodable) = burst.filter(pre_entry, |p| {
                p.meta().trap().is_some_and(|t| t.payload() == 0)
            });
            for i in undecodable {
                burst.drop(&mut dropped, i, DoneReason::TrapDecode);
            }
            let (acl_entry, bad) = enter_routed(&mut burst, acl_entry, tables);
            dropped = dropped.join(bad);
            let (accepted_entry, bad) = enter_routed(&mut burst, accepted_entry, tables);
            dropped = dropped.join(bad);
            let accepted_entry = enter_allowed(&mut burst, accepted_entry);
            let (accepted_entry, no_src) = burst.split::<kind::SrcVpc, _>(accepted_entry);
            for i in no_src {
                burst.drop(&mut dropped, i, DoneReason::TrapShape);
            }
            let (accepted_entry, no_dst) = burst.split::<kind::DstVpc, _>(accepted_entry);
            for i in no_dst {
                burst.drop(&mut dropped, i, DoneReason::TrapDecode);
            }
            let (export_entry, bad) = enter_routed(&mut burst, export_entry, tables);
            dropped = dropped.join(bad);
            let export_entry = enter_allowed(&mut burst, export_entry);

            // The arrived meter, on packets whose source VPC is known.
            let (known, unknown) = burst.split::<kind::SrcVpc, _>(root);
            executed.arrived += u64::from(known.len());
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
            let pre_in = arrived_out.join(unknown).join(pre_entry);
            let pre_in = exit(
                &mut burst,
                pre_in,
                node::PRE,
                tables,
                &mut cut,
                &mut trapped,
            );

            // Legacy: ICMP errors, flow lookup. Hosted at a join, so it sees every live packet
            // at this point, and only those.
            executed.pre += u64::from(pre_in.len());
            let hide = live_bits & !pre_in.bits();
            let (looked_up, lost) = burst.legacy_hiding(pre_in, hide, LEGACY_WRITES, |packets| {
                pre.process_burst(packets);
            });
            dropped = dropped.join(lost);

            // The flow filter, on packets no earlier stage gave a destination.
            let (placed, unplaced) = burst.split::<kind::DstVpc, _>(looked_up);
            executed.flow_filter += u64::from(unplaced.len());
            let routed = burst.per_generation(
                unplaced,
                tables,
                |t| &*t.flow_filter,
                |burst, sel, tables| flow_filter.process_sel(burst, sel, tables),
            );
            dropped = dropped.join(routed.dropped);
            let placed = routed.routed.join(placed);

            // Legacy: the SYN cookie checker.
            executed.mid += u64::from(placed.len());
            let hide = live_bits & !placed.bits();
            let (checked, lost) = burst.legacy_hiding(placed, hide, LEGACY_WRITES, |packets| {
                mid.process_burst(packets);
            });
            dropped = dropped.join(lost);

            // The ACL, on packets whose VPCs are both known; the legacy ACL drops the others first.
            let acl_in = checked.join(acl_entry);
            let acl_in = exit(
                &mut burst,
                acl_in,
                node::ACL,
                tables,
                &mut cut,
                &mut trapped,
            );
            executed.acl += u64::from(acl_in.len());
            let (with_src, no_src) = burst.split::<kind::SrcVpc, _>(acl_in);
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
            let accepted_in = filtered.allowed.join(accepted_entry);
            let accepted_in = exit(
                &mut burst,
                accepted_in,
                node::ACCEPTED,
                tables,
                &mut cut,
                &mut trapped,
            );
            executed.accepted += u64::from(accepted_in.len());
            let admitted = match accepted {
                Some(meter) => {
                    let policed = burst.per_generation(
                        accepted_in,
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
                None => accepted_in,
            };
            let admitted = exit(
                &mut burst,
                admitted,
                node::EXPORT,
                tables,
                &mut cut,
                &mut trapped,
            );

            debug_assert!(
                dag::partitions(
                    live_bits,
                    &[
                        admitted.bits(),
                        export_entry.bits(),
                        dropped.bits(),
                        trapped
                    ]
                ),
                "admission's outcomes do not partition its input"
            );
            seen
        });
        source.settle(seen);
    }

    /// Run `packets` (at most [`MAX_BURST`]) as emulated hardware: stopped where `cut` says.
    #[cfg(test)]
    pub(crate) fn emulate<Buf>(&mut self, packets: &mut Vec<Packet<Buf>>, cut: &mut dyn Cut<Buf>)
    where
        Buf: PacketBufferMut,
        Pre: NetworkFunction<Buf>,
        Mid: NetworkFunction<Buf>,
    {
        assert!(packets.len() <= MAX_BURST, "emulated bursts only");
        self.chunk(packets, Some(cut));
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
            self.chunk(burst, None);
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
        self.chunk(burst, None);
        while !rest.is_empty() {
            let tail = rest.split_off(rest.len().min(MAX_BURST));
            self.chunk(&mut rest, None);
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
