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

use acl_filter::AclFilter;
use concurrency::sync::Arc;
use dag::{Drops, Kind, MAX_BURST, Presence, kind};
use flow_filter::FlowFilter;
use net::buffer::PacketBufferMut;
use net::packet::{DoneReason, Packet};
use pipeline::{NetworkFunction, PipelineData, SchedRun};
use rate_limit::{IngressRules, PeeringRules, RateLimiter};

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

/// The admission slice as one stage: arrived meter → (pre) → flow filter → (mid) → ACL →
/// accepted meter.
pub(crate) struct Admission<Pre, Mid> {
    arrived: Option<RateLimiter<IngressRules>>,
    pre: Pre,
    flow_filter: FlowFilter,
    mid: Mid,
    acl: AclFilter,
    accepted: Option<RateLimiter<PeeringRules>>,
}

impl<Pre, Mid> Admission<Pre, Mid> {
    pub(crate) fn new(
        arrived: Option<RateLimiter<IngressRules>>,
        pre: Pre,
        flow_filter: FlowFilter,
        mid: Mid,
        acl: AclFilter,
        accepted: Option<RateLimiter<PeeringRules>>,
    ) -> Self {
        Admission {
            arrived,
            pre,
            flow_filter,
            mid,
            acl,
            accepted,
        }
    }
}

impl<Pre, Mid> Admission<Pre, Mid> {
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
        } = self;
        dag::scope(packets, |mut burst, all| {
            // Packets done or not from a VPC are not ours: they are in no edge, and untouched.
            let (live, _) = burst.scan_where(all, |p| !p.is_done() && p.meta().is_overlay());
            let live_bits = live.bits();

            // The arrived meter, on packets whose source VPC is known.
            let (known, unknown) = burst.split::<kind::SrcVpc, _>(live);
            let (arrived_out, mut dropped) = match arrived {
                Some(meter) => {
                    let policed = meter.process_sel(&mut burst, known);
                    (policed.passed, policed.dropped)
                }
                None => (known, Drops::none()),
            };
            let arrived_out = arrived_out.join(unknown);

            // Legacy: ICMP errors, flow lookup. Hosted at a join, so it sees every live packet.
            let (looked_up, lost) = burst.legacy(arrived_out, LEGACY_WRITES, |packets| {
                pre.process_burst(packets);
            });
            dropped = dropped.join(lost);

            // The flow filter, on packets no earlier stage gave a destination.
            let (placed, unplaced) = burst.split::<kind::DstVpc, _>(looked_up);
            let routed = flow_filter.process_sel(&mut burst, unplaced);
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
            let filtered = acl.process_sel(&mut burst, acl_in);
            dropped = dropped.join(filtered.dropped);

            // The accepted meter.
            let (admitted, lost) = match accepted {
                Some(meter) => {
                    let policed = meter.process_sel(&mut burst, filtered.allowed);
                    (policed.passed, policed.dropped)
                }
                None => (filtered.allowed, Drops::none()),
            };
            dropped = dropped.join(lost);

            debug_assert!(
                dag::partitions(live_bits, &[admitted.bits(), dropped.bits()]),
                "admission's outcomes do not partition its input"
            );
        });
    }
}

impl<Buf, Pre, Mid> NetworkFunction<Buf> for Admission<Pre, Mid>
where
    Buf: PacketBufferMut,
    Pre: NetworkFunction<Buf>,
    Mid: NetworkFunction<Buf>,
{
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        if burst.len() <= MAX_BURST {
            self.chunk(burst);
            return;
        }
        // Production bursts are at most MAX_BURST (MBUF_BURST); larger ones come from tests.
        // Process them in order, chunk by chunk.
        let mut rest = burst.split_off(MAX_BURST);
        self.chunk(burst);
        while !rest.is_empty() {
            let tail = rest.split_off(rest.len().min(MAX_BURST));
            self.chunk(&mut rest);
            burst.append(&mut rest);
            rest = tail;
        }
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        NetworkFunction::<Buf>::set_data(&mut self.flow_filter, data.clone());
        NetworkFunction::<Buf>::set_data(&mut self.acl, data.clone());
        self.pre.set_data(data.clone());
        self.mid.set_data(data);
    }

    fn set_sched_run(&mut self, sched: SchedRun) {
        self.pre.set_sched_run(sched.clone());
        self.mid.set_sched_run(sched);
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
