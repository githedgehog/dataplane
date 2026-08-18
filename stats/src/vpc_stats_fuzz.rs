// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Properties of the per-VPC statistics store.
//!
//! `VpcStatsStore` is what the gateway reports about itself: per-VPC and per-VPC-pair packet and
//! byte counters, the latest rates, and the human-readable names those numbers are labelled with.
//! It is read over gRPC and it had **no tests**.
//!
//! Statistics are an odd testing target, because being wrong is not an outage -- which is exactly
//! why it is worth pinning down. A counter that silently wraps, a rate attributed to the wrong vpc
//! pair, or a name that outlives the vpc it belonged to all produce numbers an operator will act on
//! without any way to tell they are wrong.
//!
//! # An operation algebra again
//!
//! The store has a small vocabulary -- add counts, set rates, record both at once, prune to a live
//! set, snapshot -- and the properties are invariants over drawn sequences of it rather than
//! statements about any one order. Two of them are relations between operations rather than
//! assertions about values, and those are the ones with no oracle at all:
//!
//! * `record_pair` must equal `add_pair_counts` followed by `set_pair_rates`, and
//! * the pair table and the per-vpc table must not disturb one another.

#![cfg(test)]

use crate::vpc_stats::{VpcId, VpcStatsStore};
use bolero::TypeGenerator;
use net::vxlan::Vni;
use std::collections::HashSet;
use vpcmap::VpcDiscriminant;

/// A small set of vpc identifiers, so that drawn operations collide often enough to be interesting.
#[derive(Debug, Clone, Copy, TypeGenerator)]
struct VpcRef(u8);

impl VpcRef {
    fn id(self) -> VpcId {
        // A handful of distinct vpcs. Drawn from a wide byte and folded down, so a sequence
        // revisits the same vpc frequently -- which is what makes accumulation and pruning
        // meaningful rather than a series of singletons.
        let raw = u32::from(self.0 % 6) + 100;
        VpcDiscriminant::from_vni(Vni::new_checked(raw).unwrap_or_else(|_| unreachable!()))
    }
}

/// One operation on the store.
#[derive(Debug, Clone, Copy, TypeGenerator)]
enum Op {
    AddPair(VpcRef, VpcRef, u32, u32),
    AddPairDrops(VpcRef, VpcRef, u32, u32),
    SetPairRates(VpcRef, VpcRef, u16, u16),
    RecordPair(VpcRef, VpcRef, u32, u32, u16, u16),
    AddVpc(VpcRef, u32, u32),
    AddVpcDrops(VpcRef, u32, u32),
    SetVpcRates(VpcRef, u16, u16),
    RecordVpc(VpcRef, u32, u32, u16, u16),
    SetName(VpcRef, u8),
}

async fn apply(store: &VpcStatsStore, op: Op) {
    match op {
        Op::AddPair(a, b, p, y) => {
            store
                .add_pair_counts(a.id(), b.id(), u64::from(p), u64::from(y))
                .await;
        }
        Op::AddPairDrops(a, b, p, y) => {
            store
                .add_pair_drops(a.id(), b.id(), u64::from(p), u64::from(y))
                .await;
        }
        Op::SetPairRates(a, b, p, y) => {
            store
                .set_pair_rates(a.id(), b.id(), f64::from(p), f64::from(y))
                .await;
        }
        Op::RecordPair(a, b, p, y, pps, bps) => {
            store
                .record_pair(
                    a.id(),
                    b.id(),
                    u64::from(p),
                    u64::from(y),
                    f64::from(pps),
                    f64::from(bps),
                )
                .await;
        }
        Op::AddVpc(a, p, y) => {
            store
                .add_vpc_counts(a.id(), u64::from(p), u64::from(y))
                .await
        }
        Op::AddVpcDrops(a, p, y) => {
            store
                .add_vpc_drops(a.id(), u64::from(p), u64::from(y))
                .await
        }
        Op::SetVpcRates(a, p, y) => {
            store
                .set_vpc_rates(a.id(), f64::from(p), f64::from(y))
                .await
        }
        Op::RecordVpc(a, p, y, pps, bps) => {
            store
                .record_vpc(
                    a.id(),
                    u64::from(p),
                    u64::from(y),
                    f64::from(pps),
                    f64::from(bps),
                )
                .await;
        }
        Op::SetName(a, n) => store.set_vpc_name_sync(a.id(), format!("vpc-{n}")),
    }
}

/// A current-thread runtime for the store's tokio locks.
///
/// Built outside `bolero::check!` and entered once per iteration rather than wrapping the whole
/// property: a bolero body is synchronous, so blocking on a runtime from *inside* one is refused at
/// run time ("cannot start a runtime from within a runtime"). Nothing here awaits anything that
/// needs time to pass; the runtime exists only because the store's locks are async.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|e| unreachable!("{e}"))
}

/// Counters only ever go up.
///
/// Monotonicity is the contract a counter *is*: every consumer of these numbers computes a delta
/// between two reads, and a counter that went down produces a negative delta, which downstream
/// tooling reads as a wrap and turns into an enormous spike. Getting this wrong does not lose data,
/// it invents it.
///
/// Checked after every operation in a drawn sequence, over both tables and over drops as well as
/// counts, since drops are accumulated by the same mechanism.
#[test]
fn counters_only_ever_increase() {
    let rt = runtime();
    bolero::check!()
        .with_type::<Vec<Op>>()
        .cloned()
        .for_each(|ops: Vec<Op>| {
            rt.block_on(async {
                let store = VpcStatsStore::new();
                let mut high: std::collections::HashMap<(VpcId, VpcId), (u64, u64, u64)> =
                    std::collections::HashMap::new();

                for op in ops.iter().take(24) {
                    apply(&store, *op).await;
                    for (key, stats) in store.snapshot_pairs().await {
                        let seen = high.entry(key).or_default();
                        assert!(
                            stats.ctr.packets >= seen.0
                                && stats.ctr.bytes >= seen.1
                                && stats.drops.packets >= seen.2,
                            "a counter for {key:?} went backwards after {op:?}: \
                                 {stats:?} against a high water mark of {seen:?}"
                        );
                        *seen = (stats.ctr.packets, stats.ctr.bytes, stats.drops.packets);
                    }
                }
            });
        });
}

/// `record_pair` is exactly `add_pair_counts` then `set_pair_rates`.
///
/// A compound operation that drifts from the parts it is meant to compose is the classic way for two
/// code paths to disagree: one caller uses the shorthand, another the long form, and the numbers
/// differ depending on which. Stated as an equivalence between two stores driven in parallel, so it
/// needs no knowledge of what either produces.
#[test]
fn recording_a_pair_equals_counting_then_rating() {
    let rt = runtime();
    bolero::check!()
        .with_type::<Vec<(VpcRef, VpcRef, u32, u32, u16, u16)>>()
        .cloned()
        .for_each(|steps: Vec<(VpcRef, VpcRef, u32, u32, u16, u16)>| {
            rt.block_on(async {
                let compound = VpcStatsStore::new();
                let parts = VpcStatsStore::new();

                for (a, b, p, y, pps, bps) in steps.iter().take(24) {
                    let (a, b) = (a.id(), b.id());
                    let (p, y) = (u64::from(*p), u64::from(*y));
                    let (pps, bps) = (f64::from(*pps), f64::from(*bps));
                    compound.record_pair(a, b, p, y, pps, bps).await;
                    parts.add_pair_counts(a, b, p, y).await;
                    parts.set_pair_rates(a, b, pps, bps).await;
                }

                let mut left = compound.snapshot_pairs().await;
                let mut right = parts.snapshot_pairs().await;
                left.sort_by_key(|(k, _)| *k);
                right.sort_by_key(|(k, _)| *k);
                assert_eq!(
                    left.len(),
                    right.len(),
                    "the two stores hold different pairs"
                );
                for ((lk, lv), (rk, rv)) in left.iter().zip(right.iter()) {
                    assert_eq!(lk, rk, "the two stores disagree on which pairs exist");
                    assert_eq!(
                        (lv.ctr.packets, lv.ctr.bytes, lv.rate.pps, lv.rate.bps),
                        (rv.ctr.packets, rv.ctr.bytes, rv.rate.pps, rv.rate.bps),
                        "record_pair and add-then-set disagree for {lk:?}"
                    );
                }
            });
        });
}

/// The pair table and the per-vpc table do not disturb one another.
///
/// They look like they should be linked -- a per-vpc total ought to be the sum of that vpc's pairs --
/// and they are not: each is maintained independently by the caller. Writing that down is the point.
/// A future change that started deriving one from the other would break every caller that maintains
/// both, and a reader who assumes the link is already there will under-report.
#[test]
fn the_two_tables_are_independent() {
    let rt = runtime();
    bolero::check!()
        .with_type::<Vec<Op>>()
        .cloned()
        .for_each(|ops: Vec<Op>| {
            rt.block_on(async {
                let store = VpcStatsStore::new();
                for op in ops.iter().take(24) {
                    // Only pair operations.
                    if matches!(
                        op,
                        Op::AddPair(..)
                            | Op::AddPairDrops(..)
                            | Op::SetPairRates(..)
                            | Op::RecordPair(..)
                    ) {
                        apply(&store, *op).await;
                    }
                }
                assert!(
                    store.snapshot_vpcs().await.is_empty(),
                    "recording pair statistics populated the per-vpc table, so per-vpc totals \
                         would double count once a caller maintains both"
                );
            });
        });
}

/// Pruning keeps exactly the live set, and a pair needs *both* ends alive.
///
/// The sharpest condition in the store. A pair is retained only if its source **and** its
/// destination survive; a slip to `||` keeps half-dead pairs, which report traffic to a vpc that no
/// longer exists and which nothing will ever clean up, because the next prune has the same defect.
///
/// Names are pruned by the same rule, and that matters for a different reason: a name outliving its
/// vpc gets attached to whatever discriminant is allocated next, so an operator reads one tenant's
/// traffic under another tenant's name.
#[test]
fn pruning_keeps_exactly_the_live_set() {
    let rt = runtime();
    bolero::check!()
        .with_type::<(Vec<Op>, Vec<VpcRef>)>()
        .cloned()
        .for_each(|(ops, alive): (Vec<Op>, Vec<VpcRef>)| {
            rt.block_on(async {
                let store = VpcStatsStore::new();
                for op in ops.iter().take(24) {
                    apply(&store, *op).await;
                }
                let alive: HashSet<VpcId> = alive.iter().map(|v| v.id()).collect();
                store.prune_to_vpcs(&alive).await;

                for (key @ (src, dst), _) in store.snapshot_pairs().await {
                    assert!(
                        alive.contains(&src) && alive.contains(&dst),
                        "pruning kept the pair {key:?} although one of its ends is gone"
                    );
                }
                for (vpc, _) in store.snapshot_vpcs().await {
                    assert!(
                        alive.contains(&vpc),
                        "pruning kept per-vpc statistics for {vpc:?}, which is gone"
                    );
                }
                for vpc in store.snapshot_names().await.keys() {
                    assert!(
                        alive.contains(vpc),
                        "pruning kept the name of {vpc:?}, which is gone; it will be read \
                             against whichever vpc is allocated that discriminant next"
                    );
                }
            });
        });
}

/// Pruning removes nothing that is still alive.
///
/// The other half of "exactly". A prune that dropped live entries would reset an operator's counters
/// to zero without warning, and the next delta would read as a wrap.
#[test]
fn pruning_removes_nothing_that_is_alive() {
    let rt = runtime();
    bolero::check!()
        .with_type::<Vec<Op>>()
        .cloned()
        .for_each(|ops: Vec<Op>| {
            rt.block_on(async {
                let store = VpcStatsStore::new();
                for op in ops.iter().take(24) {
                    apply(&store, *op).await;
                }
                let before_pairs = store.snapshot_pairs().await;
                let before_vpcs = store.snapshot_vpcs().await;
                let before_names = store.snapshot_names().await;

                // Everything mentioned anywhere is alive, so nothing may be dropped.
                let mut alive: HashSet<VpcId> = HashSet::new();
                for ((src, dst), _) in &before_pairs {
                    alive.insert(*src);
                    alive.insert(*dst);
                }
                for (vpc, _) in &before_vpcs {
                    alive.insert(*vpc);
                }
                alive.extend(before_names.keys().copied());

                store.prune_to_vpcs(&alive).await;

                assert_eq!(
                    store.snapshot_pairs().await.len(),
                    before_pairs.len(),
                    "pruning dropped a pair whose ends are both alive"
                );
                assert_eq!(
                    store.snapshot_vpcs().await.len(),
                    before_vpcs.len(),
                    "pruning dropped per-vpc statistics for a live vpc"
                );
                assert_eq!(
                    store.snapshot_names().await.len(),
                    before_names.len(),
                    "pruning dropped the name of a live vpc"
                );
            });
        });
}

/// A counter at the top of its range saturates rather than wrapping.
///
/// `saturating_add` is the deliberate choice here and it is the right one: a counter pinned at
/// `u64::MAX` is visibly stuck, while one that wrapped to a small number reports an enormous
/// negative delta that tooling renders as a traffic spike of billions of packets.
#[test]
fn counters_saturate_rather_than_wrap() {
    runtime().block_on(async {
        let store = VpcStatsStore::new();
        let (a, b) = (VpcRef(0).id(), VpcRef(1).id());
        store.add_pair_counts(a, b, u64::MAX, u64::MAX).await;
        store.add_pair_counts(a, b, 1_000, 1_000).await;
        store.add_pair_drops(a, b, u64::MAX, u64::MAX).await;
        store.add_pair_drops(a, b, 1_000, 1_000).await;

        let pairs = store.snapshot_pairs().await;
        let (_, stats) = pairs.first().unwrap_or_else(|| unreachable!());
        assert_eq!(stats.ctr.packets, u64::MAX, "a packet counter wrapped");
        assert_eq!(stats.ctr.bytes, u64::MAX, "a byte counter wrapped");
        assert_eq!(stats.drops.packets, u64::MAX, "a drop counter wrapped");
    });
}

/// A name set for a vpc is the name read back for it, and for no other.
#[test]
fn a_name_belongs_to_exactly_one_vpc() {
    let rt = runtime();
    bolero::check!()
        .with_type::<Vec<(VpcRef, u8)>>()
        .cloned()
        .for_each(|pairs: Vec<(VpcRef, u8)>| {
            rt.block_on(async {
                let store = VpcStatsStore::new();
                let mut expected = std::collections::HashMap::new();
                for (vpc, n) in pairs.iter().take(24) {
                    let name = format!("vpc-{n}");
                    store.set_vpc_name_sync(vpc.id(), name.clone());
                    expected.insert(vpc.id(), name);
                }
                for (vpc, name) in &expected {
                    assert_eq!(
                        store.name_of(*vpc).as_ref(),
                        Some(name),
                        "the name read back for {vpc:?} is not the one set"
                    );
                }
                assert_eq!(
                    store.snapshot_names().await.len(),
                    expected.len(),
                    "the store holds names for vpcs that were never named"
                );
            });
        });
}
