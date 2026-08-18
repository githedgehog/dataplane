// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::vpc_stats::{VpcId, VpcStatsStore};
use bolero::TypeGenerator;
use net::vxlan::Vni;
use std::collections::HashSet;
use vpcmap::VpcDiscriminant;

#[derive(Debug, Clone, Copy, TypeGenerator)]
struct VpcRef(u8);

impl VpcRef {
    fn id(self) -> VpcId {
        let raw = u32::from(self.0 % 6) + 100;
        VpcDiscriminant::from_vni(Vni::new_checked(raw).unwrap_or_else(|_| unreachable!()))
    }
}

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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|e| unreachable!("{e}"))
}

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
