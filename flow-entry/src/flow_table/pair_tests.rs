// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::table::{FlowTable, PairInsertion};
use concurrency::sync::Arc;
use net::flows::{FlowInfo, FlowInfoFlags};
use net::{FlowKey, IpProtoKey, TcpProtoKey};
use std::time::Duration;

fn key(port: u16) -> FlowKey {
    FlowKey::new(
        None,
        net::flows::flow_key::FlowAddrs::V4 {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
        },
        IpProtoKey::Tcp(TcpProtoKey {
            src_port: port.try_into().unwrap(),
            dst_port: 80.try_into().unwrap(),
        }),
    )
}

fn pair(forward: u16, reverse: u16) -> (Arc<FlowInfo>, Arc<FlowInfo>) {
    FlowInfo::related_pair(
        clock::now() + Duration::from_hours(1),
        key(forward),
        FlowInfoFlags::INITIATOR,
        key(reverse),
        FlowInfoFlags::default(),
    )
    .unwrap()
}

#[cfg(not(feature = "shuttle"))]
#[tokio::test]
async fn pair_admission_preserves_capacity_and_replaces_stale_entries() {
    use super::table::FlowTableError;

    let table = FlowTable::new(2);
    table.set_capacity(1);
    let (forward, reverse) = pair(1001, 1002);
    assert!(matches!(
        table.insert_pair_if_absent(&forward, &reverse).unwrap(),
        PairInsertion::Installed
    ));
    assert_eq!(table.live_len(), 2);

    let (duplicate, unused_reverse) = pair(1001, 1003);
    let PairInsertion::ForwardOccupied(held) = table
        .insert_pair_if_absent(&duplicate, &unused_reverse)
        .unwrap()
    else {
        panic!("a duplicate pair must reuse the forward owner even at capacity");
    };
    assert!(Arc::ptr_eq(&held, &forward));
    assert!(!duplicate.is_active());
    assert!(table.lookup(unused_reverse.flowkey()).is_none());

    let (extra, extra_reverse) = pair(1004, 1005);
    assert!(matches!(
        table.insert_pair_if_absent(&extra, &extra_reverse),
        Err(FlowTableError::CapacityExceeded)
    ));
    assert!(table.lookup(extra.flowkey()).is_none());
    assert!(table.lookup(extra_reverse.flowkey()).is_none());

    forward.invalidate_pair();
    let (replacement, replacement_reverse) = pair(1001, 1002);
    assert!(matches!(
        table
            .insert_pair_if_absent(&replacement, &replacement_reverse)
            .unwrap(),
        PairInsertion::Installed
    ));
    // Let the displaced pair's timers run; they must leave the replacements intact.
    tokio::task::yield_now().await;
    assert!(Arc::ptr_eq(
        &table.lookup(replacement.flowkey()).unwrap(),
        &replacement
    ));
    assert!(Arc::ptr_eq(
        &table.lookup(replacement_reverse.flowkey()).unwrap(),
        &replacement_reverse
    ));
    assert_eq!(table.live_len(), 2);
    assert_eq!(table.len(), Some(2));
}

#[cfg(not(feature = "shuttle"))]
#[tokio::test]
async fn pair_admission_rejects_a_reverse_collision_without_changing_either_owner() {
    let table = FlowTable::new(2);
    let (owner, reverse) = pair(1001, 1002);
    table.insert_pair_if_absent(&owner, &reverse).unwrap();
    let (rejected, rejected_reverse) = pair(1003, 1002);
    assert!(matches!(
        table
            .insert_pair_if_absent(&rejected, &rejected_reverse)
            .unwrap(),
        PairInsertion::ReverseOccupied
    ));
    assert!(table.lookup(rejected.flowkey()).is_none());
    assert!(!rejected.is_active());
    assert!(!rejected_reverse.is_active());
    assert!(Arc::ptr_eq(&table.lookup(owner.flowkey()).unwrap(), &owner));
    assert!(Arc::ptr_eq(
        &table.lookup(reverse.flowkey()).unwrap(),
        &reverse
    ));
    assert!(owner.is_active());
    assert!(reverse.is_active());
    assert_eq!(table.live_len(), 2);
    assert_eq!(table.len(), Some(2));
}

#[cfg(feature = "shuttle")]
mod model {
    use super::*;
    use concurrency::thread;

    fn check(test: impl Fn() + Send + Sync + 'static) {
        let scheduler = shuttle::scheduler::RandomScheduler::new_from_seed(0, 256);
        shuttle::Runner::new(scheduler, concurrency::shuttle_config()).run(test);
    }

    fn assert_complete(table: &FlowTable, forward: &Arc<FlowInfo>) {
        assert!(forward.is_active());
        let reverse = forward.related.as_ref().unwrap().upgrade().unwrap();
        assert!(
            reverse.is_active(),
            "an active forward flow has an inactive reverse"
        );
        assert!(Arc::ptr_eq(
            &table
                .lookup(reverse.flowkey())
                .expect("reverse key is installed"),
            &reverse
        ));
    }

    #[test]
    fn pair_admission_publishes_both_halves_before_lookup_or_reuse() {
        check(|| {
            let table = Arc::new(FlowTable::new(2));
            let inserting = table.clone();
            let creator = thread::spawn(move || {
                let (forward, reverse) = pair(1001, 1002);
                inserting.insert_pair_if_absent(&forward, &reverse).unwrap()
            });
            let inserting = table.clone();
            let competitor = thread::spawn(move || {
                let (forward, reverse) = pair(1001, 1003);
                let result = inserting.insert_pair_if_absent(&forward, &reverse).unwrap();
                match &result {
                    PairInsertion::Installed => assert_complete(&inserting, &forward),
                    PairInsertion::ForwardOccupied(held) => assert_complete(&inserting, held),
                    PairInsertion::ReverseOccupied => panic!("reverse keys are distinct"),
                }
                result
            });

            if let Some(forward) = table.lookup(&key(1001)) {
                assert_complete(&table, &forward);
            }
            let results = [creator.join().unwrap(), competitor.join().unwrap()];
            assert_eq!(
                results
                    .iter()
                    .filter(|r| matches!(r, PairInsertion::Installed))
                    .count(),
                1
            );
            assert_complete(&table, &table.lookup(&key(1001)).unwrap());
            assert_eq!(table.live_len(), 2);
            assert_eq!(table.len(), Some(2));
        });
    }

    #[test]
    fn pair_admission_never_exposes_a_reverse_collision() {
        check(|| {
            let table = Arc::new(FlowTable::new(2));
            let (owner, reverse) = pair(1001, 1002);
            table.insert_pair_if_absent(&owner, &reverse).unwrap();

            let workers: Vec<_> = (0..2)
                .map(|_| {
                    let inserting = table.clone();
                    thread::spawn(move || {
                        let (forward, reverse) = pair(1003, 1002);
                        assert!(matches!(
                            inserting.insert_pair_if_absent(&forward, &reverse).unwrap(),
                            PairInsertion::ReverseOccupied
                        ));
                    })
                })
                .collect();
            assert!(
                table.lookup(&key(1003)).is_none(),
                "a rejected forward key escaped"
            );
            for worker in workers {
                worker.join().unwrap();
            }
            assert!(table.lookup(&key(1003)).is_none());
            assert_complete(&table, &owner);
            assert!(Arc::ptr_eq(&table.lookup(&key(1002)).unwrap(), &reverse));
            assert_eq!(table.live_len(), 2);
            assert_eq!(table.len(), Some(2));
        });
    }

    #[test]
    fn pair_admission_reserves_the_last_slot_once() {
        check(|| {
            let table = Arc::new(FlowTable::new(2));
            table.set_capacity(1);
            let inserting = table.clone();
            let creator = thread::spawn(move || {
                let (forward, reverse) = pair(1001, 1002);
                inserting.insert_pair_if_absent(&forward, &reverse).is_ok()
            });
            let (forward, reverse) = pair(1003, 1004);
            let admitted = table.insert_pair_if_absent(&forward, &reverse).is_ok();
            assert_ne!(creator.join().unwrap(), admitted);
            assert_eq!(table.live_len(), 2);
            assert_eq!(table.len(), Some(2));
        });
    }

    #[test]
    fn pair_admission_and_removal_keep_counts_consistent() {
        check(|| {
            let table = Arc::new(FlowTable::new(2));
            let inserting = table.clone();
            let creator = thread::spawn(move || {
                let (forward, reverse) = pair(1001, 1002);
                inserting.insert_pair_if_absent(&forward, &reverse).unwrap();
            });
            let removed = usize::from(table.remove(&key(1001)).is_some())
                + usize::from(table.remove(&key(1002)).is_some());
            creator.join().unwrap();
            assert_eq!(table.live_len(), 2 - removed);
            assert_eq!(table.len(), Some(2 - removed));
        });
    }
}
