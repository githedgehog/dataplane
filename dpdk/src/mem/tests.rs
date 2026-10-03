// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::{MBUF_BURST, Mbuf, MbufAllocError, MbufArray};
use crate::test_support::{available, packet_pool};
use net::buffer::Append;
use std::collections::HashSet;

#[test]
fn bulk_allocation_and_drop_restore_the_pool_for_every_batch_size() {
    let pool = packet_pool(127);
    for count in 0..=MBUF_BURST {
        let batch = pool.alloc_bulk(count).unwrap();
        assert_eq!(batch.len(), count);
        assert_eq!(batch.is_empty(), count == 0);
        assert_eq!(available(&pool), 127 - count);
        let pointers: HashSet<_> = batch.iter().map(|mbuf| mbuf.raw).collect();
        assert_eq!(pointers.len(), count);
        drop(batch);
        assert_eq!(available(&pool), 127);
    }
}

#[test]
fn bulk_drop_releases_each_mbuf_reference_once() {
    let pool = packet_pool(127);
    let batch = pool.alloc_bulk(MBUF_BURST).unwrap();
    let retained: Vec<_> = batch
        .iter()
        .map(|mbuf| {
            // SAFETY: retain a DPDK reference to each live mbuf. Neither owner
            // mutates the shared packet data.
            unsafe {
                assert_eq!(dpdk_sys::rte_mbuf_refcnt_update(mbuf.raw.as_ptr(), 1), 2);
                Mbuf::new_from_raw_unchecked(mbuf.raw.as_ptr())
            }
        })
        .collect();
    drop(batch);
    assert_eq!(available(&pool), 127 - MBUF_BURST);
    for mbuf in &retained {
        // SAFETY: the retained reference keeps the mbuf live.
        assert_eq!(
            unsafe { dpdk_sys::rte_mbuf_refcnt_read(mbuf.raw.as_ptr()) },
            1
        );
    }
    drop(retained);
    assert_eq!(available(&pool), 127);
}

#[test]
fn oversized_allocation_leaves_the_pool_untouched() {
    let pool = packet_pool(63);
    for requested in [MBUF_BURST + 1, usize::MAX] {
        assert!(matches!(
            pool.alloc_bulk(requested),
            Err(MbufAllocError::TooMany { requested: actual, capacity })
                if actual == requested && capacity == MBUF_BURST
        ));
        assert_eq!(available(&pool), 63);
    }
}

#[test]
fn failed_bulk_allocation_preserves_the_remaining_mbufs() {
    let pool = packet_pool(63);
    let held = pool.alloc_bulk(32).unwrap();
    assert!(matches!(
        pool.alloc_bulk(32),
        Err(MbufAllocError::Exhausted { requested: 32 })
    ));
    assert_eq!(available(&pool), 31);

    let rest = pool.alloc_bulk(31).unwrap();
    assert_eq!(available(&pool), 0);
    assert!(matches!(
        pool.alloc_bulk(1),
        Err(MbufAllocError::Exhausted { requested: 1 })
    ));
    assert!(pool.alloc_bulk(0).unwrap().is_empty());
    drop(held);
    assert_eq!(available(&pool), 32);
    drop(rest);
    assert_eq!(available(&pool), 63);
    assert_eq!(pool.alloc_bulk(63).unwrap().len(), 63);
    assert_eq!(available(&pool), 63);
}

#[test]
fn dropping_an_iterator_frees_only_the_unconsumed_mbufs() {
    let pool = packet_pool(127);
    for consumed in 0..=MBUF_BURST {
        let mut batch = pool.alloc_bulk(MBUF_BURST).unwrap();
        for (id, mbuf) in batch.iter_mut().enumerate() {
            mbuf.append(1).unwrap()[0] = id as u8;
        }
        let mut iter = batch.into_iter();
        assert_eq!(available(&pool), 127 - MBUF_BURST);
        let mut held = Vec::new();
        for id in 0..consumed {
            let mbuf = iter.next().unwrap();
            assert_eq!(mbuf.raw_data(), &[id as u8]);
            held.push(mbuf);
        }
        drop(iter);
        assert_eq!(available(&pool), 127 - consumed);
        for (id, mbuf) in held.iter().enumerate() {
            assert_eq!(mbuf.raw_data(), &[id as u8]);
        }
        drop(held);
        assert_eq!(available(&pool), 127);
    }
}

#[test]
fn a_full_batch_returns_ownership_of_the_rejected_mbuf() {
    let pool = packet_pool(7);
    let mut input = pool.alloc_bulk(4).unwrap().into_iter();
    let mut batch = MbufArray::<3>::new_empty();
    for mbuf in input.by_ref().take(3) {
        batch.try_push(mbuf).unwrap();
    }
    let mut last = input.next().unwrap();
    last.append(1).unwrap()[0] = 42;
    let pointer = last.raw;
    let rejected = batch.try_push(last).unwrap_err();
    assert_eq!(rejected.raw, pointer);
    assert_eq!(rejected.raw_data(), &[42]);
    assert_eq!(batch.len(), 3);
    assert_eq!(available(&pool), 3);
    drop(batch);
    assert_eq!(available(&pool), 6);
    drop(rejected);
    assert_eq!(available(&pool), 7);
}

#[test]
fn a_zero_capacity_batch_returns_the_mbuf() {
    let pool = packet_pool(7);
    let mbuf = pool.alloc_bulk(1).unwrap().into_iter().next().unwrap();
    let mut batch = MbufArray::<0>::default();
    let rejected = batch.try_push(mbuf).unwrap_err();
    drop(batch);
    assert_eq!(available(&pool), 6);
    drop(rejected);
    assert_eq!(available(&pool), 7);
}

#[test]
fn borrowing_a_batch_preserves_ownership_and_packet_order() {
    let pool = packet_pool(7);
    let mut batch = pool.alloc_bulk(3).unwrap();
    for (id, mbuf) in (&mut batch).into_iter().enumerate() {
        mbuf.append(1).unwrap()[0] = id as u8;
    }
    batch.swap(0, 2);
    let values: Vec<_> = (&batch)
        .into_iter()
        .map(|mbuf| mbuf.raw_data()[0])
        .collect();
    assert_eq!(values, [2, 1, 0]);
    assert_eq!(available(&pool), 4);
    drop(batch);
    assert_eq!(available(&pool), 7);
}

#[test]
fn dropping_a_mixed_batch_returns_mbufs_to_their_own_pools() {
    let left = packet_pool(7);
    let right = packet_pool(7);
    let mut batch = MbufArray::<6>::default();
    for (a, b) in left
        .alloc_bulk(3)
        .unwrap()
        .into_iter()
        .zip(right.alloc_bulk(3).unwrap())
    {
        batch.try_push(a).unwrap();
        batch.try_push(b).unwrap();
    }
    assert_eq!(available(&left), 4);
    assert_eq!(available(&right), 4);
    drop(batch);
    assert_eq!(available(&left), 7);
    assert_eq!(available(&right), 7);
}
