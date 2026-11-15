// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The pool's proof covers every interleaving, under sequentially consistent
//! atomics.  This runs the compiled code on real threads, as a check on what
//! the proof trusts (vstd's atomics, ghost erasure, the verifier).

#![allow(clippy::unwrap_used)]

use dataplane_port_block::pool::BlockPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

#[test]
fn a_new_pool_is_all_free() {
    for total in [0, 1, 4, 256] {
        let pool = BlockPool::new(total);
        assert_eq!(usize::from(pool.usable()), total);
    }
}

#[test]
fn claiming_and_releasing_moves_the_count() {
    let pool = BlockPool::new(4);
    let a = pool.try_claim(2).unwrap();
    assert_eq!(a.index(), 2);
    assert!(pool.try_claim(2).is_none(), "block 2 was claimed twice");
    assert_eq!(pool.usable(), 3);
    let b = pool.claim_any(2).unwrap();
    assert_eq!(b.index(), 3, "claim_any should take the next free block");
    assert_eq!(pool.usable(), 2);
    pool.release(a);
    assert_eq!(pool.usable(), 3);
    pool.release(b);
    assert_eq!(pool.usable(), 4);
}

/// Workers fight over one block while an observer watches the count.  Each
/// worker owns the block alone between claim and release, and the count never
/// leaves `0..=1`.
#[test]
fn one_block_many_workers() {
    const WORKERS: usize = 4;
    const ROUNDS: usize = 20_000;
    let pool = BlockPool::new(1);
    let held = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    thread::scope(|s| {
        s.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                assert!(pool.usable() <= 1);
            }
        });
        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                s.spawn(|| {
                    for _ in 0..ROUNDS {
                        if let Some(block) = pool.try_claim(0) {
                            assert!(!held.swap(true, Ordering::SeqCst), "two owners");
                            held.store(false, Ordering::SeqCst);
                            pool.release(block);
                        }
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        done.store(true, Ordering::Relaxed);
    });
    assert_eq!(pool.usable(), 1);
}
