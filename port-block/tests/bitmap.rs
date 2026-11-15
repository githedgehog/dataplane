// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The proofs cover the source as Verus sees it.  These run the code `cargo`
//! actually compiles, against a plain model, to cover what the proofs trust:
//! vstd's specification of `u64::trailing_ones`, ghost erasure, and the
//! verifier itself.

#![allow(clippy::unwrap_used)]

use dataplane_port_block::bitmap::{Bitmap256, Conflict};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, bolero::TypeGenerator)]
enum Op {
    Allocate,
    Reserve(u8),
    Release(u8),
    ReserveRange(u8, u8),
}

/// Against a `BTreeSet` of used offsets: every operation agrees with the set,
/// and allocation always takes the lowest free offset.
#[test]
fn the_bitmap_agrees_with_a_set() {
    bolero::check!().with_type::<Vec<Op>>().for_each(|ops| {
        let mut bitmap = Bitmap256::new();
        let mut model = BTreeSet::<u8>::new();
        for op in ops {
            match *op {
                Op::Allocate => {
                    let lowest_free = (0..=u8::MAX).find(|o| !model.contains(o));
                    assert_eq!(bitmap.allocate(), lowest_free);
                    if let Some(o) = lowest_free {
                        model.insert(o);
                    }
                }
                Op::Reserve(o) => {
                    let expect = if model.insert(o) {
                        Ok(())
                    } else {
                        Err(Conflict::AlreadyAllocated)
                    };
                    assert_eq!(bitmap.reserve(o), expect);
                }
                Op::Release(o) => {
                    let expect = if model.remove(&o) {
                        Ok(())
                    } else {
                        Err(Conflict::NotAllocated)
                    };
                    assert_eq!(bitmap.release(o), expect);
                }
                Op::ReserveRange(a, b) => {
                    let (start, end) = (a.min(b), a.max(b));
                    bitmap.reserve_range(start, end);
                    model.extend(start..=end);
                }
            }
            for o in 0..=u8::MAX {
                assert_eq!(bitmap.contains(o), model.contains(&o), "offset {o}");
            }
            assert_eq!(bitmap.is_full(), model.len() == 256);
        }
    });
}

/// `for_block` marks exactly the claimed ports that fall inside the block.
#[test]
fn for_block_marks_exactly_the_claimed_ports() {
    bolero::check!()
        .with_type::<(u8, Vec<(u16, u16)>, bool)>()
        .for_each(|(block, claims, reserve_null)| {
            let base = u16::from(*block) * 256;
            let bitmap = Bitmap256::for_block(base, claims, *reserve_null);
            for o in 0..=u8::MAX {
                let port = base + u16::from(o);
                let expect = (*reserve_null && port == 0)
                    || claims.iter().any(|&(lo, hi)| lo <= port && port <= hi);
                assert_eq!(bitmap.contains(o), expect, "port {port}");
            }
        });
}
