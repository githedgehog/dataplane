// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Self-test for the property harness.
//!
//! Exercises `check_absorb_order_independent` against the provided
//! [`LastWriteWins`] wrapper, which we know is correct by
//! construction.  If this test fails, the harness itself is
//! broken; if it passes, the harness is a useful black-box check
//! for consumer `Absorb` impls.
//!
//! The test does *not* try to construct a deliberately broken
//! `Absorb` impl to confirm the harness catches violations -- that
//! kind of negative test is hostile to property frameworks because
//! the "expected failure" depends on which counter-example the
//! generator happens to produce on a given run.  The positive
//! self-test is enough for confidence here; broken impls in
//! consumer crates will surface as failed property runs in those
//! crates.

#![allow(clippy::expect_used)]

use bolero::TypeGenerator;

use dataplane_cascade::property_tests::check_absorb_order_independent;
use dataplane_cascade::{Absorb, LastWriteWins};

// Wrapper type so we can implement `TypeGenerator` on
// `LastWriteWins<u32>`'s Op without orphan-rule trouble.
#[derive(Debug, Clone, PartialEq, Eq, TypeGenerator)]
struct LwwOp(LwwOpInner);

#[derive(Debug, Clone, PartialEq, Eq, TypeGenerator)]
struct LwwOpInner {
    version: u32, // narrower than u64 so generator hits collisions
    value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Wrapped(LastWriteWins<u32>);

impl Absorb for Wrapped {
    type Op = LwwOp;

    fn absorb(&mut self, op: Self::Op) {
        self.0.absorb(LastWriteWins {
            version: u64::from(op.0.version),
            value: op.0.value,
        });
    }

    fn seed(op: Self::Op) -> Self {
        Wrapped(LastWriteWins {
            version: u64::from(op.0.version),
            value: op.0.value,
        })
    }
}

#[test]
fn last_write_wins_satisfies_order_independence() {
    check_absorb_order_independent::<Wrapped>();
}
