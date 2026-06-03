// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::expect_used)]

use bolero::TypeGenerator;

use dataplane_cascade::property_tests::check_upsert_order_independent;
use dataplane_cascade::{LastWriteWins, Upsert};
#[derive(Debug, Clone, PartialEq, Eq, TypeGenerator)]
struct LwwOp(LwwOpInner);

#[derive(Debug, Clone, PartialEq, Eq, TypeGenerator)]
struct LwwOpInner {
    version: u32,
    value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Wrapped(LastWriteWins<u32>);

impl Upsert for Wrapped {
    type Op = LwwOp;

    fn upsert(&mut self, op: Self::Op) {
        self.0.upsert(LastWriteWins {
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
    check_upsert_order_independent::<Wrapped>();
}
