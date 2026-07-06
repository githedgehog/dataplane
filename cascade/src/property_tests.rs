// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use core::fmt::Debug;

use bolero::TypeGenerator;

use crate::Upsert;
pub fn check_upsert_order_independent<V>()
where
    V: Upsert + Clone + PartialEq + Debug + 'static,
    V::Op: TypeGenerator + Clone + Debug + 'static,
{
    bolero::check!()
        .with_type::<[V::Op; 3]>()
        .for_each(|ops: &[V::Op; 3]| {
            let canonical = apply_in_order::<V>(ops, [0, 1, 2]);
            for perm in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
                let alt = apply_in_order::<V>(ops, perm);
                assert_eq!(
                    alt, canonical,
                    "Upsert violates order independence: \
                     canonical order [0,1,2] -> {canonical:?} but \
                     order {perm:?} -> {alt:?} for ops {ops:?}"
                );
            }
        });
}

fn apply_in_order<V>(ops: &[V::Op; 3], order: [usize; 3]) -> V
where
    V: Upsert,
    V::Op: Clone,
{
    let mut state = V::seed(ops[order[0]].clone());
    state.upsert(ops[order[1]].clone());
    state.upsert(ops[order[2]].clone());
    state
}
