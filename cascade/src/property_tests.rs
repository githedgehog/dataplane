// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reusable property-test harness for cascade-related traits.
//!
//! Consumer crates implementing [`Upsert`](crate::Upsert) on their
//! own value types can verify the algebraic laws by calling these
//! functions from their own `#[test]` bodies, provided they (a)
//! enable the `bolero` feature on `dataplane-cascade`, and (b)
//! supply `bolero::TypeGenerator` for the relevant `Op` type.
//!
//! # Coverage caveat
//!
//! These laws are only exercised over values the user's
//! [`TypeGenerator`](bolero::TypeGenerator) impl produces.  A
//! generator that only produces "easy" ops (one variant, no edge
//! cases) will pass the laws trivially without actually testing the
//! merge logic.  Make sure the generator covers the operation space
//! the runtime can produce -- in particular, every variant of an
//! enum-shaped `Op` should be reachable.  The net crate's tests
//! are the workspace's quality reference here.
//!
//! # What the harness checks
//!
//! - [`check_upsert_order_independent`] -- `Upsert` is commutative
//!   and associative across the user-supplied ops.  For any
//!   sequence of three ops applied to the same seed, all 6
//!   orderings produce the same final state.
//!
//! Future additions will cover drain fidelity (a drained diff is
//! a faithful representation of the head's state delta) and
//! round-trip through serialization (the wire format preserves
//! the diff under replay).  Those need the drain machinery to be
//! in place first.

use core::fmt::Debug;

use bolero::TypeGenerator;

use crate::Upsert;

/// Property: applying a fixed multiset of ops to the same seed in
/// any order yields the same final state.
///
/// Concretely: for every 3-tuple of ops `(a, b, c)` produced by the
/// user's generator, this checks that all 6 orderings -- `(a,b,c)`,
/// `(a,c,b)`, `(b,a,c)`, `(b,c,a)`, `(c,a,b)`, `(c,b,a)` -- starting
/// from `seed(first_op)` and upserting the rest, converge to the
/// same `V`.
///
/// This subsumes both commutativity (pairwise reorderings agree)
/// and associativity (regroupings agree).  Failures usually mean
/// the [`Upsert`] impl is missing a per-op monotone tiebreaker; the
/// fix is typically the [`LastWriteWins`](crate::LastWriteWins)
/// wrapper or a similar version-counter discipline.
///
/// # Test sizing
///
/// Bolero's default budget (1024 iterations by default in `cargo
/// test`; higher under `cargo bolero test`) is usually sufficient
/// to catch non-commutativity in any reasonable generator.  Tighter
/// budgets miss subtle interleavings.
///
/// # Panics
///
/// Panics when the [`Upsert`] impl violates order independence --
/// the panic message identifies the canonical and divergent
/// orderings plus the op triple that produced the divergence.
/// This is the intended failure mode of the test.
///
/// # Example
///
/// ```ignore
/// use dataplane_cascade::property_tests::check_upsert_order_independent;
///
/// #[test]
/// fn flow_entry_upsert_is_order_independent() {
///     check_upsert_order_independent::<FlowEntry>();
/// }
/// ```
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
