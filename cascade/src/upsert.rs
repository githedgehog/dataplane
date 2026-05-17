// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The upsert algebra used by the cascade.
//!
//! [`Upsert`] is the load-bearing trait for combining concurrent
//! writes against the same key in the head, for fusing sealed
//! intermediate layers, and for merging drained diffs into a
//! consumer's pending state.  All three are the same operation.
//!
//! The trait is named **`Upsert`** (rather than the previous
//! `Absorb`) because the semantic is literally upsert: when a key
//! is observed for the first time, [`seed`](Upsert::seed)
//! constructs the value from the op; on every subsequent write,
//! [`upsert`](Upsert::upsert) folds the new op into the existing
//! value.  This also avoids name overlap with the `left-right`
//! crate's `Absorb` trait, which has different contractual
//! obligations.
//!
//! # The contract
//!
//! The trait's *signature* requires nothing beyond a `&mut Self`
//! and an `Op`.  The *semantic* contract is that the function the
//! implementer writes must be **commutative and associative** over
//! the [`Op`](Upsert::Op) values the user supplies.
//!
//! Concretely: for any sequence of ops `o1, o2, ..., on` applied
//! to the same seed value via repeated calls to
//! [`upsert`](Upsert::upsert), the resulting state must be
//! identical regardless of arrival order or grouping.  Concurrent
//! writers in the head can interleave their writes arbitrarily,
//! so the implementer must arrange for that interleaving to
//! converge.
//!
//! Violating the contract does not corrupt memory or trip a
//! soundness invariant -- it produces *non-determinism*, the same
//! way violating [`PartialOrd`](::core::cmp::PartialOrd)'s
//! antisymmetry produces nonsensical sort orderings.  The result
//! is wrong-but-not-unsound state.
//!
//! # Upholding the contract
//!
//! The trait does not enforce the property because the property
//! cannot be expressed at the type level in plain Rust.  Two
//! common techniques:
//!
//! - **[`LastWriteWins<V>`]**: a provided wrapper that carries a
//!   monotone version counter and resolves concurrent writes by
//!   "highest version wins".  Trivially satisfies the contract.
//!   Recommended whenever the per-key semantic is "store the most
//!   recent value."
//! - **Application-specific merge** for value types that actually
//!   need to compose (state machines, counters with sum-merge,
//!   timestamps with max-merge).  Write the [`Upsert`] impl by
//!   hand, document the per-op merge rule, and ideally property-
//!   test it against random op sequences.
//!
//! See the crate-level `tests/` directory for the standard
//! property test harness.

use core::fmt;

/// Insert-or-update a value of `Self` from an [`Op`](Upsert::Op).
///
/// See the module docs for the semantic contract.
pub trait Upsert {
    /// The operation that drives state change.  For "replace"-style
    /// data, `Op` is typically just a wrapper around the new value.
    /// For composed data, `Op` is a richer enum describing what
    /// kind of change is being applied.
    type Op;

    /// Apply `op` to `self`.  Implementations must be commutative
    /// and associative across the set of `op` values the user
    /// supplies.
    fn upsert(&mut self, op: Self::Op);

    /// Construct the initial value from the first op observed for
    /// a key.  Used when the head sees a key for the first time --
    /// there is no existing value to upsert into, so the op itself
    /// must seed one.
    fn seed(op: Self::Op) -> Self
    where
        Self: Sized;
}

/// Trivial last-writer-wins wrapper.
///
/// `LastWriteWins<V>` carries a monotone version and resolves
/// concurrent writes by keeping the value associated with the
/// highest version observed.  Commutativity and associativity hold
/// trivially: `max` is both.
///
/// The version space is the user's responsibility.  Single-writer
/// control plane: just a counter.  Multi-writer dataplane: a
/// Lamport clock or a `(writer_id, counter)` tuple cast to `u128`.
/// Ties on `version` are broken by keeping the existing value (no
/// reason to copy if the version did not advance).
///
/// # Example
///
/// ```
/// use dataplane_cascade::LastWriteWins;
/// use dataplane_cascade::Upsert;
///
/// let mut v = LastWriteWins::<&'static str>::seed(LastWriteWins {
///     version: 1,
///     value: "old",
/// });
/// v.upsert(LastWriteWins { version: 2, value: "new" });
/// assert_eq!(v.value, "new");
/// // Out-of-order arrival: older op does not roll back state.
/// v.upsert(LastWriteWins { version: 1, value: "ancient" });
/// assert_eq!(v.value, "new");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastWriteWins<V> {
    pub version: u64,
    pub value: V,
}

impl<V> Upsert for LastWriteWins<V> {
    type Op = LastWriteWins<V>;

    fn upsert(&mut self, op: Self::Op) {
        if op.version > self.version {
            *self = op;
        }
    }

    fn seed(op: Self::Op) -> Self {
        op
    }
}

impl<V: fmt::Display> fmt::Display for LastWriteWins<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@v{}", self.value, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_write_wins_is_commutative() {
        let a = LastWriteWins {
            version: 1,
            value: 100,
        };
        let b = LastWriteWins {
            version: 2,
            value: 200,
        };
        let c = LastWriteWins {
            version: 3,
            value: 300,
        };

        for order in [
            [a, b, c],
            [a, c, b],
            [b, a, c],
            [b, c, a],
            [c, a, b],
            [c, b, a],
        ] {
            let mut state = LastWriteWins::<u32>::seed(order[0]);
            state.upsert(order[1]);
            state.upsert(order[2]);
            assert_eq!(state.value, 300);
            assert_eq!(state.version, 3);
        }
    }

    #[test]
    fn last_write_wins_tie_keeps_existing() {
        let mut state = LastWriteWins::<u32>::seed(LastWriteWins {
            version: 5,
            value: 100,
        });
        state.upsert(LastWriteWins {
            version: 5,
            value: 999,
        });
        assert_eq!(state.value, 100);
    }
}
