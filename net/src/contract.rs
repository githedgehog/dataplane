//! Contract / property testing helpers

use proptest::prelude::Strategy;

/// Generate _valid_ instances of a type.
pub trait TypeGenerator {
    /// Return a proptest strategy which always upholds the invariants of Self.
    fn generate_valid() -> impl Strategy<Value = Self>;
}

/// Describe the invariants of a type.
pub trait CheckTypeContract {
    /// Asserts _all_ invariants on Self.
    ///
    /// # Panics
    ///
    /// This should never panic if
    ///
    /// 1. This type is implemented correctly.
    /// 2. No unsafe methods have been used to violate any invariant constraints.
    ///
    /// This type should **_always_** panic if any invariants of this type have been violated.
    fn check_type_contract(&self);
}
