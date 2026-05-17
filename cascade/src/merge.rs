// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Type-encoded compaction logic.
//!
//! [`MergeInto<Target>`] is the trait that sealed layers implement
//! to declare \"here is how I fold myself into a tail of type
//! `Target`\".  The cascade's compactor walks the to-be-merged
//! sealed slice and folds each layer through `merge_into`, replacing
//! the tail with the result.
//!
//! # Why a trait instead of a closure
//!
//! The earlier shape passed a closure into
//! [`Cascade::compact`](crate::Cascade::compact).  That worked but
//! had three problems:
//!
//! - **Discoverability.**  Each call site wrote its own merge
//!   logic; new contributors could not `cargo doc` their way to the
//!   canonical merge for a given layer type.
//! - **Consistency.**  Two call sites could supply different
//!   closures.  The trait pins the merge to the layer type so all
//!   compactions use the same logic by construction.
//! - **Testing.**  A free-floating closure cannot be the subject of
//!   a trait-based property test.  Encoding merge in `MergeInto`
//!   lets us share an Absorb-laws-style harness across all
//!   implementations.
//!
//! # Algebraic expectations
//!
//! Implementations are expected to produce the same result
//! regardless of the order sealed layers were drained, *modulo* the
//! per-layer ordering enforced by the cascade's fold (oldest sealed
//! is merged first, then progressively newer).  The fold ordering
//! is fixed by the cascade walk semantic -- newer layers shadow
//! older ones -- so implementations should preserve that property
//! when they merge: newer entries should win on conflict.
//!
//! Concretely: if `target` already contains entry `(K, V_old)` and
//! `self` contains `(K, V_new)`, the result of `self.merge_into(&target)`
//! should contain `(K, V_new)`.  This mirrors how the cascade walk
//! returns `V_new` (from the higher-priority layer) over `V_old`
//! (from the tail).
//!
//! # Example
//!
//! ```ignore
//! impl MergeInto<MyTail> for MySealed {
//!     fn merge_into(&self, target: &MyTail) -> MyTail {
//!         let mut out = target.clone();
//!         for (k, v) in &self.entries {
//!             out.entries.insert(*k, *v);  // newer wins
//!         }
//!         out
//!     }
//! }
//! ```

/// Fold `self` into a copy of `target`, producing a new `Target`.
///
/// Called by [`Cascade::compact`](crate::Cascade::compact) once per
/// sealed layer being merged.  The cascade folds oldest sealed
/// first; each call accumulates onto the previous merge's result.
///
/// # Contract
///
/// - Implementations must treat `self` as taking precedence over
///   `target` on conflicts.  This mirrors the cascade walk's
///   newer-shadows-older semantic.
/// - Implementations must not panic on entries that exist only in
///   `target` (those are kept) or only in `self` (those are added).
/// - The returned value's lookup behaviour for any key should match
///   the cascade walk's behaviour over `[self, target]` -- if the
///   cascade walk would have returned `V` for some key, the merged
///   value should also return `V` for that key.
pub trait MergeInto<Target> {
    /// Produce a new `Target` containing `target`'s entries
    /// overlaid with `self`'s entries (with `self`'s entries
    /// winning on conflict).
    fn merge_into(&self, target: &Target) -> Target;
}
