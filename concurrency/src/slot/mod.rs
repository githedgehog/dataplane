//! Single-slot atomic publication.
//!
//! In production this is `arc_swap::ArcSwap` -- lock-free read fast path,
//! which is what makes [`Subscriber::snapshot`] cheap on the data-plane.
//!
//! When the `loom` or `shuttle` feature is enabled (via the
//! `concurrency` crate) it falls back to `Mutex<Arc<T>>` because neither
//! model checker sees `arc_swap`'s internals (hazard pointers + lower-
//! level atomics).  The two implementations are observably equivalent
//! for the QSBR protocol -- atomic publish, atomic load -- which is all
//! the model checker needs to see.
//!
//! Strict provenance checks fail with arc-swap since it uses hazard pointers
//! and does not (yet) use the new std features to expose provenance
//! information in their mechanics. As a result, we can still check for
//! provenance violations in this crate, but only with the Mutex based
//! fallback implementation.

cfg_select! {
    dataplane_concurrency_slot = "default" => {
        mod standard;
        #[doc(inline)]
        pub use standard::*;
    }
    _ => {
        mod fallback;
        #[doc(inline)]
        pub use fallback::*;
    }
}
