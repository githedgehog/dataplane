// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Direct coverage for the `concurrency::sync::Arc<T>` wrapper and
//! `Weak<T>` shim.
//!
//! Loom 0.7 does not ship `Weak<T>` and does not give `loom::sync::Arc`
//! an associated `downgrade` function. The crate adds both as a thin
//! wrapper around `loom::sync::Arc` (see `concurrency/src/sync/test_facade.rs`).
//! Because the shim is custom code -- not a re-export -- it needs its
//! own test coverage; otherwise the only thing exercising it is
//! `quiescent_model.rs`, which uses it as a building block and would
//! surface failures as misbehaving QSBR tests rather than as
//! localised shim bugs.
//!
//! Run under loom with:
//!
//! ```sh
//! cargo test --release -p dataplane-concurrency --features loom --test arc_weak
//! ```
//!
//! The tests also pass on the default and shuttle backends -- the
//! contract is the same; only the *internals* of `Arc`/`Weak` differ.
//! Documented quirks of the loom shim (e.g. `Weak::upgrade` succeeds
//! even after the last `Arc` drop, `weak_count` is always `0`) have
//! tests gated to `concurrency = "loom"` to avoid asserting on real
//! `std::sync` / `shuttle::sync` semantics.
//!
//! `shuttle_pct` is opted out at file level: PCT is for biasing toward
//! rare interleavings of concurrent code, but most of the tests in this
//! file are protocol-level checks on `Arc` / `Weak` and either run on a
//! single thread or only briefly spawn a helper. PCT panics on bodies
//! that do not exercise sustained concurrency on the main thread, and
//! the contract being tested here is identical to what the plain
//! `shuttle` (random) variant already covers.

#![cfg(not(feature = "shuttle_pct"))]

// `#[concurrency::test]` is provided by `dataplane-concurrency`; alias
// the crate so the macro path resolves inside this integration test.
extern crate dataplane_concurrency as concurrency;

use dataplane_concurrency::sync::Arc;
use dataplane_concurrency::sync::atomic::{AtomicUsize, Ordering};
use dataplane_concurrency::sync::{Mutex, Weak};
use dataplane_concurrency::thread;

#[concurrency::test]
fn arc_new_strong_count_is_one() {
    let a = Arc::new(42u32);
    assert_eq!(Arc::strong_count(&a), 1);
}

#[concurrency::test]
fn arc_clone_then_drop_round_trips_strong_count() {
    let a = Arc::new(42u32);
    let b = a.clone();
    assert!(Arc::strong_count(&a) >= 2);
    drop(b);
    // After `b` drops, `a` is the only remaining strong (modulo any
    // `Weak`-quirk count contributions, none here).
    assert_eq!(Arc::strong_count(&a), 1);
}

#[concurrency::test]
fn arc_ptr_eq_same_allocation_is_true() {
    let a = Arc::new(42u32);
    let b = a.clone();
    assert!(Arc::ptr_eq(&a, &b));
}

#[concurrency::test]
fn arc_ptr_eq_different_allocations_is_false() {
    let a = Arc::new(42u32);
    let b = Arc::new(42u32);
    assert!(!Arc::ptr_eq(&a, &b));
}

#[concurrency::test]
fn weak_new_upgrades_to_none() {
    let w: Weak<u32> = Weak::new();
    assert!(w.upgrade().is_none());
}

#[concurrency::test]
fn arc_downgrade_then_upgrade_returns_value() {
    let a = Arc::new(42u32);
    let w = Arc::downgrade(&a);
    let upgraded = w.upgrade().expect("upgrade of fresh weak should succeed");
    assert_eq!(*upgraded, 42);
}

#[concurrency::test]
fn arc_new_uninit_then_assume_init_round_trip() {
    let mut uninit: Arc<core::mem::MaybeUninit<u32>> = Arc::new_uninit();
    let slot = Arc::get_mut(&mut uninit).expect("sole strong reference");
    slot.write(42);
    // SAFETY: just initialised via `write`.
    #[allow(unsafe_code)]
    let init = unsafe { uninit.assume_init() };
    assert_eq!(*init, 42);
}

#[concurrency::test]
fn weak_into_raw_from_raw_round_trips() {
    let a = Arc::new(42u32);
    let w = Arc::downgrade(&a);
    let raw = w.into_raw();
    // SAFETY: `a` is still alive, so `raw` points at a live allocation.
    #[allow(unsafe_code)]
    let value = unsafe { *raw };
    assert_eq!(value, 42);
    // SAFETY: `raw` came from `Weak::into_raw`, never used elsewhere.
    #[allow(unsafe_code)]
    let recovered = unsafe { Weak::from_raw(raw) };
    let upgraded = recovered.upgrade().expect("upgrade after round-trip");
    assert_eq!(*upgraded, 42);
}

#[concurrency::test]
fn arc_display_forwards_to_inner() {
    let a = Arc::new(42u32);
    assert_eq!(format!("{a}"), "42");
}

#[concurrency::test]
fn arc_pointer_format_yields_address() {
    let a = Arc::new(42u32);
    // The exact representation is `0x...` on every platform we
    // target; just check the format is non-empty and starts with `0x`.
    let p = format!("{a:p}");
    assert!(p.starts_with("0x"), "pointer format unexpected: {p}");
}

// ---------- documented-quirk tests (loom-only) ----------

/// Under the loom shim, `Weak` holds a strong clone of the inner
/// `loom::sync::Arc`, so `upgrade` succeeds even after every original
/// `Arc` has dropped. This is the documented limitation explained in
/// the module-level docs of `concurrency/src/sync/loom_backend.rs`;
/// the test pins the behaviour so a future "real `Weak`"
/// implementation fails this test loudly rather than silently
/// changing semantics.
#[cfg(feature = "loom")]
#[concurrency::test]
fn loom_quirk_weak_keeps_strong_alive() {
    let a = Arc::new(42u32);
    let w = Arc::downgrade(&a);
    drop(a);
    // Under real `std::sync::Weak` semantics, this would be `None`.
    // Under the loom shim, the `Weak` itself holds a strong clone.
    let upgraded = w.upgrade().expect("loom shim quirk: Weak keeps strong");
    assert_eq!(*upgraded, 42);
}

// ---------- multi-thread (loom multiplies via scheduling) ----------

/// Two threads each clone, read, and drop independent `Arc` clones.
/// Loom explores all interleavings of the strong-count operations.
#[concurrency::test]
fn two_threads_clone_and_drop_independently() {
    let a = Arc::new(42u32);
    let a1 = a.clone();
    let a2 = a.clone();
    let h1 = thread::spawn(move || {
        assert_eq!(*a1, 42);
    });
    let h2 = thread::spawn(move || {
        assert_eq!(*a2, 42);
    });
    h1.join().unwrap();
    h2.join().unwrap();
    // After the spawned threads have joined and dropped their
    // clones, only `a` remains.
    assert_eq!(Arc::strong_count(&a), 1);
}

/// A `Weak` registered in a `Mutex`-protected slot survives concurrent
/// reader access. This is a tiny analogue of the QSBR usage pattern in
/// `nat::stateful::apalloc`: a `Weak<T>` slot upgraded by a reader
/// thread while another thread holds an `Arc` to the value.
#[concurrency::test]
fn mutex_protected_weak_slot_upgrade() {
    let a = Arc::new(99u32);
    let slot: Arc<Mutex<Option<Weak<u32>>>> = Arc::new(Mutex::new(Some(Arc::downgrade(&a))));
    let slot_for_thread = Arc::clone(&slot);
    let read = Arc::new(AtomicUsize::new(0));
    let read_for_thread = Arc::clone(&read);
    let h = thread::spawn(move || {
        let guard = slot_for_thread.lock();
        if let Some(w) = guard.as_ref()
            && let Some(inner) = w.upgrade()
        {
            read_for_thread.store(*inner as usize, Ordering::SeqCst);
        }
    });
    h.join().unwrap();
    assert_eq!(read.load(Ordering::SeqCst), 99);
    drop(a);
}
