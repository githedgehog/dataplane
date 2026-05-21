// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::disallowed_types)]

//! Direct coverage for the `concurrency::sync::Arc<T>` wrapper and
//! `Weak<T>` shim.
//!
//! Loom 0.7 has no `Weak<T>`, so the facade's local shim gets direct
//! coverage here.
//!
//! `shuttle` is opted out at file level: the portfolio runs PCT
//! alongside Random, and most of these protocol checks cannot satisfy
//! PCT's concurrency requirement.

#![cfg(not(feature = "shuttle"))]

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

/// Pins the loom shim quirk: `Weak` keeps a strong clone alive.
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

/// A tiny analogue of the NAT allocator's `Weak<T>` slot pattern.
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
