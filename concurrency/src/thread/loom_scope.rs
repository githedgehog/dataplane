// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Loom-only `thread::scope` shim.
//!
//! Loom 0.7 does not ship `scope`. We provide one by storing every
//! spawned `JoinHandle` on the `Scope` itself and joining each handle
//! from the caller of `scope()` before returning. This mirrors what
//! `std::thread::scope` does internally (its `JoinInner::drop` joins the
//! OS thread before signaling the main thread): every spawned thread
//! is fully terminated -- including all its captured drops -- before
//! `scope()` returns, so any `'scope`-bounded borrow the thread held is
//! released *on the thread that joined*, never on the spawned thread
//! after `'scope` has ended.
//!
//! The shim's safety contract therefore matches std's: spawned closures
//! may borrow data of any lifetime that outlives the scope (`'env`).
//! Internally we lift the closure's `'scope` lifetime to `'static` with
//! a single `mem::transmute`, sound because of the join-before-return
//! guarantee.
//!
//! The keepalive trait object stored in `ScopeInner::pending` keeps its
//! honest `'scope` bound; the dropck-vs-HRTB tension that requires for
//! the closure transmute is resolved on this side by wrapping
//! `ScopeInner<'scope>` in `ManuallyDrop` so that `Scope`'s implicit
//! drop never destructs `'scope`-bearing data, and then explicitly
//! `ManuallyDrop::drop`ping the inner at the end of `scope()` while
//! `'scope` is still live. See the SAFETY comments at the manual-drop
//! site and at the closure transmute for details.
//!
//! Loom's `thread::spawn` is stricter than std's `spawn_unchecked` --
//! it requires `T: 'static` for the return type as well as the closure.
//! To accommodate, the spawned closure here is wrapped to return `()`
//! and write the user-visible `T` into an `Arc<Mutex<Option<T>>>` that
//! `ScopedJoinHandle::join` reads back. The wrapper itself returns `()`
//! so loom's `'static` bound is trivially satisfied.
//!
//! ## Why the `result_slot` is held in three places, and how drop
//! affinity is enforced
//!
//! Each call to [`Scope::spawn`] produces three references to the same
//! `Arc<Mutex<Option<T>>>`:
//!
//! 1. **The spawned thread's wrapper closure** writes the user's `T`
//!    into the slot when the user closure returns.
//! 2. **The user's [`ScopedJoinHandle`]** lets `.join()` take `T` out;
//!    if the handle is dropped without joining, its clone simply
//!    decrements the strong count.
//! 3. **The `Scope`'s slot keepalive** is a type-erased third clone
//!    held in `ScopeInner::pending`. The auto-join loop in `scope()`
//!    walks every pending entry, joins its `JoinHandle`, then calls
//!    `ResultKeepalive::take_payload` on the keepalive to extract the
//!    `T` and drop it **on the main thread**. The last `Arc` clone
//!    (which might be on the spawned thread, if loom's notify fired
//!    before the closure's capture-drop completed) then frees an empty
//!    `Mutex<Option<T>>` shell with nothing left to destruct.
//!
//! Earlier revisions tried to enforce drop affinity by asserting at
//! teardown that `strong_count == 1`. That works for `std::thread::
//! scope`, which synchronously waits for the spawned thread's full
//! termination (including capture drops), but not for loom: loom's
//! `JoinHandle::join` is satisfied by the spawned thread's `notify`,
//! which is sequenced *after* `f()` returns but *before* the runtime
//! has finished dropping the box that owned the closure's captures.
//! A schedule where main reaches the assertion in that window
//! observes `strong_count == 2`, so we drop the assertion and run the
//! extract-and-drop on main thread explicitly.

// The shim has two unsafe operations: (1) a `mem::transmute` that
// lifts the spawned closure's `'scope` lifetime to `'static`, since
// loom 0.7 has no `spawn_unchecked`; (2) an explicit
// `ManuallyDrop::drop` of the inner `ScopeInner<'scope>` at the end
// of `scope()`, which lets the keepalive trait objects keep their
// honest `'scope` bound while dropck does not see them at `scope`'s
// auto-drop. Both are sound because of the join-before-return
// contract; see the per-site SAFETY comments. The crate root denies
// `unsafe_code`, so allow it locally.
#![allow(unsafe_code)]
// The shim panics on internal invariant violations -- same as std's
// `thread::scope`. The crate root denies `clippy::panic`/`expect_used`;
// allow them locally.
#![allow(clippy::panic, clippy::expect_used)]
// `Scope::scope` field is a PhantomData invariance marker matching std's
// internal layout; the name aligns with the lifetime parameter, not a
// stylistic choice.
#![allow(clippy::struct_field_names)]

use core::marker::PhantomData;
use core::panic::AssertUnwindSafe;
use loom::sync::Arc;
use loom::thread::{self, JoinHandle};
use std::panic::{catch_unwind, resume_unwind};

use crate::sync::Mutex;

/// Shared slot for a `JoinHandle<()>` that may be claimed either by
/// the user via [`ScopedJoinHandle::join`] or by [`scope`]'s
/// auto-join loop -- whichever runs first takes it out. Both sides
/// hold an `Arc` clone of the same `Mutex<Option<JoinHandle<()>>>`.
type SharedJoinSlot = Arc<Mutex<Option<JoinHandle<()>>>>;

/// A scope for spawning threads that may borrow non-`'static` data.
///
/// Created by [`scope`]. Mirrors `std::thread::Scope`.
pub struct Scope<'scope, 'env: 'scope> {
    inner: Mutex<core::mem::ManuallyDrop<ScopeInner<'scope>>>,
    /// Invariance over `'scope` (matches std). Without it, `'scope`
    /// could shrink and the unsafe lifetime launder would be unsound.
    scope: PhantomData<&'scope mut &'scope ()>,
    env: PhantomData<&'env mut &'env ()>,
}

/// Trait-object behind which each spawn's `Arc<Mutex<Option<T>>>`
/// keepalive lives. Exists so the `scope()` teardown loop can call
/// `take_payload()` to extract the `T` and drop it on the main thread,
/// regardless of how many `Arc` clones remain on other threads.
trait ResultKeepalive: Send {
    /// Take the inner `Option<T>::take()`, dropping the contained `T`
    /// on the caller's thread (main, in `scope()`'s teardown loop).
    ///
    /// Drop-affinity is enforced by this take, not by `Arc` count: any
    /// remaining `Arc<Mutex<Option<T>>>` clones (e.g. a slow-dropping
    /// `result_for_thread` whose owning thread has notified-but-not-
    /// fully-exited) will then see an `Option<T>::None` and run no
    /// `T::Drop` of their own. The last `Arc` to drop frees the empty
    /// `Mutex<Option<T>>` shell, which has no `T` to destruct.
    fn take_payload(&self);
}

impl<T: Send> ResultKeepalive for Arc<Mutex<Option<T>>> {
    fn take_payload(&self) {
        let _ = self.lock().take();
    }
}

struct ScopeInner<'scope> {
    /// Pairs of `(shared_handle_slot, slot_keepalive)`. The keepalive
    /// is the third clone of each spawn's `Arc<Mutex<Option<T>>>`,
    /// behind a small `ResultKeepalive + 'scope` trait object. The
    /// `'scope` bound is honest: the inner `Arc<Mutex<Option<T>>>`
    /// holds a `T: 'scope`, and the Vec keeps the trait object alive
    /// until `scope()`'s teardown drops it (which happens before
    /// `'scope` ends).
    pending: Vec<(SharedJoinSlot, Box<dyn ResultKeepalive + 'scope>)>,
}

/// An owned handle to a thread spawned via [`Scope::spawn`].
///
/// Dropping the handle does **not** detach the thread -- the auto-join
/// in [`scope`] still waits for it. To collect the thread's result or
/// panic, call [`ScopedJoinHandle::join`] before [`scope`] returns.
pub struct ScopedJoinHandle<'scope, T> {
    /// Shared with `Scope::inner.pending`. Whoever calls
    /// `lock().take()` first claims the handle: `ScopedJoinHandle::join`
    /// in the user path, the teardown loop in `scope` otherwise.
    handle_slot: SharedJoinSlot,
    result: Arc<Mutex<Option<T>>>,
    _scope: PhantomData<&'scope ()>,
}

impl<T> ScopedJoinHandle<'_, T> {
    /// Wait for the spawned thread to finish and return its result.
    ///
    /// # Errors
    ///
    /// Returns `Err` with the panic payload if the spawned thread
    /// panicked. The surrounding [`scope`] will not double-panic in
    /// that case: an explicitly joined handle absorbs the panic.
    ///
    /// # Panics
    ///
    /// Panics if the handle slot or result slot is empty, which would
    /// indicate a double-join or a wrapper closure that never
    /// deposited its result. Both are internal invariant violations,
    /// not user-visible conditions.
    pub fn join(self) -> std::thread::Result<T> {
        let handle = self
            .handle_slot
            .lock()
            .take()
            .expect("scoped thread handle was already taken (double join?)");
        handle.join()?;
        Ok(self
            .result
            .lock()
            .take()
            .expect("scoped thread did not deposit its result"))
    }
}

/// Spawn scoped threads, joining all of them before returning.
///
/// See `std::thread::scope` for the full API contract. The shim matches
/// that contract under loom.
///
/// # Panics
///
/// Propagates any panic from `f` after all spawned threads have been
/// joined. If `f` itself didn't panic but any spawned thread did and
/// the panic was never absorbed by an explicit `.join()`, panics with
/// `"a scoped thread panicked"`.
pub fn scope<'env, F, T>(f: F) -> T
where
    F: for<'scope> FnOnce(&'scope Scope<'scope, 'env>) -> T,
{
    let scope = Scope {
        inner: Mutex::new(core::mem::ManuallyDrop::new(ScopeInner {
            pending: Vec::new(),
        })),
        scope: PhantomData,
        env: PhantomData,
    };

    // Run `f` inside `catch_unwind` so we can still wait for spawned
    // threads even if `f` panicked.
    let result = catch_unwind(AssertUnwindSafe(|| f(&scope)));

    // Drain pending entries. For each, try to claim the handle from
    // the shared slot; if it's `None`, the user already joined. Then
    // drop the keepalive, which (now that the spawned thread has
    // fully exited and dropped its own `Arc` clone of the result
    // slot) lets `T`'s destructor run on this -- the main -- thread.
    //
    // If a spawned thread panicked, capture the first panic payload so
    // we can `resume_unwind` it at the end -- matching `std::thread::scope`,
    // which preserves the spawned thread's original assertion/panic
    // message instead of synthesizing a generic one. We still join every
    // handle so subsequent panics' associated keepalives get dropped on
    // the main thread before we propagate.
    //
    // The drain is a loop, not a single take: a scoped thread can
    // itself call `s.spawn(...)` and push a new pending entry while
    // we're joining earlier ones. Taking `pending` once would leave
    // those nested handles unjoined and violate the
    // join-before-return contract the `'scope` -> `'static` lifetime
    // transmute relies on. Loop until the queue stays empty.
    let mut first_spawn_panic: Option<Box<dyn core::any::Any + Send + 'static>> = None;
    loop {
        let pending = core::mem::take(&mut scope.inner.lock().pending);
        if pending.is_empty() {
            break;
        }
        for (handle_slot, keepalive) in pending {
            if let Some(handle) = handle_slot.lock().take()
                && let Err(payload) = handle.join()
                && first_spawn_panic.is_none()
            {
                first_spawn_panic = Some(payload);
            }
            // Drop-affinity: explicitly take the `Option<T>` payload out
            // of the slot on this (the main) thread. `T::Drop` runs
            // here, regardless of how many `Arc` clones of the slot
            // still exist on other threads. The last `Arc` to drop
            // (possibly on the spawned thread, in some interleavings
            // where the spawned thread's wrapper has notified but
            // hasn't fully released its capture) then frees the empty
            // shell, which contains no `T` to destruct.
            //
            // This is stricter than std's `Drop` ordering (std relies
            // on `JoinHandle::join()` synchronously waiting for the
            // spawned thread to fully terminate, including capture
            // drops). loom's `JoinHandle::join` only synchronises on
            // the spawned thread's notify, which can fire before all
            // captures have dropped -- so we can't rely on the Arc
            // count being exactly 1 here.
            keepalive.take_payload();
            drop(keepalive);
        }
    }

    // SAFETY: `scope.inner` wraps `ScopeInner<'scope>` in
    // `ManuallyDrop` so that the auto-drop of `scope` (a local
    // bound by the function block's lifetime) does not destruct
    // `'scope`-bearing data -- that would force `'scope` to
    // outlive `scope`, but `'scope` is fixed by the HRTB-chosen
    // borrow at `f(&scope)` and is necessarily shorter than
    // `scope`'s local lifetime. We are still inside `scope()`'s
    // body here, so `'scope` is alive, the explicit
    // `ManuallyDrop::drop` is the correct place to release the
    // (now-emptied) `Vec` allocation. The inner is never accessed
    // again after this point: the function only matches `result`
    // and returns. Loom 0.7's leak check at the end of each
    // `loom::model` iteration would otherwise flag the leaked
    // allocation.
    unsafe {
        core::mem::ManuallyDrop::drop(&mut scope.inner.lock());
    }

    match result {
        // The `f` body itself panicked. Its panic dominates (it's the
        // outermost frame), so propagate it. A spawned panic captured
        // in `first_spawn_panic` is silently dropped on this path,
        // matching std's behaviour.
        Err(e) => resume_unwind(e),
        // No body panic, but at least one spawned thread did. Resume the
        // first spawned panic with its original payload -- preserves
        // assertion messages and any other diagnostic carried in the
        // payload. (std does the same thing via JoinInner::drop +
        // a_thread_panicked.)
        Ok(_) if first_spawn_panic.is_some() => {
            resume_unwind(first_spawn_panic.expect("just checked"))
        }
        Ok(r) => r,
    }
}

impl<'scope> Scope<'scope, '_> {
    /// Spawn a thread within the scope.
    ///
    /// The closure may borrow data of any lifetime that outlives the
    /// scope (i.e. `'env`). The scope guarantees the thread is joined
    /// before [`scope`] returns, so those borrows remain valid for the
    /// duration of the thread.
    pub fn spawn<F, T>(&'scope self, f: F) -> ScopedJoinHandle<'scope, T>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        let result_slot: Arc<Mutex<Option<T>>> = Arc::new(Mutex::new(None));
        let result_for_thread = Arc::clone(&result_slot);
        // Third clone, kept alive by the Scope itself until after the
        // thread is joined. See module docs ("Why the result_slot is
        // held in three places").
        let result_keepalive = Arc::clone(&result_slot);

        let wrapped = move || {
            // Mirror std: catch the panic and resume so loom sees the
            // thread terminate with a panic. The scope's `pending`
            // loop will record the panic via `JoinHandle::join()`.
            //
            // `result_for_thread` (the spawned-thread Arc clone of the
            // result slot) is dropped implicitly when the closure body
            // exits.  We do not rely on that drop happening before
            // `scope()`'s teardown runs `T::Drop`; loom's `JoinHandle::
            // join` synchronises only on `notify`, which can fire before
            // the closure's captures have fully been released.
            // `scope()`'s teardown calls `take_payload` to drop the `T`
            // on the main thread regardless of the Arc count, which is
            // what the keepalive trait's contract guarantees.
            match catch_unwind(AssertUnwindSafe(f)) {
                Ok(v) => {
                    *result_for_thread.lock() = Some(v);
                }
                Err(e) => resume_unwind(e),
            }
        };

        // SAFETY: `loom::thread::spawn` requires `F: 'static` (no
        // `spawn_unchecked` is available in loom 0.7), so we have to
        // lifetime-launder the closure box from `'scope` to `'static`.
        // Soundness rests on the join-before-return contract: every
        // spawned thread is joined by `scope()`'s teardown loop before
        // `scope()` returns. By that time the closure has run, its
        // captures (including `result_for_thread`, the only capture
        // bound to `'scope`) have dropped, and the user-visible
        // `ScopedJoinHandle.result` has dropped (the handle's `'scope`
        // bound forces it). loom's `JoinHandle::join` synchronises on
        // `notify`, which the spawned thread emits after `f()` returns;
        // by that point the wrapper closure's captures are gone. The
        // `take_payload` step in the teardown loop additionally drops
        // any leftover `T` on the main thread, so even in interleavings
        // where the spawned thread's `Arc` clone of the result slot
        // outlives `notify`, `T::Drop` does not run on the spawned
        // thread. This is the same lifetime-launder pattern std uses
        // for `spawn_unchecked` internally.
        let wrapped: Box<dyn FnOnce() + Send + 'static> = unsafe {
            core::mem::transmute::<
                Box<dyn FnOnce() + Send + 'scope>,
                Box<dyn FnOnce() + Send + 'static>,
            >(Box::new(wrapped))
        };

        let join_handle = thread::spawn(wrapped);

        // Shared handle slot: `scope()` and the user's
        // `ScopedJoinHandle` both hold an `Arc` clone of the same
        // `Mutex<Option<JoinHandle<()>>>`. Whoever calls
        // `lock().take()` first claims the join.
        let handle_slot: SharedJoinSlot = Arc::new(Mutex::new(Some(join_handle)));
        let handle_for_scope = Arc::clone(&handle_slot);

        // No lifetime launder needed: `ScopeInner<'scope>` carries the
        // `'scope` parameter on the `Box<dyn ResultKeepalive + 'scope>`
        // it stores, so the trait object's lifetime is honest. The
        // for-all-`'scope` HRTB on `scope()`'s `F` resolves because
        // `Scope<'scope, 'env>` is already parameterised by `'scope`
        // and `'scope`'s invariance (the `PhantomData<&'scope mut
        // &'scope ()>`) keeps the chosen `'scope` from shrinking.
        let keepalive: Box<dyn ResultKeepalive + 'scope> = Box::new(result_keepalive);
        self.inner
            .lock()
            .pending
            .push((handle_for_scope, keepalive));

        ScopedJoinHandle {
            handle_slot,
            result: result_slot,
            _scope: PhantomData,
        }
    }
}
