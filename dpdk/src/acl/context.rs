// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL context with typestate lifecycle management.
//!
//! This module provides [`AclContext`], a safe RAII wrapper around DPDK's opaque
//! [`rte_acl_ctx`][dpdk_sys::rte_acl_ctx] handle.  The context uses a **typestate** pattern to
//! enforce the correct lifecycle at compile time:
//!
//! ```text
//! AclContext<N, Configuring>  --build()-->  AclContext<N, Built>
//!          ^                                         |
//!          +----------------reset()------------------+
//! ```
//!
//! - In the [`Configuring`] state you can add rules ([`add_rules`][AclContext::add_rules]) and
//!   compile them ([`build`][AclContext::build]).  Mutation methods take `&mut self`, which lets
//!   the Rust borrow checker enforce DPDK's documented constraint that these operations are **not
//!   thread-safe**.
//!
//! - In the [`Built`] state you can classify packets ([`classify`][AclContext::classify]).
//!   Classification takes `&self`, which -- combined with the `Sync` implementation -- allows safe
//!   concurrent access from multiple threads, matching DPDK's documented thread-safety guarantee
//!   for [`rte_acl_classify`][dpdk_sys::rte_acl_classify].
//!
//! The context is parameterised by a const generic `N` (the number of fields per rule).  This
//! same `N` appears in [`Rule<N>`][super::rule::Rule] and
//! [`AclBuildConfig<N>`][super::config::AclBuildConfig], so a field-count mismatch between rules
//! and context is caught at compile time.
//!
//! # RAII
//!
//! When an [`AclContext`] is dropped (in any state), it calls
//! [`rte_acl_free`][dpdk_sys::rte_acl_free] to release all DPDK-managed memory.
//!
//! # Examples
//!
//! See the [module-level documentation][super] for a complete usage example.

use core::fmt;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use concurrency::sync::{Mutex, OnceLock};
use errno::Errno;
use tracing::{debug, error, trace};

use super::classify::ClassifyAlgorithm;
use super::config::{AclBuildConfig, AclCreateParams};
use super::error::{
    AclAddRulesError, AclBuildError, AclClassifyError, AclCreateError, AclSetAlgorithmError,
};
use super::field::FieldDef;
use super::rule::Rule;

/// Process-wide guard for any operation that touches DPDK's global ACL
/// registry: [`AclContext::new`] (find_existing + create), [`Drop`] for
/// [`AclContext`] (free), and [`dump_all_contexts`] (list dump).
///
/// DPDK's `rte_acl_create` does not itself fail on duplicate names: it
/// returns the **existing** context pointer for a matching name.  Without
/// serialization, two threads can both observe
/// `rte_acl_find_existing -> NULL` for the same name, both call
/// `rte_acl_create`, and both receive the same pointer -- producing two
/// [`AclContext`] wrappers that race to free the same DPDK handle on drop.
/// Holding this mutex across the check-and-create sequence closes the TOCTOU.
/// Drop and list-dump take the same lock so the "registry-touching
/// operations are serialized" invariant holds at the wrapper seam.
///
/// Why [`OnceLock`] rather than a `static` initializer: under the
/// `loom`/`shuttle` model-checker backends, `concurrency::sync::Mutex::new`
/// is not `const fn` (each instance registers with the scheduler), so a
/// `static M: Mutex<()> = Mutex::new(())` would fail to typecheck on those
/// configurations.  `OnceLock` + lazy init is the portable idiom across
/// all backends.  See the module docs on `concurrency::sync`.
///
/// Why the concurrency facade rather than [`std::sync::Mutex`] directly:
/// the workspace policy is poison-as-panic ("poison is a fatal invariant
/// violation"); the facade applies that policy uniformly so call sites
/// never see `LockResult`.
///
/// # Tracing reentrancy
///
/// The lock is **not** reentrant.  Anything that runs while a thread holds
/// this lock -- including `tracing` layers invoked by the [`debug!`] /
/// [`error!`] / `#[tracing::instrument]` macros sprinkled through the
/// surrounding methods -- must not call back into any ACL wrapper API that
/// would re-acquire it: [`AclContext::new`], [`dump_all_contexts`], or
/// dropping any [`AclContext`].  Doing so deadlocks the calling thread on
/// its own previously-acquired guard.  The default `tracing-subscriber`
/// configuration never touches ACL, but custom layers (e.g. one that
/// resolves the context name from a registry lookup for log enrichment)
/// could trip this if added later.
static ACL_CREATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Lazy accessor for [`ACL_CREATE_LOCK`].
fn acl_create_lock() -> &'static Mutex<()> {
    ACL_CREATE_LOCK.get_or_init(|| Mutex::new(()))
}

// ---------------------------------------------------------------------------
// Typestate markers
// ---------------------------------------------------------------------------

/// Typestate: the context is accepting rule mutations and has not yet been compiled.
///
/// Methods available in this state:
/// - [`add_rules`][AclContext::add_rules] (`&mut self`)
/// - [`reset_rules`][AclContext::reset_rules] (`&mut self`)
/// - [`build`][AclContext::build] (consumes `self`, transitions to [`Built`])
///
/// Carries the [`AclBuildConfig<N>`] that the context was created with so
/// that [`add_rules`][AclContext::add_rules] can validate each
/// [`Rule<N>`]'s field values against the layout (catching e.g. an
/// out-of-range prefix length before it reaches DPDK's C shift in
/// `RTE_ACL_MASKLEN_TO_BITMASK`) and [`build`][AclContext::build] can
/// dispatch with no extra arguments.
#[derive(Debug, Clone)]
pub struct Configuring<const N: usize> {
    config: AclBuildConfig<N>,
}

/// Typestate: the context has been compiled and is ready for packet classification.
///
/// Methods available in this state:
/// - [`classify`][AclContext::classify] (`&self`, thread-safe)
/// - [`classify_with_algorithm`][AclContext::classify_with_algorithm] (`&self`, thread-safe)
/// - [`set_default_algorithm`][AclContext::set_default_algorithm] (`&mut self`)
/// - [`reset`][AclContext::reset] (consumes `self`, transitions back to [`Configuring`])
///
/// Carries the [`AclBuildConfig<N>`] that produced this build so that
/// downstream code can query the field layout and category count without
/// recomputing or re-passing it.  Read via
/// [`build_config`][AclContext::build_config].
#[derive(Debug, Clone)]
pub struct Built<const N: usize> {
    config: AclBuildConfig<N>,
}

/// Sealed marker trait for valid [`AclContext`] typestates.
///
/// Implemented for [`Configuring`] and [`Built<N>`].
///
/// `Send` is a supertrait because [`AclContext`] has a blanket `unsafe
/// impl<State: AclState> Send`; the supertrait guarantees the state's own
/// auto-trait obligations are respected (e.g. an internal typestate that
/// held an `Rc<_>` could not implement `AclState` at all, which is the
/// desired outcome).
///
/// `Sync` is deliberately **not** a supertrait.  Per-state `unsafe impl
/// Sync` blocks are the single audit gate: adding a new typestate
/// requires writing a fresh `unsafe impl Sync for AclContext<N, NewState>`
/// (or omitting it and getting a non-`Sync` context).  A `Sync` supertrait
/// would mean every state mechanically gains `Sync` just by satisfying
/// the trait bound, hiding the per-state audit.
pub trait AclState: sealed::Sealed + Send {}

mod sealed {
    /// Sealed-trait support for [`super::AclState`].  External crates cannot
    /// implement this trait, so they cannot add new typestates that would
    /// inherit [`Send`]/[`Sync`].
    pub trait Sealed {}
    impl<const N: usize> Sealed for super::Configuring<N> {}
    impl<const N: usize> Sealed for super::Built<N> {}
}

impl<const N: usize> AclState for Configuring<N> {}
impl<const N: usize> AclState for Built<N> {}

// ---------------------------------------------------------------------------
// Build failure
// ---------------------------------------------------------------------------

/// Returned when [`AclContext::build`] fails.
///
/// Because `build` consumes the [`Configuring`] context, this error wraps
/// **both** the error description and the original context so the caller can
/// recover, inspect, or drop it.  The returned context is still in
/// [`Configuring`] state and **retains any rules previously added via**
/// [`add_rules`][AclContext::add_rules] -- `build` does not call
/// `rte_acl_reset_rules` on failure.  Callers who want a clean slate must
/// invoke [`reset_rules`][AclContext::reset_rules] on the returned context.
///
/// # Example
///
/// ```ignore
/// match ctx.build() {
///     Ok(built) => { /* use built context */ }
///     Err(failure) => {
///         eprintln!("build failed: {}", failure.error);
///         // The original context is still usable; previously-added rules are
///         // still present.  Clear them if you want to retry from scratch:
///         let mut ctx = failure.context;
///         ctx.reset_rules();
///     }
/// }
/// ```
#[derive(thiserror::Error)]
#[error("ACL build failed for context '{}'", self.context.name())]
pub struct AclBuildFailure<const N: usize> {
    /// The build error.
    #[source]
    pub error: AclBuildError,
    /// The original context, returned in [`Configuring`] state so it can be reused or dropped.
    pub context: AclContext<N, Configuring<N>>,
}

// Hand-rolled Debug because `AclContext` does not derive `Debug` (and
// embedding the full context state in error logs would be noise).
impl<const N: usize> fmt::Debug for AclBuildFailure<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AclBuildFailure")
            .field("error", &self.error)
            .field("context_name", &self.context.name())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// AclContext
// ---------------------------------------------------------------------------

/// A DPDK ACL context parameterised by field count `N` and lifecycle state `State`.
///
/// See the [module documentation][self] for an overview of the typestate lifecycle.
///
/// # Type parameters
///
/// - `N`: the number of fields per rule.  Must match across [`Rule<N>`][super::rule::Rule],
///   [`AclBuildConfig<N>`][super::config::AclBuildConfig], and this context.
/// - `State`: one of [`Configuring`] or [`Built`].  Defaults to [`Configuring`] for newly created
///   contexts.
pub struct AclContext<const N: usize, State = Configuring<N>> {
    /// Raw DPDK context handle.  Non-null invariant maintained at all times.
    ctx: NonNull<dpdk_sys::rte_acl_ctx>,
    /// The validated parameters that were used to create this context.
    /// `AclCreateParams<N>` ties the field-count to the context's `N` so a
    /// mismatch is a compile-time error rather than UB at `rte_acl_add_rules`
    /// time.
    params: AclCreateParams<N>,
    /// Per-state data: both [`Configuring<N>`] and [`Built<N>`] carry the
    /// [`AclBuildConfig<N>`] (the [`Built`] copy is the one used by
    /// `rte_acl_build`; the [`Configuring`] copy is used to validate rules
    /// at `add_rules` time and is what `build` will pass to DPDK).
    state: State,
}

// The DPDK ACL context handle is a heap allocation -- it is not inherently tied to any particular
// thread, so `Send` is correct for any state that itself is `Send`.  The
// blanket `Send` impl across `State: AclState` is fine because the trait's
// `Send` supertrait already guarantees the per-state portion is `Send`.
unsafe impl<const N: usize, State: AclState> Send for AclContext<N, State> {}

// `Sync` is **not** blanket.  Each typestate must explicitly opt in with
// its own `unsafe impl` so that adding a new typestate forces the author
// to write a fresh reentrancy audit.  A blanket `impl<State: AclState>
// Sync` would let a new state silently inherit Sync just by implementing
// the (sealed) `AclState` supertrait -- which would obscure the audit
// requirement.
//
// The load-bearing claim for `Sync` is that **every method on AclContext
// reachable through a shared `&self` is reentrant** -- i.e. two threads
// each holding `&self` cannot race against each other through any safe
// API.  `Sync` already follows tautologically from `&mut self` discipline
// on the mutation methods; the non-trivial claim is what the `&self`
// methods do.
//
// `&self` methods reachable in any state ("all-states" impl on
// `AclContext<N, State>`) and their reentrancy story:
// - `name()`, `params()`, `as_raw_ptr()` -- read-only access to immutable
//   fields stored in the wrapper.  Trivially reentrant.
//
// `dump()` is explicitly **not** in the `&self` set: it takes `&mut self`,
// which sidesteps any reentrancy claim against `rte_acl_dump`'s
// implementation details.  Even though the current DPDK source only reads
// from the context inside `rte_acl_dump`, the `&mut self` borrow makes
// the argument robust against any future DPDK change that adds caching
// or other mutation inside the dump path.  See the `dump` doc for the
// rationale.  Listing `dump` here would be a documentation lie that
// could mislead a future reviewer into believing the `&self` Sync claim
// covered it.
//
// Cross-context registry mutation (Drop and `dump_all_contexts`) is
// protected by [`ACL_CREATE_LOCK`] at the Rust seam, so it does not
// participate in the per-context `&self` reentrancy story.

// Sync impl for the [`Configuring<N>`] state.
//
// `&self` methods reachable here are exactly the all-states ones above
// (`name`, `params`, `as_raw_ptr`).  No `Configuring`-specific `&self`
// method exists; all rule mutation, `dump`, and the `build` transition
// take `&mut self` / consume `self`, which `Sync` does not concern.
unsafe impl<const N: usize> Sync for AclContext<N, Configuring<N>> {}

// Sync impl for the [`Built<N>`] state.
//
// In addition to the all-states `&self` methods, `Built<N>` exposes
// `classify` / `classify_with_algorithm` (DPDK documents these as
// thread-safe), `build_config`/`num_categories`/`field_defs`
// (read-only accessors into the stored config).  All reentrant.
unsafe impl<const N: usize> Sync for AclContext<N, Built<N>> {}

// ---------------------------------------------------------------------------
// Methods available in ALL states
// ---------------------------------------------------------------------------

impl<const N: usize, State> AclContext<N, State> {
    /// Get the context name (as passed to [`AclCreateParams::new`]).
    #[must_use]
    #[inline]
    pub fn name(&self) -> &str {
        self.params.name()
    }

    /// Get the creation parameters.
    #[must_use]
    #[inline]
    pub fn params(&self) -> &AclCreateParams<N> {
        &self.params
    }

    /// Get the raw DPDK context pointer for read-only FFI.
    ///
    /// Returning a raw pointer is itself a safe operation; *using* the pointer
    /// in any FFI call is what is unsafe, and that obligation already lives on
    /// those FFI signatures.  Mirrors the safety story of
    /// [`Box::as_ptr`][core::ptr] and similar std accessors.
    ///
    /// For DPDK calls that take `*mut rte_acl_ctx` (e.g. `rte_acl_add_rules`,
    /// `rte_acl_reset`, `rte_acl_set_ctx_classify`), use
    /// [`as_raw_mut_ptr`][AclContext::as_raw_mut_ptr] instead so the
    /// `&mut self` requirement carries the typestate's mutability discipline
    /// into raw FFI code.
    ///
    /// # Lifetime
    ///
    /// The returned pointer is valid only while `self` is alive.  Raw pointers
    /// in Rust do **not** carry lifetimes, so the borrow checker will not catch
    /// use-after-free of this pointer past a [`Drop`] of the context.  Treat
    /// the result as borrowed from `&self`: pass it straight to the FFI call
    /// and do not hold it across moves or drops of the context.
    #[must_use]
    #[inline]
    pub fn as_raw_ptr(&self) -> *const dpdk_sys::rte_acl_ctx {
        self.ctx.as_ptr()
    }

    /// Get the raw DPDK context pointer for mutating FFI.
    ///
    /// Taking `&mut self` mirrors the typestate's mutability discipline: a
    /// caller cannot obtain a `*mut rte_acl_ctx` from a shared borrow of the
    /// context, preventing data races between concurrent
    /// `rte_acl_classify` (which takes `&self`) and any mutating FFI call
    /// the caller might make through this pointer.
    ///
    /// See [`as_raw_ptr`][AclContext::as_raw_ptr] for the lifetime caveat
    /// (raw pointers do not carry lifetimes in Rust; treat this one as
    /// borrowed from `&mut self`).
    #[must_use]
    #[inline]
    pub fn as_raw_mut_ptr(&mut self) -> *mut dpdk_sys::rte_acl_ctx {
        self.ctx.as_ptr()
    }

    /// Dump the context's internal state to stdout via
    /// [`rte_acl_dump`][dpdk_sys::rte_acl_dump].
    ///
    /// This is a debugging aid.  Output goes to stdout and is not captured
    /// by the tracing subsystem.  Under `cargo nextest`, stdout is captured
    /// per test and only surfaced on failure or with `--no-capture`; under
    /// `cargo test`, stdout is captured by default unless `--nocapture` is
    /// passed.  Either way, the output will not appear in the tracing
    /// stream -- redirect or run the harness with capture disabled if you
    /// need to read it interactively.
    ///
    /// # `&mut self`
    ///
    /// Takes `&mut self` rather than `&self` even though
    /// [`rte_acl_dump`][dpdk_sys::rte_acl_dump] is read-only on the
    /// current DPDK source.  The exclusive borrow side-steps a
    /// pin-to-DPDK-version reentrancy audit: any future change to DPDK
    /// that adds caching inside `rte_acl_dump` would silently invalidate
    /// a `&self` claim, but cannot affect `&mut self` (no other thread
    /// has access to the context for the duration of the call).
    #[cold]
    pub fn dump(&mut self) {
        // SAFETY: rte_acl_dump operates on the single context pointed
        // at by `self.ctx` and does not touch the global registry, so
        // no ACL_CREATE_LOCK acquisition is required.  The `&mut self`
        // borrow guarantees we have exclusive access to this context,
        // covering any future DPDK change that adds mutation inside
        // `rte_acl_dump`.
        unsafe { dpdk_sys::rte_acl_dump(self.ctx.as_ptr()) }
    }

    /// Decompose the context into its raw parts **without** running the destructor.
    ///
    /// Used internally to implement typestate transitions: the raw pointer,
    /// params, and per-state data are moved out, and [`ManuallyDrop`] prevents
    /// the old value's [`Drop`] from freeing the DPDK handle.
    fn into_parts(self) -> (NonNull<dpdk_sys::rte_acl_ctx>, AclCreateParams<N>, State) {
        let this = ManuallyDrop::new(self);
        let ctx = this.ctx;
        // SAFETY: `this` is wrapped in ManuallyDrop, so its Drop will not run
        // and the fields will not be double-freed when this function returns.
        // Moving `params` out via ptr::read yields exactly one owner of the
        // AclCreateParams<N>.
        let params = unsafe { core::ptr::read(&this.params) };
        // SAFETY: same reasoning as the params move above -- `this` is
        // ManuallyDrop, so reading `state` produces a single owner.
        let state = unsafe { core::ptr::read(&this.state) };
        (ctx, params, state)
    }
}

impl<const N: usize, State> fmt::Debug for AclContext<N, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AclContext")
            .field("name", &self.name())
            .field("num_fields", &N)
            .field("ptr", &self.ctx)
            .finish()
    }
}

impl<const N: usize, State> fmt::Display for AclContext<N, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AclContext<{N}>({:?})", self.name())
    }
}

// ---------------------------------------------------------------------------
// Configuring state
// ---------------------------------------------------------------------------

impl<const N: usize> AclContext<N, Configuring<N>> {
    /// Create a new ACL context in the [`Configuring`] state.
    ///
    /// This is a safe wrapper around [`rte_acl_create`][dpdk_sys::rte_acl_create].
    ///
    /// # Arguments
    ///
    /// * `params` -- validated creation parameters (see [`AclCreateParams::new`]).
    /// * `config` -- validated build parameters (see
    ///   [`AclBuildConfig::new`]).  The context retains the config for the
    ///   lifetime of the [`Configuring`] state and uses it to validate
    ///   [`Rule<N>`] values at [`add_rules`][AclContext::add_rules] time and
    ///   to dispatch [`build`][AclContext::build] without re-supplying it.
    ///
    /// # Errors
    ///
    /// Returns [`AclCreateError`] if DPDK fails to allocate the context.  This
    /// includes the case where the DPDK EAL has not been initialized:
    /// `rte_acl_create` returns NULL with `rte_errno` set, which surfaces as
    /// [`AclCreateError::InvalidParams`] or [`AclCreateError::Unknown`].  The
    /// failure is graceful -- this is a regular error path, not undefined
    /// behavior.
    #[cold]
    #[tracing::instrument(level = "debug", skip(params, config), fields(name = params.name()))]
    pub fn new(
        params: AclCreateParams<N>,
        config: AclBuildConfig<N>,
    ) -> Result<Self, AclCreateError> {
        // Serialize the find_existing + create sequence with a process-wide
        // mutex (see [`ACL_CREATE_LOCK`]).  Without this, two threads can
        // both observe find_existing -> NULL, both call rte_acl_create, and
        // both receive the same DPDK pointer (since rte_acl_create returns
        // the existing context for a duplicate name), producing two
        // AclContext wrappers that race to free the same handle on drop.
        //
        // Lock acquisition uses the concurrency facade, which treats poison
        // as a fatal invariant violation and panics rather than handing
        // back a `LockResult`.  That matches the workspace policy: a
        // prior holder panicking while the registry was being mutated
        // leaves DPDK's TAILQ in an unknown state, and continuing
        // silently could lead to use-after-free.  Aborting via the
        // panic is the only safe answer.
        let _create_guard = acl_create_lock().lock();

        // Pre-flight: DPDK's `rte_acl_create` silently returns the existing
        // context for a duplicate name.  Refuse if one is already registered.
        //
        // SAFETY: name_cstr returns a valid, NUL-terminated C string borrowed
        // from `params`; `rte_acl_find_existing` only reads through that
        // pointer and does not retain it.
        let existing = unsafe { dpdk_sys::rte_acl_find_existing(params.name_cstr().as_ptr()) };
        if !existing.is_null() {
            error!(
                "rte_acl_find_existing found context '{}' already registered",
                params.name(),
            );
            return Err(AclCreateError::AlreadyExists {
                name: params.name().to_owned(),
            });
        }

        let raw_params = params.to_raw();

        // SAFETY: raw_params borrows from `params` (which is on the stack and
        // lives through the call), so the contained `name` pointer is valid for
        // the duration of `rte_acl_create`.  The `RawParams<'_>` lifetime
        // statically prevents misuse.
        let ctx_ptr = unsafe { dpdk_sys::rte_acl_create(raw_params.as_ptr()) };

        let ctx = match NonNull::new(ctx_ptr) {
            Some(ptr) => ptr,
            None => {
                let rte_errno = unsafe { dpdk_sys::rte_errno_get() };
                error!(
                    "rte_acl_create failed for '{}': rte_errno = {rte_errno}",
                    params.name(),
                );
                return Err(match rte_errno {
                    errno::EINVAL => AclCreateError::InvalidParams,
                    errno::ENOMEM => AclCreateError::OutOfMemory,
                    other => AclCreateError::Unknown(Errno(other)),
                });
            }
        };

        debug!(
            "Created ACL context '{}' at {:p} (rule_size={}, max_rules={})",
            params.name(),
            ctx_ptr,
            params.rule_size(),
            params.max_rule_num(),
        );

        Ok(Self {
            ctx,
            params,
            state: Configuring { config },
        })
    }

    /// Borrow the [`AclBuildConfig<N>`] this context was created with.
    ///
    /// Symmetric with [`build_config`][AclContext::build_config] on
    /// [`AclContext<N, Built<N>>`].
    #[must_use]
    #[inline]
    pub fn build_config(&self) -> &AclBuildConfig<N> {
        &self.state.config
    }

    /// Add rules to the context.
    ///
    /// This is a safe wrapper around [`rte_acl_add_rules`][dpdk_sys::rte_acl_add_rules].
    ///
    /// Takes `&mut self` because DPDK documents this operation as **not thread-safe**.
    ///
    /// # Arguments
    ///
    /// * `rules` -- a slice of [`Rule<N>`] to add.  Each rule must have its fields in the same
    ///   order as the [`FieldDef`]s that will be used at build time.
    ///   All field values must be in **host byte order**.
    ///
    /// Each rule is validated against this context's [`AclBuildConfig<N>`]
    /// (the one passed to [`AclContext::new`]) before being handed to
    /// `rte_acl_add_rules`.  In particular, a
    /// [`FieldType::Mask`][super::field::FieldType::Mask] field whose
    /// `mask_range` (interpreted as a prefix length) exceeds the field's
    /// bit width is rejected here -- if it were forwarded to DPDK, the
    /// `RTE_ACL_MASKLEN_TO_BITMASK` macro would perform a C shift by
    /// `>= 8 * size`, which is undefined behaviour.
    ///
    /// # Errors
    ///
    /// Returns [`AclAddRulesError`] when a rule fails wrapper-side validation
    /// ([`AclAddRulesError::InvalidRule`], which carries the offending
    /// rule's index in the slice) or when DPDK itself rejects the rules
    /// (e.g. the context is full or the rules are invalid).  DPDK does
    /// **not** report which rule it rejected; the wrapper-side check
    /// catches the soundness-critical cases up-front, and for other
    /// rejections you may need to bisect by submitting smaller
    /// sub-slices.
    #[cold]
    #[tracing::instrument(level = "debug", skip(self, rules), fields(name = self.name(), count = rules.len()))]
    pub fn add_rules(&mut self, rules: &[Rule<N>]) -> Result<(), AclAddRulesError> {
        if rules.is_empty() {
            debug!("add_rules called with empty slice -- no-op");
            return Ok(());
        }

        // Wrapper-side validation against this context's AclBuildConfig.
        // Catches soundness-critical mismatches (e.g. an out-of-range
        // prefix length for a Mask field) before they reach DPDK's C code.
        for (rule_index, rule) in rules.iter().enumerate() {
            rule.validate(&self.state.config)
                .map_err(|source| AclAddRulesError::InvalidRule { rule_index, source })?;
        }

        // The length must fit in a u32 for the DPDK API.
        let num: u32 = rules.len().try_into().map_err(|_| {
            error!("Rule count {} exceeds u32::MAX", rules.len());
            AclAddRulesError::TooManyRules { len: rules.len() }
        })?;

        // SAFETY:
        // - `Rule<N>` is #[repr(C)] with identical layout to `RTE_ACL_RULE_DEF(_, N)`.
        //   The `rte_acl_rule` type is the "base" struct with a flexible array member; the
        //   `rule_size` parameter passed at context creation tells DPDK the actual stride.
        // - The pointer is valid for `num` consecutive `Rule<N>` elements.
        let ret = unsafe {
            dpdk_sys::rte_acl_add_rules(
                self.ctx.as_ptr(),
                rules.as_ptr() as *const dpdk_sys::rte_acl_rule,
                num,
            )
        };

        if ret != 0 {
            error!(
                "rte_acl_add_rules failed for '{}': ret = {ret}",
                self.name(),
            );
            return Err(match ret {
                errno::NEG_ENOMEM => AclAddRulesError::OutOfMemory,
                errno::NEG_EINVAL => AclAddRulesError::InvalidParams,
                other => AclAddRulesError::Unknown(Errno(other)),
            });
        }

        debug!("Added {num} rules to ACL context '{}'", self.name(),);
        Ok(())
    }

    /// Delete all rules from the context without destroying compiled runtime structures.
    ///
    /// Safe wrapper around [`rte_acl_reset_rules`][dpdk_sys::rte_acl_reset_rules].
    ///
    /// Takes `&mut self` because DPDK documents this operation as **not thread-safe**.
    ///
    /// # `reset_rules` vs [`reset`][AclContext::reset]
    ///
    /// The two reset entry points are distinguished by the state they
    /// operate on:
    ///
    /// | method | available in | takes | clears rules | clears compiled structures | state after |
    /// |--------|--------------|-------|--------------|----------------------------|-------------|
    /// | `reset_rules` | [`Configuring`] | `&mut self` | yes | no (no compiled structures exist yet) | [`Configuring`] (unchanged) |
    /// | [`reset`][AclContext::reset] | [`Built`] | `self` (consumes) | yes | yes (calls `rte_acl_reset`) | [`Configuring`] |
    ///
    /// Both keep the [`AclBuildConfig<N>`] that was originally supplied to
    /// [`AclContext::new`]; the next [`build`][AclContext::build] takes no
    /// config argument.  To switch to a different field layout, drop the
    /// context and create a new one with the new config.
    ///
    /// The shape difference (`&mut self` vs consuming) is forced by the
    /// typestate transition: `reset` changes the type, so it must consume
    /// the value; `reset_rules` keeps the same type and so can mutate in
    /// place.
    #[cold]
    #[tracing::instrument(level = "debug", skip(self), fields(name = self.name()))]
    pub fn reset_rules(&mut self) {
        // SAFETY: rte_acl_reset_rules mutates only the context pointed
        // at by `self.ctx`; `&mut self` guarantees exclusive access for
        // the duration of the call.
        unsafe { dpdk_sys::rte_acl_reset_rules(self.ctx.as_ptr()) };
        debug!("Reset rules for ACL context '{}'", self.name());
    }

    /// Compile the rules into optimized runtime lookup structures.
    ///
    /// Safe wrapper around [`rte_acl_build`][dpdk_sys::rte_acl_build].  The
    /// build config supplied to [`AclContext::new`] is forwarded to DPDK
    /// here; this method takes no config argument.
    ///
    /// On success, the context transitions from [`Configuring`] to [`Built`] and is ready for
    /// packet classification.
    ///
    /// On failure, the original context is returned inside [`AclBuildFailure`] so that the caller
    /// can recover, inspect, or drop it.  The rules remain intact; the caller may adjust rules
    /// and try again.
    ///
    /// # Errors
    ///
    /// Returns [`AclBuildFailure`] wrapping an [`AclBuildError`] on failure.
    #[cold]
    #[tracing::instrument(level = "debug", skip(self), fields(name = self.name()))]
    pub fn build(self) -> Result<AclContext<N, Built<N>>, AclBuildFailure<N>> {
        let raw_cfg = self.state.config.to_raw();

        // SAFETY: `raw_cfg` is a stack-local copy with no dangling pointers and lives through
        // the `rte_acl_build` call.
        let ret = unsafe { dpdk_sys::rte_acl_build(self.ctx.as_ptr(), &raw_cfg) };

        if ret != 0 {
            error!("rte_acl_build failed for '{}': ret = {ret}", self.name(),);
            let error = match ret {
                errno::NEG_ENOMEM => AclBuildError::OutOfMemory,
                errno::NEG_EINVAL => AclBuildError::InvalidConfig,
                errno::NEG_ERANGE => AclBuildError::ExceededMaxSize,
                other => AclBuildError::Unknown(Errno(other)),
            };
            return Err(AclBuildFailure {
                error,
                context: self,
            });
        }

        debug!("Built ACL context '{}'", self.name());

        // Transition: Configuring -> Built.  The config moves from
        // Configuring into Built without a clone -- both states hold the
        // same logical artifact.
        let (ctx, params, old_state) = self.into_parts();
        Ok(AclContext {
            ctx,
            params,
            state: Built {
                config: old_state.config,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Built state
// ---------------------------------------------------------------------------

impl<const N: usize> AclContext<N, Built<N>> {
    /// Borrow the [`AclBuildConfig<N>`] used to compile this context.
    ///
    /// Useful when classify-time code needs to know the field layout (offsets,
    /// sizes) or the number of categories without threading the config through
    /// the call chain.
    #[must_use]
    #[inline]
    pub fn build_config(&self) -> &AclBuildConfig<N> {
        &self.state.config
    }

    /// Get the number of categories used at build time.
    ///
    /// Shorthand for `self.build_config().num_categories()`.
    #[must_use]
    #[inline]
    pub fn num_categories(&self) -> u32 {
        self.state.config.num_categories()
    }

    /// Borrow the field definitions used at build time.
    ///
    /// Shorthand for `self.build_config().field_defs()`.
    #[must_use]
    #[inline]
    pub fn field_defs(&self) -> &[FieldDef; N] {
        self.state.config.field_defs()
    }

    /// Classify input data buffers against the compiled rules.
    ///
    /// This is the **hot-path** function and the primary reason the ACL context exists.
    /// It is a thin wrapper around [`rte_acl_classify`][dpdk_sys::rte_acl_classify];
    /// the function is `unsafe` because the per-pointer buffer-size precondition
    /// cannot be expressed in the type system (see the `# Safety` section below).
    ///
    /// Takes `&self` because DPDK documents classification as **thread-safe**.  An
    /// `Arc<AclContext<N, Built>>` can be shared across threads for concurrent classification.
    ///
    /// # Arguments
    ///
    /// * `data` -- array of pointers to input data buffers.  Each pointer should reference the
    ///   first byte of the region described by the [`FieldDef`] offsets.
    ///   All fields in the input buffers must be in **network byte order** (MSB).
    /// * `results` -- output array to receive match results.  Must have at least
    ///   `data.len() * categories` elements.  Each result is either `0` (no match) or the
    ///   `userdata` value of the highest-priority matching rule for that (buffer, category) pair.
    /// * `categories` -- number of match categories.  Must be between 1 and
    ///   [`MAX_CATEGORIES`][super::config::MAX_CATEGORIES] (inclusive), and either 1 or a multiple
    ///   of [`RESULTS_MULTIPLIER`][super::config::RESULTS_MULTIPLIER].
    ///
    /// # Errors
    ///
    /// Returns [`AclClassifyError::InvalidArgs`] if:
    /// - The `results` slice is too small for `data.len() * categories` entries.
    /// - `data.len()` exceeds `u32::MAX`.
    /// - `categories` is zero, exceeds [`MAX_CATEGORIES`][super::config::MAX_CATEGORIES],
    ///   is not `1` or a multiple of [`RESULTS_MULTIPLIER`][super::config::RESULTS_MULTIPLIER],
    ///   or exceeds the [`num_categories`][super::config::AclBuildConfig::num_categories]
    ///   the context was built with.
    ///
    /// Returns the appropriate error variant if DPDK itself rejects the arguments.
    ///
    /// # Safety
    ///
    /// Every pointer in `data` must be valid for reads of at least
    /// [`AclBuildConfig::min_input_size`][super::config::AclBuildConfig::min_input_size]
    /// bytes, where the build config is the one returned by
    /// [`build_config`][AclContext::build_config].  DPDK reads from those
    /// buffers without bounds checks and a dangling, null, or too-small
    /// pointer is undefined behavior.
    ///
    /// The bound is **wider** than `max(field.offset + field.size)`: DPDK's
    /// classify loop performs 4-byte aligned loads where each load's
    /// starting offset is the **lowest `FieldDef.offset` within an
    /// `input_index` group** (this is what DPDK's `data_index` is built
    /// from at `rte_acl_build` time).  Concretely,
    /// [`min_input_size`][super::config::AclBuildConfig::min_input_size]
    /// returns `max(group_offset + 4)` across all `input_index` groups in
    /// the field-def array, which is the upper bound on the byte offset
    /// DPDK may read from.  The grouping validation in
    /// [`AclBuildConfig::new`][super::config::AclBuildConfig::new]
    /// guarantees this is at least `max(field.offset + field.size)`, so
    /// callers do not need to also account for the per-field extent
    /// separately.
    ///
    /// The data array itself is read-only.  bindgen generates `data: *mut *const
    /// u8` (the loose C signature is `const uint8_t **`), but DPDK only reads
    /// the array: `acl_set_flow` in `lib/eal/acl/acl_run.h` stores the pointer
    /// once, and the only access site dereferences `flows->data[i]` for read.
    /// The `.cast_mut()` below is a type accommodation for the bindgen signature
    /// and does not license writes through it.
    ///
    /// A future safe wrapper could enforce this statically via `&[&[u8; STRIDE]]`
    /// where `STRIDE` is derived from the field layout; deferred until a
    /// concrete consumer demonstrates the shape it wants.
    #[inline]
    pub unsafe fn classify(
        &self,
        data: &[*const u8],
        results: &mut [u32],
        categories: u32,
    ) -> Result<(), AclClassifyError> {
        let num = self.validate_classify_args(data, results, categories)?;

        // SAFETY:
        // - data and results slice lengths have been validated.
        // - The pointer validity precondition on the individual buffers is
        //   forwarded to our caller via the `unsafe fn` signature.
        // - The `.cast_mut()` is sound because DPDK only reads the data
        //   array (see the # Safety section above for the source citation).
        let ret = unsafe {
            dpdk_sys::rte_acl_classify(
                self.ctx.as_ptr(),
                data.as_ptr().cast_mut(),
                results.as_mut_ptr(),
                num,
                categories,
            )
        };

        if ret != 0 {
            trace!(
                "rte_acl_classify returned {ret} for context '{}'",
                self.name(),
            );
            return Err(match ret {
                errno::NEG_EINVAL => AclClassifyError::InvalidArgs,
                other => AclClassifyError::Unknown(Errno(other)),
            });
        }

        Ok(())
    }

    /// Classify input data buffers using a specific SIMD algorithm.
    ///
    /// Identical to [`classify`][AclContext::classify] except that the caller explicitly selects
    /// the classification algorithm instead of using the context's default.
    ///
    /// Thin wrapper around
    /// [`rte_acl_classify_alg`][fn@dpdk_sys::rte_acl_classify_alg], except
    /// when `algorithm == ClassifyAlgorithm::Default`: see the
    /// "[`Default`][ClassifyAlgorithm::Default] is special" note below.
    ///
    /// # `Default` is special
    ///
    /// `rte_acl_classify_alg(ctx, ..., RTE_ACL_CLASSIFY_DEFAULT)` dispatches
    /// table slot 0 in DPDK's classify dispatch table, which is the
    /// **scalar** implementation -- not "DPDK's best available".  Only
    /// [`rte_acl_set_ctx_classify`][dpdk_sys::rte_acl_set_ctx_classify]
    /// expands `Default` to the best available variant on the current CPU.
    /// To honour the "use the context's default algorithm" intent without
    /// silently forcing scalar, this wrapper dispatches through
    /// [`rte_acl_classify`] (which uses the context's currently-set
    /// algorithm) when `algorithm == ClassifyAlgorithm::Default`.  Any
    /// other variant goes directly to `rte_acl_classify_alg`.
    ///
    /// [`rte_acl_classify`]: dpdk_sys::rte_acl_classify
    ///
    /// # Arguments
    ///
    /// See [`classify`][AclContext::classify] for `data`, `results`, and `categories`.
    ///
    /// * `algorithm` -- the SIMD implementation to use for this call.  The caller
    ///   is responsible for ensuring the selected algorithm is supported on the
    ///   current CPU; see the `# Safety` section below.
    ///
    /// # Errors
    ///
    /// Same as [`classify`][AclContext::classify], plus
    /// [`AclClassifyError::NotSupported`] if the underlying
    /// `rte_acl_classify_alg` returns `-ENOTSUP` (typically because a non-stub
    /// SIMD slot was selected but DPDK still reported it as unsupported).
    ///
    /// # Safety
    ///
    /// Same pointer-validity precondition as [`classify`][AclContext::classify], plus:
    ///
    /// `algorithm` must be implemented and runnable on the current CPU.
    /// Unlike
    /// [`set_default_algorithm`][AclContext::set_default_algorithm] (which
    /// delegates to `rte_acl_set_ctx_classify` and which validates against
    /// the per-CPU capability table before installing the algorithm),
    /// [`rte_acl_classify_alg`][fn@dpdk_sys::rte_acl_classify_alg] does
    /// **not** pre-check feature support; it dispatches straight through
    /// the classify function-pointer table.  Selecting a real SIMD variant
    /// that the host does not implement therefore executes unsupported
    /// instructions (SIGILL or silent corruption) rather than returning an
    /// error.
    ///
    /// `ClassifyAlgorithm::Scalar` is always safe.
    /// `ClassifyAlgorithm::Default` is also safe and is routed through
    /// `rte_acl_classify` (see the "`Default` is special" section above), so
    /// it picks up whatever variant `set_default_algorithm` previously
    /// vetted.  Every other variant requires the caller to confirm CPU
    /// support out-of-band (e.g. via `is_x86_feature_detected!` or
    /// `std::arch::is_aarch64_feature_detected!`).
    ///
    /// Note that an unsupported-but-stubbed-out slot (DPDK ships scalar
    /// fallbacks for some entries on builds where the SIMD codepath was
    /// disabled) will return `-ENOTSUP` through the FFI, surfacing as
    /// [`AclClassifyError::NotSupported`] -- the unsafe contract is about
    /// the case where the slot is a real, non-stub SIMD entry whose
    /// instructions the CPU cannot execute.
    #[inline]
    pub unsafe fn classify_with_algorithm(
        &self,
        data: &[*const u8],
        results: &mut [u32],
        categories: u32,
        algorithm: ClassifyAlgorithm,
    ) -> Result<(), AclClassifyError> {
        // See doc comment: `Default` through `rte_acl_classify_alg` would
        // pin table slot 0 (scalar) rather than "the context's default".
        // Dispatch through `rte_acl_classify` instead so the call honours
        // whatever the context was last configured with.  (Argument
        // validation runs once, inside the delegated `classify`.)
        if matches!(algorithm, ClassifyAlgorithm::Default) {
            // SAFETY: same as classify; caller upholds the pointer validity
            // precondition.
            return unsafe { self.classify(data, results, categories) };
        }

        let num = self.validate_classify_args(data, results, categories)?;

        // SAFETY: same as classify; additionally `algorithm` maps to a valid
        // rte_acl_classify_alg constant by construction.
        let ret = unsafe {
            dpdk_sys::rte_acl_classify_alg(
                self.ctx.as_ptr(),
                data.as_ptr().cast_mut(),
                results.as_mut_ptr(),
                num,
                categories,
                algorithm.into(),
            )
        };

        if ret != 0 {
            trace!(
                "rte_acl_classify_alg({algorithm}) returned {ret} for context '{}'",
                self.name(),
            );
            return Err(match ret {
                errno::NEG_EINVAL => AclClassifyError::InvalidArgs,
                errno::NEG_ENOTSUP => AclClassifyError::NotSupported,
                other => AclClassifyError::Unknown(Errno(other)),
            });
        }

        Ok(())
    }

    /// Set the default classification algorithm for future calls to
    /// [`classify`][AclContext::classify].
    ///
    /// This is a safe wrapper around
    /// [`rte_acl_set_ctx_classify`][dpdk_sys::rte_acl_set_ctx_classify].
    ///
    /// Takes `&mut self` because DPDK takes a `*mut rte_acl_ctx`, indicating the context is
    /// mutated.  Requiring exclusive access prevents data races with concurrent
    /// [`classify`][AclContext::classify] calls.
    ///
    /// # Interaction with [`Arc`][std::sync::Arc]
    ///
    /// The `&mut self` requirement means a context that has been wrapped in
    /// [`Arc`][std::sync::Arc] (the typical pattern for sharing a
    /// [`Built<N>`] context across classification threads) is no longer
    /// reachable for `set_default_algorithm`.  Call this **before** wrapping
    /// the context in an `Arc`, or use
    /// [`classify_with_algorithm`][AclContext::classify_with_algorithm] to
    /// override the algorithm on individual calls without mutating the
    /// shared context.
    ///
    /// # Errors
    ///
    /// Returns [`AclSetAlgorithmError`] if the algorithm is unsupported or the parameters are
    /// invalid.
    #[cold]
    #[tracing::instrument(level = "debug", skip(self), fields(name = self.name()))]
    pub fn set_default_algorithm(
        &mut self,
        algorithm: ClassifyAlgorithm,
    ) -> Result<(), AclSetAlgorithmError> {
        // SAFETY: `algorithm.into()` yields a valid rte_acl_classify_alg constant by
        // construction.
        let ret =
            unsafe { dpdk_sys::rte_acl_set_ctx_classify(self.ctx.as_ptr(), algorithm.into()) };

        if ret != 0 {
            error!(
                "rte_acl_set_ctx_classify({algorithm}) failed for '{}': ret = {ret}",
                self.name(),
            );
            return Err(match ret {
                errno::NEG_EINVAL => AclSetAlgorithmError::InvalidParams,
                errno::NEG_ENOTSUP => AclSetAlgorithmError::NotSupported,
                other => AclSetAlgorithmError::Unknown(Errno(other)),
            });
        }

        debug!(
            "Set default classify algorithm to {algorithm} for ACL context '{}'",
            self.name(),
        );
        Ok(())
    }

    /// Reset the context, clearing **both** rules and compiled runtime
    /// structures, and transition back to the [`Configuring`] state.
    ///
    /// Safe wrapper around [`rte_acl_reset`][dpdk_sys::rte_acl_reset].  The
    /// [`AclBuildConfig<N>`] is retained (it lives on the [`Configuring`]
    /// state just as on [`Built<N>`]), so the next
    /// [`build`][AclContext::build] requires no fresh config argument.  If
    /// the caller wants to switch to a different field layout, they should
    /// drop the context and construct a new one with the desired config.
    ///
    /// See [`reset_rules`][AclContext::reset_rules] for the matching method on
    /// [`Configuring`] contexts and a comparison table.
    ///
    /// The returned context has no rules and no compiled structures, but
    /// the same field layout as before; ready for new rules to be added
    /// via [`add_rules`][AclContext::add_rules].
    #[cold]
    #[tracing::instrument(level = "debug", skip(self), fields(name = self.name()))]
    pub fn reset(self) -> AclContext<N, Configuring<N>> {
        // SAFETY: rte_acl_reset mutates only the context pointed at by
        // `self.ctx`; consuming `self` by value guarantees no other
        // reference to this context can be in use.
        unsafe { dpdk_sys::rte_acl_reset(self.ctx.as_ptr()) };

        debug!("Reset ACL context '{}'", self.name());

        // Transition: Built -> Configuring.  Carry the config forward; the
        // post-reset context still describes the same field layout.
        let (ctx, params, old_state) = self.into_parts();
        AclContext {
            ctx,
            params,
            state: Configuring {
                config: old_state.config,
            },
        }
    }

    /// Validate the arguments common to both classify methods.
    ///
    /// Returns the validated `num` value as `u32` on success.
    ///
    /// `categories` is checked against DPDK's documented bounds **before** we
    /// hand it to FFI.  DPDK uses `categories` to index into per-thread runtime
    /// arrays sized to [`RTE_ACL_MAX_CATEGORIES`][dpdk_sys::RTE_ACL_MAX_CATEGORIES],
    /// so out-of-bound values can overflow C-side state and are not safe to
    /// forward.
    #[inline]
    fn validate_classify_args(
        &self,
        data: &[*const u8],
        results: &[u32],
        categories: u32,
    ) -> Result<u32, AclClassifyError> {
        // `categories` must be in the closed range [1, MAX_CATEGORIES] and
        // either 1 or a multiple of RESULTS_MULTIPLIER -- the same constraints
        // applied by AclBuildConfig::new at build time.  We re-check here
        // because the categories value at classify time is independent of the
        // build's num_categories and is otherwise unconstrained input.
        use super::config::{MAX_CATEGORIES, RESULTS_MULTIPLIER};
        if categories == 0 {
            error!("classify categories must be at least 1");
            return Err(AclClassifyError::InvalidArgs);
        }
        if categories > MAX_CATEGORIES {
            error!(
                "classify categories {categories} exceeds RTE_ACL_MAX_CATEGORIES ({MAX_CATEGORIES})",
            );
            return Err(AclClassifyError::InvalidArgs);
        }
        if categories != 1 && !categories.is_multiple_of(RESULTS_MULTIPLIER) {
            error!(
                "classify categories {categories} must be 1 or a multiple of \
                 RTE_ACL_RESULTS_MULTIPLIER ({RESULTS_MULTIPLIER})",
            );
            return Err(AclClassifyError::InvalidArgs);
        }
        // `categories` must not exceed the value supplied at build time.
        // The trie's per-node result slots are sized to `num_categories`;
        // passing `categories > num_categories` would make DPDK's classify
        // loop read past those slots into adjacent trie memory.  DPDK does
        // not validate this itself, so we close the hole here.  Passing
        // `categories < num_categories` is permitted and just truncates
        // the results (one valid use case is a multi-category build that
        // a particular caller only wants the first category from).
        let built_num_categories = self.state.config.num_categories();
        if categories > built_num_categories {
            error!(
                "classify categories {categories} exceeds build-time num_categories ({built_num_categories})",
            );
            return Err(AclClassifyError::InvalidArgs);
        }

        // The number of input buffers must fit in u32.
        let num: u32 = data.len().try_into().map_err(|_| {
            error!("Input buffer count {} exceeds u32::MAX", data.len());
            AclClassifyError::InvalidArgs
        })?;

        // The results slice must be large enough for `num * categories` entries.
        let required = (num as usize)
            .checked_mul(categories as usize)
            .ok_or_else(|| {
                error!("Overflow computing required results size: {num} * {categories}",);
                AclClassifyError::InvalidArgs
            })?;

        if results.len() < required {
            error!(
                "Results slice too small: have {}, need {} ({num} buffers * {categories} categories)",
                results.len(),
                required,
            );
            return Err(AclClassifyError::InvalidArgs);
        }

        Ok(num)
    }
}

// ---------------------------------------------------------------------------
// RAII: Drop
// ---------------------------------------------------------------------------

// Drop takes [`ACL_CREATE_LOCK`] before calling `rte_acl_free` (see the
// comment on that static).  ACL contexts are expected to be long-lived
// (created during setup, dropped at shutdown), so this serialisation has
// no practical cost.  If a future caller drops `AclContext`s on a hot
// path, the contention with concurrent `AclContext::new` and
// `dump_all_contexts` calls becomes visible -- prefer to keep contexts
// alive for their useful lifetime instead.
//
// Reentrancy invariant: the lock is a non-reentrant `Mutex<()>`, so an
// `AclContext` must **not** be dropped on a thread that already holds
// [`ACL_CREATE_LOCK`] -- doing so would deadlock the current thread on
// its own previously-acquired guard.  In practice this can only happen
// in pathological setups (e.g. a caller manually acquires the lock by
// poking module-private state); the wrapper itself never holds the
// lock across a region that could free an `AclContext`.
impl<const N: usize, State> Drop for AclContext<N, State> {
    fn drop(&mut self) {
        debug!("Freeing ACL context '{}'", self.name());
        // Serialize the rte_acl_free call against AclContext::new and
        // dump_all_contexts via the same process-wide mutex (see
        // [`ACL_CREATE_LOCK`]).  DPDK's `rte_acl_free` removes the
        // context's entry from the global TAILQ; without this lock, an
        // interleaving with a concurrent `find_existing`-then-`create` in
        // another thread could observe a half-removed entry.
        //
        // The facade panics on poison.  Dropping while another holder
        // panicked mid-operation means the DPDK registry may be in an
        // unknown state; aborting via the panic is the only safe answer.
        let _guard = acl_create_lock().lock();
        // SAFETY: rte_acl_free is safe to call on any valid context pointer; `Drop` runs at
        // most once per `AclContext`, and the create-lock acquired above serialises against
        // `rte_acl_create` / `dump_all_contexts`.
        unsafe { dpdk_sys::rte_acl_free(self.ctx.as_ptr()) };
    }
}

// ---------------------------------------------------------------------------
// Module-level utilities
// ---------------------------------------------------------------------------

/// Dump information about **all** ACL contexts to stdout.
///
/// This is a debugging aid that calls [`rte_acl_list_dump`][dpdk_sys::rte_acl_list_dump].
/// Output goes directly to stdout and is not captured by the tracing subsystem.
///
/// # Thread safety
///
/// Holds the same process-wide ACL registry mutex used by
/// [`AclContext::new`] and [`AclContext`] drops, so the list-walking
/// inside `rte_acl_list_dump` does not race against concurrent registry
/// mutation elsewhere in the process.
#[cold]
pub fn dump_all_contexts() {
    // See the locking rationale on Drop / AclContext::new.  The dump walks
    // DPDK's global TAILQ of contexts; concurrent registry mutation would
    // expose a list in an inconsistent state to the walk.  Facade panics
    // on poison (workspace policy -- a prior holder panic implies the
    // registry may be inconsistent).
    let _guard = acl_create_lock().lock();
    // SAFETY: rte_acl_list_dump takes no arguments and simply iterates an internal list.
    unsafe { dpdk_sys::rte_acl_list_dump() }
}
