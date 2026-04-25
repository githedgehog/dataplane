// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL context with typestate lifecycle management.
//!
//! This module provides [`AclContext`], a safe RAII wrapper around DPDK's opaque
//! [`rte_acl_ctx`][dpdk_sys::rte_acl_ctx] handle.  The context uses a **typestate** pattern to
//! enforce the correct lifecycle at compile time:
//!
//! ```text
//! AclContext<N, Configuring>  ──build()──▶  AclContext<N, Built>
//!          ▲                                         │
//!          └────────────────reset()──────────────────┘
//! ```
//!
//! - In the [`Configuring`] state you can add rules ([`add_rules`][AclContext::add_rules]) and
//!   compile them ([`build`][AclContext::build]).  Mutation methods take `&mut self`, which lets
//!   the Rust borrow checker enforce DPDK's documented constraint that these operations are **not
//!   thread-safe**.
//!
//! - In the [`Built`] state you can classify packets ([`classify`][AclContext::classify]).
//!   Classification takes `&self`, which — combined with the `Sync` implementation — allows safe
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
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use errno::Errno;
use tracing::{debug, error, info, trace};

use super::classify::ClassifyAlgorithm;
use super::config::{AclBuildConfig, AclCreateParams};
use super::error::{AclAddRulesError, AclBuildError, AclClassifyError, AclCreateError, AclSetAlgorithmError};
use super::rule::Rule;

// ---------------------------------------------------------------------------
// Typestate markers
// ---------------------------------------------------------------------------

/// Typestate marker: the context is accepting rule mutations and has not yet been compiled.
///
/// Methods available in this state:
/// - [`add_rules`][AclContext::add_rules] (`&mut self`)
/// - [`reset_rules`][AclContext::reset_rules] (`&mut self`)
/// - [`build`][AclContext::build] (consumes `self`, transitions to [`Built`])
#[derive(Debug)]
pub struct Configuring;

/// Typestate marker: the context has been compiled and is ready for packet classification.
///
/// Methods available in this state:
/// - [`classify`][AclContext::classify] (`&self`, thread-safe)
/// - [`classify_with_algorithm`][AclContext::classify_with_algorithm] (`&self`, thread-safe)
/// - [`set_default_algorithm`][AclContext::set_default_algorithm] (`&mut self`)
/// - [`reset`][AclContext::reset] (consumes `self`, transitions back to [`Configuring`])
#[derive(Debug)]
pub struct Built;

// ---------------------------------------------------------------------------
// Build failure
// ---------------------------------------------------------------------------

/// Returned when [`AclContext::build`] fails.
///
/// Because `build` consumes the [`Configuring`] context, this error wraps **both** the error
/// description and the original context so the caller can recover, inspect, or drop it.
///
/// # Example
///
/// ```ignore
/// match ctx.build(&cfg) {
///     Ok(built) => { /* use built context */ }
///     Err(failure) => {
///         eprintln!("build failed: {}", failure.error);
///         // The original context is still usable:
///         let mut ctx = failure.context;
///         ctx.reset_rules();
///     }
/// }
/// ```
pub struct AclBuildFailure<const N: usize> {
    /// The build error.
    pub error: AclBuildError,
    /// The original context, returned in [`Configuring`] state so it can be reused or dropped.
    pub context: AclContext<N, Configuring>,
}

impl<const N: usize> fmt::Debug for AclBuildFailure<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AclBuildFailure")
            .field("error", &self.error)
            .field("context_name", &self.context.name())
            .finish()
    }
}

impl<const N: usize> fmt::Display for AclBuildFailure<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ACL build failed for context '{}': {}",
            self.context.name(),
            self.error,
        )
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
pub struct AclContext<const N: usize, State = Configuring> {
    /// Raw DPDK context handle.  Non-null invariant maintained at all times.
    ctx: NonNull<dpdk_sys::rte_acl_ctx>,
    /// The validated parameters that were used to create this context.
    params: AclCreateParams,
    /// Zero-sized typestate marker.
    _state: PhantomData<State>,
}

// The DPDK ACL context handle is a heap allocation — it is not inherently tied to any particular
// thread, so `Send` is correct for all states.
//
// For `Sync`:
// - In `Configuring`, all mutation methods require `&mut self`, so sharing an immutable reference
//   across threads is safe (there is nothing useful a second thread can do with `&self` that would
//   race with mutation).
// - In `Built`, `classify` is documented by DPDK as thread-safe, so sharing `&self` across
//   threads is explicitly correct.
unsafe impl<const N: usize, State> Send for AclContext<N, State> {}
unsafe impl<const N: usize, State> Sync for AclContext<N, State> {}

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
    pub fn params(&self) -> &AclCreateParams {
        &self.params
    }

    /// Get the raw DPDK context pointer.
    ///
    /// # Safety
    ///
    /// The caller must not free the returned pointer or use it after the context is dropped.
    /// The pointer is valid for the lifetime of `self`.
    #[must_use]
    #[inline]
    pub unsafe fn as_raw_ptr(&self) -> *const dpdk_sys::rte_acl_ctx {
        self.ctx.as_ptr()
    }

    /// Dump the context's internal state to stdout via
    /// [`rte_acl_dump`][dpdk_sys::rte_acl_dump].
    ///
    /// This is a debugging aid.  Output goes to stdout and is not captured by the tracing
    /// subsystem.
    pub fn dump(&self) {
        // SAFETY: ctx is guaranteed non-null by the NonNull invariant.
        // rte_acl_dump takes *const and performs read-only access.
        unsafe { dpdk_sys::rte_acl_dump(self.ctx.as_ptr()) }
    }

    /// Decompose the context into its raw parts **without** running the destructor.
    ///
    /// This is used internally to implement zero-cost typestate transitions: the raw pointer and
    /// params are moved into a new [`AclContext`] with a different `State` marker, and
    /// [`ManuallyDrop`] prevents the old value's [`Drop`] from freeing the DPDK handle.
    fn into_raw_parts(self) -> (NonNull<dpdk_sys::rte_acl_ctx>, AclCreateParams) {
        let this = ManuallyDrop::new(self);
        let ctx = this.ctx;
        // SAFETY: `this` will not be dropped (ManuallyDrop), so moving `params` out via
        // ptr::read is safe — there will be exactly one owner of the AclCreateParams after
        // this call.
        let params = unsafe { core::ptr::read(&this.params) };
        (ctx, params)
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

impl<const N: usize> AclContext<N, Configuring> {
    /// Create a new ACL context in the [`Configuring`] state.
    ///
    /// This is a safe wrapper around [`rte_acl_create`][dpdk_sys::rte_acl_create].
    ///
    /// # Arguments
    ///
    /// * `params` — validated creation parameters (see [`AclCreateParams::new`]).
    ///
    /// # Errors
    ///
    /// Returns [`AclCreateError`] if DPDK fails to allocate the context.
    ///
    /// # Safety
    ///
    /// Requires that the DPDK EAL has been initialised.
    #[cold]
    #[tracing::instrument(level = "debug", skip(params), fields(name = params.name()))]
    pub fn new(params: AclCreateParams) -> Result<Self, AclCreateError> {
        let raw_params = params.to_raw();

        // SAFETY: raw_params contains a valid C string pointer that is guaranteed to outlive
        // this call (it's borrowed from `params` which is on the stack).
        let ctx_ptr = unsafe { dpdk_sys::rte_acl_create(&raw_params) };

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

        info!(
            "Created ACL context '{}' at {:p} (rule_size={}, max_rules={})",
            params.name(),
            ctx_ptr,
            params.rule_size(),
            params.max_rule_num(),
        );

        Ok(Self {
            ctx,
            params,
            _state: PhantomData,
        })
    }

    /// Add rules to the context.
    ///
    /// This is a safe wrapper around [`rte_acl_add_rules`][dpdk_sys::rte_acl_add_rules].
    ///
    /// Takes `&mut self` because DPDK documents this operation as **not thread-safe**.
    ///
    /// # Arguments
    ///
    /// * `rules` — a slice of [`Rule<N>`] to add.  Each rule must have its fields in the same
    ///   order as the [`FieldDef`][super::field::FieldDef]s that will be used at build time.
    ///   All field values must be in **host byte order**.
    ///
    /// # Errors
    ///
    /// Returns [`AclAddRulesError`] if DPDK rejects the rules (e.g. the context is full or the
    /// rules are invalid).
    #[tracing::instrument(level = "debug", skip(self, rules), fields(name = self.name(), count = rules.len()))]
    pub fn add_rules(&mut self, rules: &[Rule<N>]) -> Result<(), AclAddRulesError> {
        if rules.is_empty() {
            debug!("add_rules called with empty slice — no-op");
            return Ok(());
        }

        // The length must fit in a u32 for the DPDK API.
        let num: u32 = rules.len().try_into().map_err(|_| {
            error!("Rule count {} exceeds u32::MAX", rules.len());
            AclAddRulesError::InvalidParams
        })?;

        // SAFETY:
        // - `Rule<N>` is #[repr(C)] with identical layout to `RTE_ACL_RULE_DEF(_, N)`.
        //   The `rte_acl_rule` type is the "base" struct with a flexible array member; the
        //   `rule_size` parameter passed at context creation tells DPDK the actual stride.
        // - The pointer is valid for `num` consecutive `Rule<N>` elements.
        // - `self.ctx` is guaranteed non-null.
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

        debug!(
            "Added {num} rules to ACL context '{}'",
            self.name(),
        );
        Ok(())
    }

    /// Delete all rules from the context without destroying compiled runtime structures.
    ///
    /// This is a safe wrapper around [`rte_acl_reset_rules`][dpdk_sys::rte_acl_reset_rules].
    ///
    /// Takes `&mut self` because DPDK documents this operation as **not thread-safe**.
    ///
    /// # Note
    ///
    /// This only removes the rules; any previously compiled lookup structures remain intact
    /// (though they will be stale if you intend to rebuild).  Use [`build`][AclContext::build] to
    /// recompile after adding new rules.
    #[tracing::instrument(level = "debug", skip(self), fields(name = self.name()))]
    pub fn reset_rules(&mut self) {
        // SAFETY: ctx is guaranteed non-null.
        unsafe { dpdk_sys::rte_acl_reset_rules(self.ctx.as_ptr()) };
        debug!("Reset rules for ACL context '{}'", self.name());
    }

    /// Compile the rules into optimised runtime lookup structures.
    ///
    /// This is a safe wrapper around [`rte_acl_build`][dpdk_sys::rte_acl_build].
    ///
    /// On success, the context transitions from [`Configuring`] to [`Built`] and is ready for
    /// packet classification.
    ///
    /// On failure, the original context is returned inside [`AclBuildFailure`] so that the caller
    /// can recover, inspect, or drop it.  The rules remain intact; the caller may adjust rules
    /// and try again.
    ///
    /// # Arguments
    ///
    /// * `config` — validated build parameters that define the field layout and category count.
    ///
    /// # Errors
    ///
    /// Returns [`AclBuildFailure`] wrapping an [`AclBuildError`] on failure.
    #[cold]
    #[tracing::instrument(level = "debug", skip(self, config), fields(name = self.name()))]
    pub fn build(
        self,
        config: &AclBuildConfig<N>,
    ) -> Result<AclContext<N, Built>, AclBuildFailure<N>> {
        let raw_cfg = config.to_raw();

        // SAFETY: ctx is guaranteed non-null; raw_cfg is a stack-local copy with no dangling
        // pointers.
        let ret = unsafe { dpdk_sys::rte_acl_build(self.ctx.as_ptr(), &raw_cfg) };

        if ret != 0 {
            error!(
                "rte_acl_build failed for '{}': ret = {ret}",
                self.name(),
            );
            let error = match ret {
                errno::NEG_ENOMEM => AclBuildError::OutOfMemory,
                errno::NEG_EINVAL => AclBuildError::InvalidConfig,
                other => AclBuildError::Unknown(Errno(other)),
            };
            return Err(AclBuildFailure {
                error,
                context: self,
            });
        }

        info!("Built ACL context '{}'", self.name());

        // Transition: Configuring → Built (zero-cost — same pointer, different phantom type).
        let (ctx, params) = self.into_raw_parts();
        Ok(AclContext {
            ctx,
            params,
            _state: PhantomData,
        })
    }
}

// ---------------------------------------------------------------------------
// Built state
// ---------------------------------------------------------------------------

impl<const N: usize> AclContext<N, Built> {
    /// Classify input data buffers against the compiled rules.
    ///
    /// This is the **hot-path** function and the primary reason the ACL context exists.
    /// It is a safe wrapper around [`rte_acl_classify`][dpdk_sys::rte_acl_classify].
    ///
    /// Takes `&self` because DPDK documents classification as **thread-safe**.  An
    /// `Arc<AclContext<N, Built>>` can be shared across threads for concurrent classification.
    ///
    /// # Arguments
    ///
    /// * `data` — array of pointers to input data buffers.  Each pointer should reference the
    ///   first byte of the region described by the [`FieldDef`][super::field::FieldDef] offsets.
    ///   All fields in the input buffers must be in **network byte order** (MSB).
    /// * `results` — output array to receive match results.  Must have at least
    ///   `data.len() * categories` elements.  Each result is either `0` (no match) or the
    ///   `userdata` value of the highest-priority matching rule for that (buffer, category) pair.
    /// * `categories` — number of match categories.  Must be between 1 and
    ///   [`MAX_CATEGORIES`][super::config::MAX_CATEGORIES] (inclusive), and either 1 or a multiple
    ///   of [`RESULTS_MULTIPLIER`][super::config::RESULTS_MULTIPLIER].
    ///
    /// # Errors
    ///
    /// Returns [`AclClassifyError::InvalidArgs`] if:
    /// - The `results` slice is too small for `data.len() * categories` entries.
    /// - `data.len()` exceeds `u32::MAX`.
    ///
    /// Returns the appropriate error variant if DPDK itself rejects the arguments.
    ///
    /// # Safety note
    ///
    /// The caller is responsible for ensuring that every pointer in `data` is valid and points to
    /// a buffer with at least as many bytes as the largest `offset + size` in the field
    /// definitions.  This cannot be checked by the Rust type system.
    #[inline]
    pub fn classify(
        &self,
        data: &[*const u8],
        results: &mut [u32],
        categories: u32,
    ) -> Result<(), AclClassifyError> {
        let num = Self::validate_classify_args(data, results, categories)?;

        // SAFETY:
        // - ctx is guaranteed non-null.
        // - data and results slice lengths have been validated.
        // - The caller is responsible for the validity of the data pointers (documented above).
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
    /// This is a safe wrapper around
    /// [`rte_acl_classify_alg`][dpdk_sys::rte_acl_classify_alg].
    ///
    /// # Arguments
    ///
    /// See [`classify`][AclContext::classify] for `data`, `results`, and `categories`.
    ///
    /// * `algorithm` — the SIMD implementation to use for this call.  It is the caller's
    ///   responsibility to ensure the selected algorithm is supported on the current CPU.
    ///
    /// # Errors
    ///
    /// Same as [`classify`][AclContext::classify].
    #[inline]
    pub fn classify_with_algorithm(
        &self,
        data: &[*const u8],
        results: &mut [u32],
        categories: u32,
        algorithm: ClassifyAlgorithm,
    ) -> Result<(), AclClassifyError> {
        let num = Self::validate_classify_args(data, results, categories)?;

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
    /// # Errors
    ///
    /// Returns [`AclSetAlgorithmError`] if the algorithm is unsupported or the parameters are
    /// invalid.
    #[tracing::instrument(level = "debug", skip(self), fields(name = self.name()))]
    pub fn set_default_algorithm(
        &mut self,
        algorithm: ClassifyAlgorithm,
    ) -> Result<(), AclSetAlgorithmError> {
        // SAFETY: ctx is guaranteed non-null; algorithm maps to a valid constant.
        let ret = unsafe {
            dpdk_sys::rte_acl_set_ctx_classify(self.ctx.as_ptr(), algorithm.into())
        };

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

    /// Reset the context, clearing **both** rules and compiled runtime structures, and transition
    /// back to the [`Configuring`] state.
    ///
    /// This is a safe wrapper around [`rte_acl_reset`][dpdk_sys::rte_acl_reset].
    ///
    /// The returned context is empty (no rules, no compiled structures) and ready for new rules
    /// to be added via [`add_rules`][AclContext::add_rules].
    #[cold]
    #[tracing::instrument(level = "debug", skip(self), fields(name = self.name()))]
    pub fn reset(self) -> AclContext<N, Configuring> {
        // SAFETY: ctx is guaranteed non-null.
        unsafe { dpdk_sys::rte_acl_reset(self.ctx.as_ptr()) };

        info!("Reset ACL context '{}'", self.name());

        // Transition: Built → Configuring (zero-cost — same pointer, different phantom type).
        let (ctx, params) = self.into_raw_parts();
        AclContext {
            ctx,
            params,
            _state: PhantomData,
        }
    }

    /// Validate the arguments common to both classify methods.
    ///
    /// Returns the validated `num` value as `u32` on success.
    #[inline]
    fn validate_classify_args(
        data: &[*const u8],
        results: &[u32],
        categories: u32,
    ) -> Result<u32, AclClassifyError> {
        // The number of input buffers must fit in u32.
        let num: u32 = data.len().try_into().map_err(|_| {
            error!("Input buffer count {} exceeds u32::MAX", data.len());
            AclClassifyError::InvalidArgs
        })?;

        // The results slice must be large enough for `num * categories` entries.
        let required = (num as usize).checked_mul(categories as usize).ok_or_else(|| {
            error!(
                "Overflow computing required results size: {num} * {categories}",
            );
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

impl<const N: usize, State> Drop for AclContext<N, State> {
    #[tracing::instrument(level = "debug", skip(self), fields(name = self.name()))]
    fn drop(&mut self) {
        info!("Freeing ACL context '{}'", self.name());
        // SAFETY: ctx is guaranteed non-null by the NonNull invariant.
        // rte_acl_free is safe to call on any valid context pointer and handles NULL gracefully
        // (though we never pass NULL).
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
pub fn dump_all_contexts() {
    // SAFETY: rte_acl_list_dump takes no arguments and simply iterates an internal list.
    unsafe { dpdk_sys::rte_acl_list_dump() }
}