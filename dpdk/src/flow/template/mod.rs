// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Synchronous wrappers for `rte_flow` templates (mlx5 hardware steering, `dv_flow_en=2`).
//!
//! Call [`Dev::configure_templates`](crate::dev::Dev::configure_templates) before starting the port.
//! Then use [`TemplateFlows`] to create templates, tables, meters and rules.
//! Handles borrow their dependencies: rules cannot outlive tables or meters, nor tables their templates.
//! All handles borrow the device.
//!
//! Unconfirmed operations block further operations on that handle.
//! Failed cleanup retains native dependencies until port close, even after Rust handles are dropped.
//!
//! Each port has at most one thread-bound context, which owns flow queue 0 and waits for each completion.

mod actions;
mod lifetime;
mod meter;
mod pattern;
mod shared;
mod table;

#[cfg(any(test, feature = "template-test"))]
pub mod testing;
#[cfg(any(test, feature = "template-test"))]
use testing::ffi as dpdk_sys;

pub use actions::{ArgumentError, RssTarget, RuleArg, TemplateAction};
pub use meter::{
    Meter, MeterAlgorithm, MeterError, MeterProfile, MeterProfileHandle, MeterProfileId, MeterUnit,
};
pub use pattern::{Color, Colored, Complete, InnerEth, Pattern};
pub use shared::{
    SharedActionsTemplate, SharedArg, SharedMeter, SharedMeterProfile, SharedPatternTemplate,
    SharedRule, SharedTable,
};
pub use table::{Counts, TableConfig, TemplateRule, TemplateTable};

use self::lifetime::Resource;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::time::Duration;

use dpdk_sys::{
    rte_flow_actions_template, rte_flow_actions_template_attr, rte_flow_actions_template_create,
    rte_flow_actions_template_destroy, rte_flow_configure, rte_flow_error, rte_flow_isolate,
    rte_flow_op_result, rte_flow_op_status, rte_flow_pattern_template,
    rte_flow_pattern_template_attr, rte_flow_pattern_template_create,
    rte_flow_pattern_template_destroy, rte_flow_port_attr, rte_flow_pull, rte_flow_push,
    rte_flow_queue_attr,
};
use tracing::warn;

use crate::dev::{Configured, Dev, DevIndex, Started};
use crate::flow::pattern::ItemShape;
use crate::flow::{Domain, FlowError, SetDirection, item};
use concurrency::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The flow queue every [`TemplateFlows`] uses.
const QUEUE: u32 = 0;

/// How long an operation may take to complete before it is reported as lost.
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(5);

/// Empty pulls to spin through before sleeping between them: completions usually arrive within
/// microseconds.
const SPINS: u32 = 1 << 12;

/// The sleep between pulls once spinning has found nothing.
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Resources the PMD reserves for template rules when the port is configured.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TemplateConfig {
    /// Operations flow queue 0 holds at once.
    pub queue_size: u32,
    /// Counters for [`TemplateAction::Count`].
    pub counters: u32,
    /// Meters ([`Meter`]); rounded up to a power of two, so at most 2^31.
    pub meters: u32,
}

/// The template state of a port, kept by the device.
#[derive(Debug, Default)]
pub(crate) struct PortTemplates {
    /// [`Dev::configure_templates`] succeeded.
    configured: bool,
    /// A [`TemplateFlows`] owns flow queue 0.
    in_use: AtomicBool,
    /// The tag of the last operation queued on the port, by any context: a late completion from a
    /// dropped context never matches a new one's operation.
    last_op: AtomicUsize,
    /// Template rules whose removal is unconfirmed.
    /// mlx5 also removes these when flushing synchronous rules, but leaves this count unchanged.
    /// It may therefore overcount after a flush.
    live_rules: AtomicUsize,
}

impl PortTemplates {
    /// Template rules whose removal has not been confirmed; they stay in the NIC until the port
    /// closes.
    pub(crate) fn live_rules(&self) -> usize {
        self.live_rules.load(Ordering::Acquire)
    }
}

/// Errors from template rules.
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// The PMD rejected a request.
    #[error(transparent)]
    Flow(#[from] FlowError),
    /// The port was started without [`Dev::configure_templates`].
    #[error("port {0} was not configured for template rules before it started")]
    NotConfigured(DevIndex),
    /// Another [`TemplateFlows`] owns the port's flow queue.
    #[error("port {0} already has a template rule context")]
    Busy(DevIndex),
    /// The PMD completed an operation with an error.
    #[error("the PMD failed a queued {0} operation")]
    OperationFailed(&'static str),
    /// No completion arrived.
    #[error("a queued {0} operation did not complete within {COMPLETION_TIMEOUT:?}")]
    Timeout(&'static str),
    /// An operation was enqueued, but pushing or collecting its completion failed.
    #[error("could not complete queued {what}: {source}")]
    Completion {
        /// The operation whose outcome is unknown.
        what: &'static str,
        /// The queue error after enqueue succeeded.
        source: FlowError,
    },
    /// An earlier operation on this handle has no collected completion.
    #[error("an operation on this handle is still pending; resources retained until port teardown")]
    Pending,
    /// A table names more templates than `rte_flow` can index.
    #[error("a template table takes at most 255 templates of each kind, not {0}")]
    TooManyTemplates(usize),
    /// A rule named a template its table does not have.
    #[error("the table has {count} {kind} template(s); there is no template {index}")]
    NoSuchTemplate {
        /// `"pattern"` or `"actions"`.
        kind: &'static str,
        /// The index the rule named.
        index: usize,
        /// How many the table has.
        count: usize,
    },
    /// A rule's pattern does not have the shape of its template.
    #[error("the rule pattern {rule:?} does not have the shape of its template {template:?}")]
    PatternShape {
        /// The template's shape.
        template: Vec<ItemShape>,
        /// The rule's shape.
        rule: Vec<ItemShape>,
    },
    /// A rule gave the wrong number of per-rule arguments.
    #[error(transparent)]
    Arguments(#[from] ArgumentError),
    /// [`TemplateRule::counts`] on a rule without [`TemplateAction::Count`].
    #[error("the rule does not count")]
    NotCounted,
    /// A table still has native dependents, including abandoned or forgotten rules.
    #[error("the table still has rules")]
    InUse,
    /// A rule was updated through a table it is not in.
    #[error("the rule is not in this table")]
    ForeignRule,
    /// A template, profile or meter of one port was used with another port's.
    #[error("{what} of port {got} used on port {expected}")]
    OtherPort {
        /// What was used.
        what: &'static str,
        /// The port it was used on.
        expected: DevIndex,
        /// The port it belongs to.
        got: DevIndex,
    },
}

impl TemplateError {
    /// Whether the enqueued operation still has no collected completion.
    fn is_pending(&self) -> bool {
        matches!(self, Self::Timeout(_) | Self::Completion { .. })
    }

    /// Whether an update reached the queue and its new dependencies might be in use.
    fn may_have_updated(&self) -> bool {
        self.is_pending() || matches!(self, Self::OperationFailed(_))
    }
}

/// Fail with [`TemplateError::OtherPort`] unless `got` is `expected`.
fn same_port(what: &'static str, expected: DevIndex, got: DevIndex) -> Result<(), TemplateError> {
    if expected == got {
        Ok(())
    } else {
        Err(TemplateError::OtherPort {
            what,
            expected,
            got,
        })
    }
}

/// Call an `rte_flow` function that returns 0 or a negative errno and fills `rte_flow_error`.
fn check(call: impl FnOnce(&mut rte_flow_error) -> i32) -> Result<(), FlowError> {
    // SAFETY: an all-zero `rte_flow_error` is a valid out-parameter.
    let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
    if call(&mut error) == 0 {
        Ok(())
    } else {
        Err(FlowError::from_raw(&error))
    }
}

impl Dev<'_, Configured> {
    /// Restrict ingress to the port's flow rules (isolated mode).
    /// Unmatched traffic on bifurcated ports such as mlx5 stays with the kernel netdev.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error if it cannot isolate the port.
    pub fn isolate(&mut self) -> Result<(), FlowError> {
        let port = self.info().index().as_u16();
        // SAFETY: plain FFI call on a configured, never started port.
        check(|error| unsafe { rte_flow_isolate(port, 1, error) })
    }

    /// Reserve resources for template rules, which [`TemplateFlows`] needs after start.
    ///
    /// # Errors
    ///
    /// Returns [`FlowError::Unspecified`] for more than 2^31 meters, or the PMD's error, for
    /// instance if the port does not support templates (mlx5 needs the `dv_flow_en=2` device
    /// argument).
    pub fn configure_templates(&mut self, config: &TemplateConfig) -> Result<(), FlowError> {
        let port = self.info().index().as_u16();
        // SAFETY: zero is valid for these C structs.
        let mut port_attr: rte_flow_port_attr = unsafe { core::mem::zeroed() };
        port_attr.nb_counters = config.counters;
        // mlx5 sizes its meter object for `rte_align32pow2(nb_meters >> 1)` pairs of meters, so an
        // odd count leaves the last meter outside it, and rules using that meter fail in hardware.
        port_attr.nb_meters = match config.meters {
            0 => 0,
            meters => meters
                .checked_next_power_of_two()
                .ok_or_else(|| {
                    FlowError::Unspecified(format!(
                        "cannot reserve {meters} meters: no power of two that large fits in u32"
                    ))
                })?
                .max(2),
        };
        let queue_attr = rte_flow_queue_attr {
            size: config.queue_size,
        };
        let mut queue_attrs = [&raw const queue_attr];
        // SAFETY: the attributes outlive the call; the PMD copies them.
        check(|error| unsafe {
            rte_flow_configure(
                port,
                &raw const port_attr,
                1,
                queue_attrs.as_mut_ptr(),
                error,
            )
        })?;
        self.templates_mut().configured = true;
        Ok(())
    }
}

/// Owns flow queue 0 of a started port and creates template rules through it.
///
/// Bound to its thread, like the queue:
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::flow::template::TemplateFlows;
/// fn assert_send<T: Send>() {}
/// assert_send::<TemplateFlows<'static>>();
/// ```
#[derive(Debug)]
pub struct TemplateFlows<'dev> {
    port: DevIndex,
    live_rules: &'dev AtomicUsize,
    in_use: &'dev AtomicBool,
    /// The tag of the last operation queued on the port; see [`complete`](Self::complete).
    last_op: &'dev AtomicUsize,
    /// How long [`complete`](Self::complete) sleeps waiting for a completion.
    timeout: Duration,
    _thread: PhantomData<*const ()>,
}

impl<'dev> TemplateFlows<'dev> {
    /// Take the port's flow queue.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::NotConfigured`] if the port was started without
    /// [`Dev::configure_templates`], or [`TemplateError::Busy`] while another context exists.
    pub fn new(dev: &'dev Dev<'_, Started>) -> Result<TemplateFlows<'dev>, TemplateError> {
        let port = dev.info().index();
        let templates = dev.templates();
        if !templates.configured {
            return Err(TemplateError::NotConfigured(port));
        }
        if templates.in_use.swap(true, Ordering::AcqRel) {
            return Err(TemplateError::Busy(port));
        }
        Ok(TemplateFlows {
            port,
            live_rules: &templates.live_rules,
            in_use: &templates.in_use,
            last_op: &templates.last_op,
            timeout: COMPLETION_TIMEOUT,
            _thread: PhantomData,
        })
    }

    /// The port the context belongs to.
    #[must_use]
    pub fn port(&self) -> DevIndex {
        self.port
    }

    /// Create a pattern template from `pattern`'s items and masks.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error if it rejects the pattern.
    pub fn pattern_template<D: Domain, Pos>(
        &self,
        pattern: &Pattern<Pos>,
    ) -> Result<PatternTemplate<'dev, D>, FlowError> {
        // SAFETY: zero is valid for this C struct.
        let mut attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
        attr.set_direction(D::DIRECTION);
        let items = item::lower(&pattern.items);
        // SAFETY: an all-zero `rte_flow_error` is a valid out-parameter.
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: the attribute and items (and what they point at) outlive the call.
        let raw = unsafe {
            rte_flow_pattern_template_create(
                self.port.as_u16(),
                &raw const attr,
                items.as_ptr(),
                &raw mut error,
            )
        };
        match NonNull::new(raw) {
            Some(raw) => Ok(PatternTemplate {
                port: self.port,
                raw,
                shapes: pattern.shapes.clone(),
                resource: Resource::default(),
                _dev: PhantomData,
                _domain: PhantomData,
            }),
            None => Err(FlowError::from_raw(&error)),
        }
    }

    /// Create an actions template.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error if it rejects the actions.
    pub fn actions_template<D: Domain>(
        &self,
        actions: &[TemplateAction],
    ) -> Result<ActionsTemplate<'dev, D>, FlowError> {
        // SAFETY: zero is valid for this C struct.
        let mut attr: rte_flow_actions_template_attr = unsafe { core::mem::zeroed() };
        attr.set_direction(D::DIRECTION);
        let (values, masks) = actions::template(actions);
        let (values_ffi, masks_ffi) = (actions::lower(&values), actions::lower(&masks));
        // SAFETY: an all-zero `rte_flow_error` is a valid out-parameter.
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: the attribute and arrays (and what they point at) outlive the call.
        let raw = unsafe {
            rte_flow_actions_template_create(
                self.port.as_u16(),
                &raw const attr,
                values_ffi.as_ptr(),
                masks_ffi.as_ptr(),
                &raw mut error,
            )
        };
        match NonNull::new(raw) {
            Some(raw) => Ok(ActionsTemplate {
                port: self.port,
                raw,
                actions: actions.to_vec(),
                resource: Resource::default(),
                _dev: PhantomData,
                _domain: PhantomData,
            }),
            None => Err(FlowError::from_raw(&error)),
        }
    }

    /// Add a meter profile.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error, for instance if the identifier is taken.
    pub fn meter_profile(
        &self,
        id: MeterProfileId,
        profile: &MeterProfile,
    ) -> Result<MeterProfileHandle<'dev>, MeterError> {
        MeterProfileHandle::add(self.port, id, profile)
    }

    /// Create a meter with `profile`, for rules to share through [`RuleArg::Meter`], and wait
    /// for it to be created.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error, for instance when the configured meters run out.
    pub fn meter<'p, D: Domain>(
        &'p self,
        profile: &'p MeterProfileHandle<'dev>,
    ) -> Result<Meter<'p, D>, TemplateError> {
        Meter::new(self, profile)
    }

    /// A new tag for an operation, to pass as its `user_data` and then to
    /// [`complete`](Self::complete).
    pub(crate) fn tag(&self) -> *mut core::ffi::c_void {
        let mut tag = self.last_op.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        // Zero is no tag: a null `user_data`.
        if tag == 0 {
            tag = self.last_op.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        }
        core::ptr::without_provenance_mut(tag)
    }

    /// Push queued operations and wait for completion of `tag`.
    /// A missing completion leaves the handle pending; callers must not reuse it.
    /// Late completions from abandoned handles can be discarded.
    ///
    /// Count sleeps because this runs in `Drop`, where a paused virtual clock may never advance.
    /// Oversleeping only lengthens the wait.
    pub(crate) fn complete(
        &self,
        what: &'static str,
        tag: *mut core::ffi::c_void,
    ) -> Result<(), TemplateError> {
        let port = self.port.as_u16();
        // SAFETY: plain FFI call on a queue this context owns.
        check(|error| unsafe { rte_flow_push(port, QUEUE, error) })
            .map_err(|source| TemplateError::Completion { what, source })?;
        let (mut spins, mut slept) = (0, Duration::ZERO);
        loop {
            let mut result = rte_flow_op_result {
                status: rte_flow_op_status::RTE_FLOW_OP_SUCCESS,
                user_data: core::ptr::null_mut(),
            };
            // SAFETY: an all-zero `rte_flow_error` is a valid out-parameter.
            let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
            // SAFETY: room for one result; the queue is this context's.
            let pulled = unsafe { rte_flow_pull(port, QUEUE, &raw mut result, 1, &raw mut error) };
            match pulled {
                1 if result.user_data != tag => {}
                1 if result.status == rte_flow_op_status::RTE_FLOW_OP_SUCCESS => return Ok(()),
                1 => return Err(TemplateError::OperationFailed(what)),
                0 if spins < SPINS => {
                    spins += 1;
                    core::hint::spin_loop();
                }
                0 if slept < self.timeout => {
                    std::thread::sleep(POLL_INTERVAL);
                    slept += POLL_INTERVAL;
                }
                0 => return Err(TemplateError::Timeout(what)),
                _ => {
                    return Err(TemplateError::Completion {
                        what,
                        source: FlowError::from_raw(&error),
                    });
                }
            }
        }
    }
}

impl Drop for TemplateFlows<'_> {
    fn drop(&mut self) {
        self.in_use.store(false, Ordering::Release);
    }
}

/// A pattern template: which items a table's rules match, and with which masks.
#[derive(Debug)]
pub struct PatternTemplate<'dev, D: Domain> {
    port: DevIndex,
    raw: NonNull<rte_flow_pattern_template>,
    shapes: Vec<ItemShape>,
    resource: Resource,
    _dev: PhantomData<&'dev ()>,
    _domain: PhantomData<D>,
}

impl<D: Domain> Drop for PatternTemplate<'_, D> {
    fn drop(&mut self) {
        if self.resource.in_use() {
            warn!(
                "keeping a pattern template on port {} until it closes: native tables still use it",
                self.port
            );
            return;
        }
        // SAFETY: the template is live and owned, with no native dependents remaining.
        if let Err(e) = check(|error| unsafe {
            rte_flow_pattern_template_destroy(self.port.as_u16(), self.raw.as_ptr(), error)
        }) {
            warn!(
                "failed to destroy a pattern template on port {}: {e}",
                self.port
            );
        }
    }
}

/// An actions template: what a table's rules do, and which parts each rule chooses.
#[derive(Debug)]
pub struct ActionsTemplate<'dev, D: Domain> {
    port: DevIndex,
    raw: NonNull<rte_flow_actions_template>,
    actions: Vec<TemplateAction>,
    resource: Resource,
    _dev: PhantomData<&'dev ()>,
    _domain: PhantomData<D>,
}

impl<D: Domain> Drop for ActionsTemplate<'_, D> {
    fn drop(&mut self) {
        if self.resource.in_use() {
            warn!(
                "keeping an actions template on port {} until it closes: native tables still use it",
                self.port
            );
            return;
        }
        // SAFETY: the template is live and owned, with no native dependents remaining.
        if let Err(e) = check(|error| unsafe {
            rte_flow_actions_template_destroy(self.port.as_u16(), self.raw.as_ptr(), error)
        }) {
            warn!(
                "failed to destroy an actions template on port {}: {e}",
                self.port
            );
        }
    }
}
