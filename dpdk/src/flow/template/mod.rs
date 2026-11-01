// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Template rules: the `rte_flow` template API, which mlx5 serves with hardware steering
//! (`dv_flow_en=2`).
//!
//! Configure the device for templates before starting it
//! ([`Dev::configure_templates`](crate::dev::Dev::configure_templates)).
//! On the started device, a [`TemplateFlows`] context creates [`PatternTemplate`]s,
//! [`ActionsTemplate`]s, [`TemplateTable`]s built from them, meters, and rules.
//! Each handle borrows what it depends on: a table cannot outlive its templates, a rule its table
//! or its meter, or anything the device.
//!
//! The template API is asynchronous: operations are queued, pushed, and completed later.
//! A context owns flow queue 0 of its port and waits for each operation to complete, so it is a
//! synchronous facade; it is bound to its thread, and a port has at most one at a time.

mod actions;
mod meter;
mod pattern;
mod table;

pub use actions::{ArgumentError, RuleArg, TemplateAction};
pub use meter::{
    Meter, MeterAlgorithm, MeterError, MeterProfile, MeterProfileHandle, MeterProfileId, MeterUnit,
};
pub use pattern::{Color, Colored, Complete, InnerEth, Pattern};
pub use table::{Counts, TableConfig, TemplateRule, TemplateTable};

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
use crate::flow::{Direction, Domain, FlowError, item};
use concurrency::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The flow queue every [`TemplateFlows`] uses.
const QUEUE: u32 = 0;

/// How long an operation may take to complete before it is reported as lost.
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(5);

/// Resources the PMD reserves for template rules when the port is configured.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TemplateConfig {
    /// Operations flow queue 0 holds at once.
    pub queue_size: u32,
    /// Counters for [`TemplateAction::Count`].
    pub counters: u32,
    /// Meters ([`Meter`]); rounded up to a power of two.
    pub meters: u32,
}

/// The template state of a port, kept by the device.
#[derive(Debug, Default)]
pub(crate) struct PortTemplates {
    /// [`Dev::configure_templates`] succeeded.
    configured: bool,
    /// A [`TemplateFlows`] owns flow queue 0.
    in_use: AtomicBool,
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
    /// Restrict ingress to the port's flow rules ("isolated mode").
    ///
    /// On a bifurcated port (mlx5), everything no rule takes stays with the kernel's netdev, so a
    /// process can install rules without receiving any traffic.
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
    /// Returns the PMD's error, for instance if the port does not support templates (mlx5 needs
    /// the `dv_flow_en=2` device argument).
    pub fn configure_templates(&mut self, config: &TemplateConfig) -> Result<(), FlowError> {
        let port = self.info().index().as_u16();
        // SAFETY: zero is valid for these C structs.
        let mut port_attr: rte_flow_port_attr = unsafe { core::mem::zeroed() };
        port_attr.nb_counters = config.counters;
        // mlx5 sizes its meter object for `rte_align32pow2(nb_meters >> 1)` pairs of meters, so an
        // odd count leaves the last meter outside it, and rules using that meter fail in hardware
        // (`mlx5_flow_meter_init`, which computes `rte_align32pow2(nb_meters)` but does not use it).
        port_attr.nb_meters = match config.meters {
            0 => 0,
            meters => meters.checked_next_power_of_two().unwrap_or(meters).max(2),
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
            live_rules: dev.live_rules(),
            in_use: &templates.in_use,
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
        match D::DIRECTION {
            Direction::Ingress => attr.set_ingress(1),
            Direction::Egress => attr.set_egress(1),
            Direction::Transfer => attr.set_transfer(1),
        }
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
        match D::DIRECTION {
            Direction::Ingress => attr.set_ingress(1),
            Direction::Egress => attr.set_egress(1),
            Direction::Transfer => attr.set_transfer(1),
        }
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

    /// Create a meter with `profile`, for rules to share through [`RuleArg::Meter`].
    ///
    /// # Errors
    ///
    /// Returns the PMD's error, for instance when the configured meters run out.
    pub fn meter<'p, D: Domain>(
        &self,
        profile: &'p MeterProfileHandle<'dev>,
    ) -> Result<Meter<'p, D>, FlowError> {
        Meter::new(profile)
    }

    /// Push queued operations and wait for one to complete.
    ///
    /// Each operation waits for its own completion before the next is queued, so the completion
    /// pulled is that operation's.
    fn complete(&self, what: &'static str) -> Result<(), TemplateError> {
        let port = self.port.as_u16();
        // SAFETY: plain FFI call on a queue this context owns.
        check(|error| unsafe { rte_flow_push(port, QUEUE, error) })?;
        let deadline = clock::deadline(COMPLETION_TIMEOUT);
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
                1 if result.status == rte_flow_op_status::RTE_FLOW_OP_SUCCESS => return Ok(()),
                1 => return Err(TemplateError::OperationFailed(what)),
                0 if clock::now() < deadline => core::hint::spin_loop(),
                0 => return Err(TemplateError::Timeout(what)),
                _ => return Err(FlowError::from_raw(&error).into()),
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
    _dev: PhantomData<&'dev ()>,
    _domain: PhantomData<D>,
}

impl<D: Domain> Drop for PatternTemplate<'_, D> {
    fn drop(&mut self) {
        // SAFETY: the template is live and owned; tables using it borrow it, so none remain.
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
    _dev: PhantomData<&'dev ()>,
    _domain: PhantomData<D>,
}

impl<D: Domain> Drop for ActionsTemplate<'_, D> {
    fn drop(&mut self) {
        // SAFETY: the template is live and owned; tables using it borrow it, so none remain.
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
