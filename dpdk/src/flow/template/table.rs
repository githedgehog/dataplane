// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Template tables and the rules inserted into them.

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ptr::NonNull;

#[cfg(any(test, feature = "template-test"))]
use super::testing::ffi as dpdk_sys;

use dpdk_sys::{
    rte_flow, rte_flow_action, rte_flow_action_type as at, rte_flow_async_actions_update,
    rte_flow_async_create, rte_flow_async_destroy, rte_flow_error, rte_flow_op_attr,
    rte_flow_query, rte_flow_query_count, rte_flow_table_insertion_type, rte_flow_template_table,
    rte_flow_template_table_attr, rte_flow_template_table_create, rte_flow_template_table_destroy,
};
use tracing::warn;

use crate::flow::pattern::ItemShape;
use crate::flow::{Domain, FlowError, FlowGroup, Priority, SetDirection, item};
use concurrency::sync::atomic::Ordering;

use super::actions::{self, RuleArg, TemplateAction};
use super::lifetime::{Dependencies, Resource};
use super::{
    ActionsTemplate, Pattern, PatternTemplate, QUEUE, TemplateError, TemplateFlows, check,
    same_port,
};

/// Where a table sits and how many rules it holds.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TableConfig {
    /// The group the table's rules are in.
    pub group: FlowGroup,
    /// The table's priority within its group: lower values are matched first.
    pub priority: Priority,
    /// The most rules the table holds.
    pub capacity: u32,
}

/// A template table: rules of the given pattern and actions templates, in one group.
#[derive(Debug)]
pub struct TemplateTable<'t, D: Domain> {
    flows: &'t TemplateFlows<'t>,
    raw: NonNull<rte_flow_template_table>,
    patterns: Vec<Vec<ItemShape>>,
    actions: Vec<Vec<TemplateAction>>,
    resource: Resource,
    templates: Dependencies,
    destroy_attempted: bool,
    _domain: PhantomData<D>,
}

impl<'t> TemplateFlows<'t> {
    /// Create a table whose rules use one of `patterns` and one of `actions`, by index.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::TooManyTemplates`] for more than 255 templates of a kind, or the
    /// PMD's error.
    pub fn table<D: Domain>(
        &'t self,
        config: TableConfig,
        patterns: &[&'t PatternTemplate<'_, D>],
        actions: &[&'t ActionsTemplate<'_, D>],
    ) -> Result<TemplateTable<'t, D>, TemplateError> {
        self.table_unbound(config, patterns, actions)
    }

    /// [`table`](Self::table), but the caller keeps the templates alive as long as the table:
    /// [`SharedTable`](super::SharedTable) by owning them.
    pub(crate) fn table_unbound<D: Domain>(
        &'t self,
        config: TableConfig,
        patterns: &[&PatternTemplate<'_, D>],
        actions: &[&ActionsTemplate<'_, D>],
    ) -> Result<TemplateTable<'t, D>, TemplateError> {
        for pattern in patterns {
            same_port("a pattern template", self.port, pattern.port)?;
        }
        for action in actions {
            same_port("an actions template", self.port, action.port)?;
        }
        let count = |n: usize| u8::try_from(n).map_err(|_| TemplateError::TooManyTemplates(n));
        let (n_patterns, n_actions) = (count(patterns.len())?, count(actions.len())?);
        // SAFETY: zero is valid for this C struct.
        let mut attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
        attr.flow_attr.group = config.group.0;
        attr.flow_attr.priority = config.priority.0;
        attr.flow_attr.set_direction(D::DIRECTION);
        attr.nb_flows = config.capacity;
        attr.insertion_type = rte_flow_table_insertion_type::RTE_FLOW_TABLE_INSERTION_TYPE_PATTERN;
        let mut pattern_ptrs: Vec<_> = patterns.iter().map(|p| p.raw.as_ptr()).collect();
        let mut action_ptrs: Vec<_> = actions.iter().map(|a| a.raw.as_ptr()).collect();
        // SAFETY: an all-zero `rte_flow_error` is a valid out-parameter.
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: the attribute and arrays outlive the call; the templates outlive the table.
        let raw = unsafe {
            rte_flow_template_table_create(
                self.port.as_u16(),
                &raw const attr,
                pattern_ptrs.as_mut_ptr(),
                n_patterns,
                action_ptrs.as_mut_ptr(),
                n_actions,
                &raw mut error,
            )
        };
        let raw = NonNull::new(raw).ok_or_else(|| FlowError::from_raw(&error))?;
        Ok(TemplateTable {
            flows: self,
            raw,
            patterns: patterns.iter().map(|p| p.shapes.clone()).collect(),
            actions: actions.iter().map(|a| a.actions.clone()).collect(),
            resource: Resource::default(),
            templates: Dependencies(
                patterns
                    .iter()
                    .map(|p| p.resource.clone())
                    .chain(actions.iter().map(|a| a.resource.clone()))
                    .collect(),
            ),
            destroy_attempted: false,
            _domain: PhantomData,
        })
    }
}

impl<'t, D: Domain> TemplateTable<'t, D> {
    /// Check that `args`' meters are of this table's port.
    fn args_on_port(&self, args: &[RuleArg<'_, D>]) -> Result<(), TemplateError> {
        for arg in args {
            if let RuleArg::Meter(meter) = arg {
                same_port("a meter", self.flows.port, meter.port())?;
            }
        }
        Ok(())
    }

    /// Insert a rule matching `pattern` with pattern template `pattern_template`, acting with
    /// actions template `actions_template`, given its per-rule `args`.
    ///
    /// Waits for the rule to be installed.
    ///
    /// # Errors
    ///
    /// Returns an error if a template index is out of range, if `pattern` does not have the shape
    /// of its template, if `args` do not fit the actions template, or if the PMD fails.
    pub fn insert<'r, Pos>(
        &'r self,
        pattern_template: usize,
        pattern: &Pattern<Pos>,
        actions_template: usize,
        args: &[RuleArg<'r, D>],
    ) -> Result<TemplateRule<'r>, TemplateError> {
        self.insert_unbound(pattern_template, pattern, actions_template, args)
    }

    /// [`insert`](Self::insert), but the rule is not bound to a borrow of the table, nor of its
    /// meters: the caller keeps them alive as long as the rule ([`SharedRule`](super::SharedRule)
    /// by owning them).
    pub(crate) fn insert_unbound<Pos>(
        &self,
        pattern_template: usize,
        pattern: &Pattern<Pos>,
        actions_template: usize,
        args: &[RuleArg<'_, D>],
    ) -> Result<TemplateRule<'t>, TemplateError> {
        let shapes = self
            .patterns
            .get(pattern_template)
            .ok_or(TemplateError::NoSuchTemplate {
                kind: "pattern",
                index: pattern_template,
                count: self.patterns.len(),
            })?;
        if *shapes != pattern.shapes {
            return Err(TemplateError::PatternShape {
                template: shapes.clone(),
                rule: pattern.shapes.clone(),
            });
        }
        let template_actions =
            self.actions
                .get(actions_template)
                .ok_or(TemplateError::NoSuchTemplate {
                    kind: "actions",
                    index: actions_template,
                    count: self.actions.len(),
                })?;
        self.args_on_port(args)?;
        let owned = actions::rule(template_actions, args)?;
        let items = item::lower(&pattern.items);
        let actions = actions::lower(&owned);
        let flows = self.flows;
        // SAFETY: zero is valid for this C struct; a cleared `postpone` pushes at once.
        let op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
        // SAFETY: an all-zero `rte_flow_error` is a valid out-parameter.
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        let tag = flows.tag();
        // SAFETY: the arrays (and what they point at) outlive the call, which copies them; the
        // indices are in range (checked above, and fewer than 256 by construction of the table).
        let flow = unsafe {
            rte_flow_async_create(
                flows.port.as_u16(),
                QUEUE,
                &raw const op_attr,
                self.raw.as_ptr(),
                items.as_ptr(),
                pattern_template as u8,
                actions.as_ptr(),
                actions_template as u8,
                tag,
                &raw mut error,
            )
        };
        let flow = NonNull::new(flow).ok_or_else(|| FlowError::from_raw(&error))?;
        // A handle exists once enqueued, but it may only be destroyed after creation completes.
        // Missing completions leave the rule and its native dependencies for port teardown.
        flows.live_rules.fetch_add(1, Ordering::AcqRel);
        let mut rule = TemplateRule {
            flows,
            flow,
            table: self.raw,
            counted: template_actions.contains(&TemplateAction::Count),
            table_dependency: Dependencies(vec![self.resource.clone()]),
            meters: Dependencies(meter_dependencies(args)),
            pending: true,
            destroy_attempted: false,
        };
        let result = flows.complete("rule creation", tag);
        rule.pending = result.as_ref().is_err_and(TemplateError::is_pending);
        result?;
        Ok(rule)
    }

    /// Replace the actions of `rule`, a rule of this table, with those of actions template
    /// `actions_template` given `args`, in place, and wait for it.
    ///
    /// The PMD swaps the actions of the installed rule: a packet sees the old actions or the new
    /// ones, not a rule that is missing.
    ///
    /// The new meters must outlive the rule, as those it was inserted with:
    ///
    /// ```compile_fail,E0597
    /// # use dataplane_dpdk::flow::Ingress;
    /// # use dataplane_dpdk::flow::template::{
    /// #     MeterProfileHandle, Pattern, RuleArg, TemplateFlows, TemplateTable,
    /// # };
    /// fn short_lived_meter<'t, P>(
    ///     flows: &'t TemplateFlows<'t>,
    ///     profile: &'t MeterProfileHandle<'t>,
    ///     table: &TemplateTable<'t, Ingress>,
    ///     pattern: &Pattern<P>,
    /// ) {
    ///     let m1 = flows.meter::<Ingress>(profile).unwrap();
    ///     let mut rule = table.insert(0, pattern, 0, &[RuleArg::Meter(&m1)]).unwrap();
    ///     {
    ///         let m2 = flows.meter::<Ingress>(profile).unwrap();
    ///         table.update(&mut rule, 0, &[RuleArg::Meter(&m2)]).unwrap();
    ///     }
    ///     drop(rule);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::ForeignRule`] if `rule` is not in this table, an error if the
    /// template index is out of range, if `args` do not fit it, or if the PMD fails. After enqueue,
    /// an error may leave either action set installed. Missing completions leave the rule pending:
    /// further updates and queries return [`TemplateError::Pending`], and drop retains native
    /// resources until port teardown.
    pub fn update<'r>(
        &self,
        rule: &mut TemplateRule<'r>,
        actions_template: usize,
        args: &[RuleArg<'r, D>],
    ) -> Result<(), TemplateError> {
        self.update_unbound(rule, actions_template, args)
    }

    /// [`update`](Self::update), but the new meters are not bound to the rule's lifetime: the
    /// caller keeps them alive as long as the rule ([`SharedRule`](super::SharedRule) by owning
    /// them).
    pub(crate) fn update_unbound(
        &self,
        rule: &mut TemplateRule<'_>,
        actions_template: usize,
        args: &[RuleArg<'_, D>],
    ) -> Result<(), TemplateError> {
        if rule.table != self.raw {
            return Err(TemplateError::ForeignRule);
        }
        if rule.pending {
            return Err(TemplateError::Pending);
        }
        self.args_on_port(args)?;
        let template_actions =
            self.actions
                .get(actions_template)
                .ok_or(TemplateError::NoSuchTemplate {
                    kind: "actions",
                    index: actions_template,
                    count: self.actions.len(),
                })?;
        let owned = actions::rule(template_actions, args)?;
        let actions = actions::lower(&owned);
        let flows = self.flows;
        // SAFETY: zero is valid for this C struct; a cleared `postpone` pushes at once.
        let op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
        let tag = flows.tag();
        // SAFETY: the rule is live and of this table (checked above); the actions outlive the
        // call, which copies them; the index is in range (checked above, and below 256 by
        // construction).
        check(|error| unsafe {
            rte_flow_async_actions_update(
                flows.port.as_u16(),
                QUEUE,
                &raw const op_attr,
                rule.flow.as_ptr(),
                actions.as_ptr(),
                actions_template as u8,
                tag,
                error,
            )
        })?;
        // After enqueue, every completion error must preserve both dependency sets, including
        // push/pull errors. A later completion must not race another operation on this handle.
        rule.pending = true;
        let mut meters = Dependencies(meter_dependencies(args));
        let result = flows.complete("rule update", tag);
        rule.pending = result.as_ref().is_err_and(TemplateError::is_pending);
        if result.is_ok() {
            rule.meters.release();
        }
        rule.meters.0.append(&mut meters.0);
        // After a failed update either action set may be installed: query only if both count.
        let counts = template_actions.contains(&TemplateAction::Count);
        rule.counted = if result.is_ok() {
            counts
        } else {
            rule.counted && counts
        };
        result
    }
}

impl<D: Domain> TemplateTable<'_, D> {
    /// Destroy the table. Drop does the same but can only log errors.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::InUse`] if abandoned or forgotten rules still use the table,
    /// or the PMD's error. On failure, the native table and its templates are retained until
    /// port teardown, and the handle is gone, so the destroy cannot be retried; Rust allocations
    /// are still released.
    pub fn destroy(mut self) -> Result<(), TemplateError> {
        self.remove()
    }

    fn remove(&mut self) -> Result<(), TemplateError> {
        if core::mem::replace(&mut self.destroy_attempted, true) {
            return Ok(());
        }
        if self.resource.in_use() {
            return Err(TemplateError::InUse);
        }
        let port = self.flows.port;
        // SAFETY: the table is live and owned, with no native rules remaining.
        check(|error| unsafe {
            rte_flow_template_table_destroy(port.as_u16(), self.raw.as_ptr(), error)
        })?;
        self.templates.release();
        Ok(())
    }
}

impl<D: Domain> Drop for TemplateTable<'_, D> {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            warn!(
                "failed to destroy a template table on port {}: {e}",
                self.flows.port
            );
        }
    }
}

/// Packets and bytes a rule's [`TemplateAction::Count`] has seen.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    /// Packets.
    pub packets: u64,
    /// Bytes.
    pub bytes: u64,
}

/// An installed template rule, destroyed on drop.
///
/// It cannot outlive its table:
///
/// ```compile_fail,E0597
/// # use dataplane_dpdk::flow::Ingress;
/// # use dataplane_dpdk::flow::template::{
/// #     ActionsTemplate, Pattern, PatternTemplate, TableConfig, TemplateFlows,
/// # };
/// fn rule_outlives_table<'t, P>(
///     flows: &'t TemplateFlows<'t>,
///     config: TableConfig,
///     pattern_template: &'t PatternTemplate<'t, Ingress>,
///     actions_template: &'t ActionsTemplate<'t, Ingress>,
///     pattern: &Pattern<P>,
/// ) {
///     let rule;
///     {
///         let table = flows.table(config, &[pattern_template], &[actions_template]).unwrap();
///         rule = table.insert(0, pattern, 0, &[]).unwrap();
///     }
///     drop(rule);
/// }
/// ```
///
/// nor its meters:
///
/// ```compile_fail,E0597
/// # use dataplane_dpdk::flow::Ingress;
/// # use dataplane_dpdk::flow::template::{
/// #     MeterProfileHandle, Pattern, RuleArg, TemplateFlows, TemplateTable,
/// # };
/// fn rule_outlives_meter<'t, P>(
///     flows: &'t TemplateFlows<'t>,
///     profile: &'t MeterProfileHandle<'t>,
///     table: &TemplateTable<'t, Ingress>,
///     pattern: &Pattern<P>,
/// ) {
///     let rule;
///     {
///         let meter = flows.meter::<Ingress>(profile).unwrap();
///         rule = table.insert(0, pattern, 0, &[RuleArg::Meter(&meter)]).unwrap();
///     }
///     drop(rule);
/// }
/// ```
///
/// If destroying it fails, the rule may stay in the NIC. Its native table, templates, meters
/// and meter profiles are retained until the port is closed.
#[derive(Debug)]
#[must_use = "dropping a TemplateRule immediately destroys the hardware rule"]
pub struct TemplateRule<'r> {
    flows: &'r TemplateFlows<'r>,
    flow: NonNull<rte_flow>,
    /// The table it is in, to refuse updates through another.
    table: NonNull<rte_flow_template_table>,
    counted: bool,
    table_dependency: Dependencies,
    meters: Dependencies,
    pending: bool,
    destroy_attempted: bool,
}

impl TemplateRule<'_> {
    /// Read the rule's counter, which keeps counting.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::Pending`] if an operation has no collected completion,
    /// [`TemplateError::NotCounted`] if its actions do not count, or the PMD's error.
    pub fn counts(&self) -> Result<Counts, TemplateError> {
        if self.pending {
            return Err(TemplateError::Pending);
        }
        if !self.counted {
            return Err(TemplateError::NotCounted);
        }
        let query = [
            rte_flow_action {
                type_: at::RTE_FLOW_ACTION_TYPE_COUNT,
                conf: core::ptr::null(),
            },
            rte_flow_action {
                type_: at::RTE_FLOW_ACTION_TYPE_END,
                conf: core::ptr::null(),
            },
        ];
        // SAFETY: zero is valid for this C struct; a clear `reset` bit keeps the counter.
        let mut count: rte_flow_query_count = unsafe { core::mem::zeroed() };
        let port = self.flows.port.as_u16();
        // SAFETY: the rule is live; the action array and output outlive the call.
        check(|error| unsafe {
            rte_flow_query(
                port,
                self.flow.as_ptr(),
                query.as_ptr(),
                (&raw mut count).cast(),
                error,
            )
        })?;
        Ok(Counts {
            packets: count.hits,
            bytes: count.bytes,
        })
    }

    /// Destroy the rule and wait for it to be removed. Drop does the same but can only log errors.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error, or [`TemplateError::Pending`] if creation or update has no
    /// collected completion. The rule and its native dependencies are retained for port teardown.
    pub fn destroy(mut self) -> Result<(), TemplateError> {
        self.remove()
    }

    fn remove(&mut self) -> Result<(), TemplateError> {
        if core::mem::replace(&mut self.destroy_attempted, true) {
            return Ok(());
        }
        if self.pending {
            return Err(TemplateError::Pending);
        }
        let flows = self.flows;
        // SAFETY: zero is valid for this C struct; a cleared `postpone` pushes at once.
        let op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
        let tag = flows.tag();
        // SAFETY: the rule is live and owned by `self`, which is not used again.
        check(|error| unsafe {
            rte_flow_async_destroy(
                flows.port.as_u16(),
                QUEUE,
                &raw const op_attr,
                self.flow.as_ptr(),
                tag,
                error,
            )
        })?;
        flows.complete("rule destruction", tag)?;
        flows.live_rules.fetch_sub(1, Ordering::AcqRel);
        self.table_dependency.release();
        self.meters.release();
        Ok(())
    }
}

impl Drop for TemplateRule<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            warn!(
                "failed to destroy a template rule on port {}: {e}",
                self.flows.port
            );
        }
    }
}

/// Native meters a rule will use once its create/update request is enqueued.
fn meter_dependencies<D: Domain>(args: &[RuleArg<'_, D>]) -> Vec<Resource> {
    args.iter()
        .filter_map(|arg| match arg {
            RuleArg::Meter(meter) => Some(meter.resource.clone()),
            RuleArg::Jump(_) => None,
        })
        .collect()
}

#[cfg(test)]
pub(super) mod tests;
