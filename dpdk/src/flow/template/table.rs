// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Template tables and the rules inserted into them.

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ptr::NonNull;

use dpdk_sys::{
    rte_flow, rte_flow_action, rte_flow_action_type as at, rte_flow_async_create,
    rte_flow_async_destroy, rte_flow_error, rte_flow_op_attr, rte_flow_query, rte_flow_query_count,
    rte_flow_table_insertion_type, rte_flow_template_table, rte_flow_template_table_attr,
    rte_flow_template_table_create, rte_flow_template_table_destroy,
};
use tracing::warn;

use crate::flow::pattern::ItemShape;
use crate::flow::{Direction, Domain, FlowError, FlowGroup, Priority, item};
use concurrency::sync::atomic::Ordering;

use super::actions::{self, RuleArg, TemplateAction};
use super::{
    ActionsTemplate, Pattern, PatternTemplate, QUEUE, TemplateError, TemplateFlows, check,
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
        let count = |n: usize| u8::try_from(n).map_err(|_| TemplateError::TooManyTemplates(n));
        let (n_patterns, n_actions) = (count(patterns.len())?, count(actions.len())?);
        // SAFETY: zero is valid for this C struct.
        let mut attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
        attr.flow_attr.group = config.group.0;
        attr.flow_attr.priority = config.priority.0;
        match D::DIRECTION {
            Direction::Ingress => attr.flow_attr.set_ingress(1),
            Direction::Egress => attr.flow_attr.set_egress(1),
            Direction::Transfer => attr.flow_attr.set_transfer(1),
        }
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
            _domain: PhantomData,
        })
    }
}

impl<D: Domain> TemplateTable<'_, D> {
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
        let owned = actions::rule(template_actions, args)?;
        let items = item::lower(&pattern.items);
        let actions = actions::lower(&owned);
        let flows = self.flows;
        // SAFETY: zero is valid for this C struct; a cleared `postpone` pushes at once.
        let op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
        // SAFETY: an all-zero `rte_flow_error` is a valid out-parameter.
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
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
                core::ptr::null_mut(),
                &raw mut error,
            )
        };
        let flow = NonNull::new(flow).ok_or_else(|| FlowError::from_raw(&error))?;
        // The rule exists from here on, whether or not its creation completes: it is destroyed
        // (through `Drop`) on failure.
        flows.live_rules.fetch_add(1, Ordering::AcqRel);
        let rule = TemplateRule {
            flows,
            flow,
            counted: template_actions.contains(&TemplateAction::Count),
        };
        flows.complete("rule creation")?;
        Ok(rule)
    }
}

impl<D: Domain> Drop for TemplateTable<'_, D> {
    fn drop(&mut self) {
        let port = self.flows.port;
        // SAFETY: the table is live and owned; its rules borrow it, so none remain.
        if let Err(e) = check(|error| unsafe {
            rte_flow_template_table_destroy(port.as_u16(), self.raw.as_ptr(), error)
        }) {
            warn!("failed to destroy a template table on port {port}: {e}");
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
#[derive(Debug)]
#[must_use = "dropping a TemplateRule immediately destroys the hardware rule"]
pub struct TemplateRule<'r> {
    flows: &'r TemplateFlows<'r>,
    flow: NonNull<rte_flow>,
    counted: bool,
}

impl TemplateRule<'_> {
    /// Read the rule's counter, which keeps counting.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::NotCounted`] if its actions do not count, or the PMD's error.
    pub fn counts(&self) -> Result<Counts, TemplateError> {
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
    /// Returns the PMD's error. The rule is then left in place and counted as leaked; the device
    /// flushes leaked rules when it stops.
    pub fn destroy(self) -> Result<(), TemplateError> {
        let this = core::mem::ManuallyDrop::new(self);
        this.remove()
    }

    fn remove(&self) -> Result<(), TemplateError> {
        let flows = self.flows;
        // SAFETY: zero is valid for this C struct; a cleared `postpone` pushes at once.
        let op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
        // SAFETY: the rule is live and owned by `self`, which is not used again.
        check(|error| unsafe {
            rte_flow_async_destroy(
                flows.port.as_u16(),
                QUEUE,
                &raw const op_attr,
                self.flow.as_ptr(),
                core::ptr::null_mut(),
                error,
            )
        })?;
        flows.complete("rule destruction")?;
        flows.live_rules.fetch_sub(1, Ordering::AcqRel);
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
