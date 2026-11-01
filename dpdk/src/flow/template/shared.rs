// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Template objects that own what they depend on, for rule sets that outlive the code that built
//! them.
//!
//! The borrowed handles ([`TemplateTable`], [`TemplateRule`], [`Meter`]) tie each object to a
//! borrow of what it depends on, so the compiler enforces that a rule goes before its table and
//! meters, a table before its templates, a meter before its profile. That suits a rule set built
//! and held in one place. A rule set that is built while another serves, and replaced while
//! others stay (one generation of rules after another), cannot be expressed that way.
//!
//! These handles keep their dependencies alive instead: a [`SharedRule`] owns its table and
//! meters, a [`SharedTable`] its templates, a [`SharedMeter`] its profile, by reference counting.
//! Whatever the order handles are dropped in, each object is destroyed after everything that uses
//! it. They borrow only the [`TemplateFlows`] context, and like it they stay on its thread.

use alloc::rc::Rc;
use alloc::vec::Vec;

use crate::flow::{Domain, FlowGroup};

use super::{
    ActionsTemplate, Counts, Meter, MeterProfileHandle, Pattern, PatternTemplate, RuleArg,
    TableConfig, TemplateError, TemplateFlows, TemplateRule, TemplateTable,
};

/// A pattern template, shared by the tables using it.
pub type SharedPatternTemplate<'t, D> = Rc<PatternTemplate<'t, D>>;

/// An actions template, shared by the tables using it.
pub type SharedActionsTemplate<'t, D> = Rc<ActionsTemplate<'t, D>>;

/// A meter profile, shared by the meters using it.
pub type SharedMeterProfile<'t> = Rc<MeterProfileHandle<'t>>;

/// A meter that keeps its profile alive; clones share the meter (and its token state).
#[derive(Debug)]
pub struct SharedMeter<'t, D: Domain> {
    inner: Rc<MeterInner<'t, D>>,
}

// Fields drop in order: the meter before its profile.
#[derive(Debug)]
struct MeterInner<'t, D: Domain> {
    meter: Meter<'t, D>,
    _profile: SharedMeterProfile<'t>,
}

impl<D: Domain> Clone for SharedMeter<'_, D> {
    fn clone(&self) -> Self {
        SharedMeter {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<'t, D: Domain> SharedMeter<'t, D> {
    /// Create a meter with `profile` on `flows`' port, and wait for it.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error, for instance when the configured meters run out.
    pub fn new(
        flows: &'t TemplateFlows<'t>,
        profile: &SharedMeterProfile<'t>,
    ) -> Result<SharedMeter<'t, D>, TemplateError> {
        Ok(SharedMeter {
            inner: Rc::new(MeterInner {
                meter: Meter::new(flows, profile)?,
                _profile: Rc::clone(profile),
            }),
        })
    }

    /// Whether `self` and `other` are the same meter.
    #[must_use]
    pub fn same(&self, other: &SharedMeter<'t, D>) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }
}

/// A template table that keeps its templates alive; clones share the table.
#[derive(Debug)]
pub struct SharedTable<'t, D: Domain> {
    inner: Rc<TableInner<'t, D>>,
}

// Fields drop in order: the table before its templates.
#[derive(Debug)]
struct TableInner<'t, D: Domain> {
    table: TemplateTable<'t, D>,
    _patterns: Vec<SharedPatternTemplate<'t, D>>,
    _actions: Vec<SharedActionsTemplate<'t, D>>,
}

impl<D: Domain> Clone for SharedTable<'_, D> {
    fn clone(&self) -> Self {
        SharedTable {
            inner: Rc::clone(&self.inner),
        }
    }
}

/// A per-rule argument of a [`SharedRule`]; see [`RuleArg`].
#[derive(Debug)]
pub enum SharedArg<'t, D: Domain> {
    /// The meter for a [`TemplateAction::Meter`](super::TemplateAction::Meter).
    Meter(SharedMeter<'t, D>),
    /// The group for a [`TemplateAction::JumpPerRule`](super::TemplateAction::JumpPerRule).
    Jump(FlowGroup),
}

impl<D: Domain> Clone for SharedArg<'_, D> {
    fn clone(&self) -> Self {
        match self {
            SharedArg::Meter(meter) => SharedArg::Meter(meter.clone()),
            SharedArg::Jump(group) => SharedArg::Jump(*group),
        }
    }
}

/// The borrowed arguments `args` stand for, and the meters to keep alive with the rule.
fn borrowed<'a, 't, D: Domain>(
    args: &'a [SharedArg<'t, D>],
) -> (Vec<RuleArg<'a, D>>, Vec<SharedMeter<'t, D>>) {
    let mut meters = Vec::new();
    let args = args
        .iter()
        .map(|arg| match arg {
            SharedArg::Meter(meter) => {
                meters.push(meter.clone());
                RuleArg::Meter(&meter.inner.meter)
            }
            SharedArg::Jump(group) => RuleArg::Jump(*group),
        })
        .collect();
    (args, meters)
}

impl<'t, D: Domain> SharedTable<'t, D> {
    /// Create a table on `flows`' port whose rules use one of `patterns` and one of `actions`, by
    /// index; see [`TemplateFlows::table`].
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::TooManyTemplates`] for more than 255 templates of a kind, or the
    /// PMD's error.
    pub fn new(
        flows: &'t TemplateFlows<'t>,
        config: TableConfig,
        patterns: &[SharedPatternTemplate<'t, D>],
        actions: &[SharedActionsTemplate<'t, D>],
    ) -> Result<SharedTable<'t, D>, TemplateError> {
        let pattern_refs: Vec<&PatternTemplate<'t, D>> = patterns.iter().map(|p| &**p).collect();
        let action_refs: Vec<&ActionsTemplate<'t, D>> = actions.iter().map(|a| &**a).collect();
        Ok(SharedTable {
            inner: Rc::new(TableInner {
                table: flows.table_unbound(config, &pattern_refs, &action_refs)?,
                _patterns: patterns.to_vec(),
                _actions: actions.to_vec(),
            }),
        })
    }

    /// Insert a rule; see [`TemplateTable::insert`]. The rule keeps the table and its meters
    /// alive.
    ///
    /// # Errors
    ///
    /// As [`TemplateTable::insert`].
    pub fn insert<Pos>(
        &self,
        pattern_template: usize,
        pattern: &Pattern<Pos>,
        actions_template: usize,
        args: &[SharedArg<'t, D>],
    ) -> Result<SharedRule<'t, D>, TemplateError> {
        let (borrowed, meters) = borrowed(args);
        let rule = self.inner.table.insert_unbound(
            pattern_template,
            pattern,
            actions_template,
            &borrowed,
        )?;
        Ok(SharedRule {
            rule,
            _table: self.clone(),
            _meters: meters,
        })
    }

    /// Replace the actions of `rule`, a rule of this table, in place; see
    /// [`TemplateTable::update`]. The rule then keeps the new arguments' meters alive instead of
    /// the old ones.
    ///
    /// # Errors
    ///
    /// As [`TemplateTable::update`]; the rule then keeps its old actions and meters.
    pub fn update(
        &self,
        rule: &mut SharedRule<'t, D>,
        actions_template: usize,
        args: &[SharedArg<'t, D>],
    ) -> Result<(), TemplateError> {
        let (borrowed, meters) = borrowed(args);
        self.inner
            .table
            .update(&mut rule.rule, actions_template, &borrowed)?;
        // The old meters may go now: the rule no longer uses them.
        rule._meters = meters;
        Ok(())
    }
}

/// A rule that keeps its table and meters alive.
#[derive(Debug)]
#[must_use = "dropping a SharedRule immediately destroys the hardware rule"]
pub struct SharedRule<'t, D: Domain> {
    // Fields drop in order: the rule before its table and meters.
    rule: TemplateRule<'t>,
    _table: SharedTable<'t, D>,
    _meters: Vec<SharedMeter<'t, D>>,
}

impl<D: Domain> SharedRule<'_, D> {
    /// Read the rule's counter; see [`TemplateRule::counts`].
    ///
    /// # Errors
    ///
    /// As [`TemplateRule::counts`].
    pub fn counts(&self) -> Result<Counts, TemplateError> {
        self.rule.counts()
    }

    /// Destroy the rule and wait for it to be removed; see [`TemplateRule::destroy`]. Dropping
    /// does the same but can only log errors.
    ///
    /// # Errors
    ///
    /// As [`TemplateRule::destroy`]: the rule is then left in place, counted as leaked.
    pub fn destroy(self) -> Result<(), TemplateError> {
        self.rule.destroy()
    }
}
