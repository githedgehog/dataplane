// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A [`Plan`] installed on a port, and kept in step with the policy: [`Port`].

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Duration;

use dpdk::dev::{Dev, Started};
use dpdk::flow::template::{
    Color, Counts, MeterProfileId, SharedActionsTemplate, SharedArg, SharedMeter,
    SharedPatternTemplate, SharedRule, SharedTable, TableConfig, TemplateAction, TemplateError,
    TemplateFlows,
};
use dpdk::flow::{FlowGroup, Ingress, ItemShape};
use net::vxlan::Vni;
use rekon::{SyncCreate, SyncObserve, SyncReconcile, SyncRemove};
use tracing::{error, info, warn};

use super::{
    Arg, Error, Group, MeterKey, Plan, PlannedTable, PlannedVpc, RESOURCES, Role, SWITCH, VpcSpec,
    unknown_state,
};
use crate::Policy;
use crate::program::{Origin, Peering, Program};

/// How often the rules are checked against the published policy.
const POLL: Duration = Duration::from_millis(200);
/// How often hardware counters are reported.
const REPORT: Duration = Duration::from_secs(10);
/// The highest flow group mlx5 hardware steering takes (BlueField-3: 32762 groups).
const MAX_GROUP: u32 = 32_000;

type Rule<'t> = SharedRule<'t, Ingress>;
type Table<'t> = SharedTable<'t, Ingress>;

/// Flow group numbers: 0 is the root, 1 the switch, the rest are handed out and taken back.
#[derive(Debug)]
struct Groups {
    next: u32,
    free: Vec<u32>,
}

impl Groups {
    fn take(&mut self) -> Result<FlowGroup, Error> {
        if let Some(group) = self.free.pop() {
            return Ok(FlowGroup(group));
        }
        if self.next > MAX_GROUP {
            return Err(Error::NoGroup);
        }
        self.next += 1;
        Ok(FlowGroup(self.next - 1))
    }

    fn give(&mut self, group: FlowGroup) {
        self.free.push(group.0);
    }
}

/// The switch table, its catch-all, and the switch rule of each attached VPC.
#[derive(Debug)]
struct Switch<'t> {
    // Fields drop in order: the switch rules before the catch-all.
    rules: BTreeMap<Vni, Rule<'t>>,
    catch_all: Rule<'t>,
    table: Table<'t>,
}

/// A source VPC's generation of rules.
#[derive(Debug)]
struct Generation<'t> {
    spec: VpcSpec,
    entry: FlowGroup,
    rules: Vec<(Role, Rule<'t>)>,
    tables: Vec<Table<'t>>,
    groups: Vec<FlowGroup>,
}

/// A meter, and its color group.
#[derive(Debug)]
struct InstalledMeter<'t> {
    key: MeterKey,
    // Fields drop in order: the rules before their table.
    rules: Vec<(Color, Rule<'t>)>,
    table: Table<'t>,
    group: FlowGroup,
    meter: SharedMeter<'t, Ingress>,
}

/// What a port holds, as its reconciler knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The attached VPCs, and what their generations enforce.
    pub vpcs: BTreeMap<Vni, VpcSpec>,
    /// The meters.
    pub meters: Vec<MeterKey>,
    /// Whether the port's offload is off for good ([`Error::Lost`]).
    pub poisoned: bool,
}

/// What a reconciliation did not do: rules of the program the NIC refused, with why. Their
/// VPCs were not attached.
#[derive(Debug, Default)]
pub struct Reconciled {
    /// The refused rules, by role, with the NIC's reason.
    pub refused: Vec<(Role, Error)>,
}

/// One port's rules, reconciled with plans one source VPC at a time.
///
/// What the port holds is known from the handles of what was created. The NIC changes
/// through two kinds of step, each atomic for a packet:
///
/// - a source VPC is *detached* by removing its switch rule: its traffic then goes to software
///   (the switch's catch-all), and its generation of rules, unreachable, is torn down;
/// - a source VPC is *attached* by building its next generation aside, unreachable, and then
///   inserting its switch rule.
///
/// A VPC whose policy changed is detached, then attached again: between the two, software alone
/// enforces its policy, which is always safe. (Switching it in place, which mlx5 can do in a few
/// microseconds, would keep the old policy in the NIC until the new generation is built, while
/// software already enforces the new one.) VPCs whose policy did not change are left alone, and
/// so are their meters' token states. A generation the NIC refuses part of is never attached.
///
/// If removing a rule or table fails, or an operation times out or fails on completion, what the
/// NIC holds is no longer known: the root rule is removed, so that software alone handles
/// everything, and the port's offload stays off until it restarts. A group is handed out again only once its tables are known to be gone.
#[derive(Debug)]
pub struct Port<'t> {
    // Fields drop in order: the root first, so no packet enters what goes next.
    root: Option<Rule<'t>>,
    switch: Option<Switch<'t>>,
    vpcs: BTreeMap<Vni, Generation<'t>>,
    meters: Vec<InstalledMeter<'t>>,
    flows: &'t TemplateFlows<'t>,
    patterns: Vec<(Vec<ItemShape>, SharedPatternTemplate<'t, Ingress>)>,
    actions: Vec<(Vec<TemplateAction>, SharedActionsTemplate<'t, Ingress>)>,
    groups: Groups,
    next_profile: u32,
    /// For the plan being reconciled: its meters' indices into `meters`.
    plan_meters: Vec<Option<usize>>,
    poisoned: bool,
}

impl<'t> Port<'t> {
    /// A port with nothing installed, programmed through `flows`.
    #[must_use]
    pub fn new(flows: &'t TemplateFlows<'t>) -> Port<'t> {
        Port {
            root: None,
            switch: None,
            vpcs: BTreeMap::new(),
            meters: Vec::new(),
            flows,
            patterns: Vec::new(),
            actions: Vec::new(),
            groups: Groups {
                next: 2,
                free: Vec::new(),
            },
            next_profile: 0,
            plan_meters: Vec::new(),
            poisoned: false,
        }
    }

    /// Whether the port's offload is off for good.
    #[must_use]
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }

    /// Turn offload off for good on this port, as `what` failed with `source`: remove the root
    /// rule, so software alone handles everything.
    fn lose(&mut self, what: &'static str, source: TemplateError) -> Error {
        error!(
            "{what}: the NIC's rules are no longer known ({source}): offload is off on this port until it restarts"
        );
        self.poisoned = true;
        if let Some(root) = self.root.take()
            && let Err(e) = root.destroy()
        {
            error!(
                "the root rule could not be removed either ({e}): the NIC may enforce a stale policy until the port restarts"
            );
        }
        Error::Lost { what, source }
    }

    /// Destroy `rules`; a failure loses the port.
    fn destroy_rules<W>(
        &mut self,
        what: &'static str,
        rules: impl IntoIterator<Item = (W, Rule<'t>)>,
    ) -> Result<(), Error> {
        let mut failed = None;
        for (_, rule) in rules {
            if let Err(e) = rule.destroy() {
                failed.get_or_insert(e);
            }
        }
        match failed {
            None => Ok(()),
            Some(e) => Err(self.lose(what, e)),
        }
    }

    /// Destroy `tables`, whose rules are gone, and then hand `groups` out again; a failure loses
    /// the port, and the groups are not handed out again.
    fn destroy_tables(
        &mut self,
        what: &'static str,
        tables: impl IntoIterator<Item = Table<'t>>,
        groups: impl IntoIterator<Item = FlowGroup>,
    ) -> Result<(), Error> {
        let mut failed = None;
        for table in tables {
            if let Err(e) = table.destroy() {
                failed.get_or_insert(e);
            }
        }
        if let Some(e) = failed {
            return Err(self.lose(what, e));
        }
        for group in groups {
            self.groups.give(group);
        }
        Ok(())
    }

    /// Insert a rule; an operation that leaves the NIC's state unknown loses the port, a refusal is
    /// returned as `Ok(Err(..))`.
    fn insert(
        &mut self,
        what: &'static str,
        table: &Table<'t>,
        rule: &super::PlannedRule,
        args: &[SharedArg<'t, Ingress>],
    ) -> Result<Result<Rule<'t>, Error>, Error> {
        match table.insert(0, &rule.pattern, rule.actions, args) {
            Ok(installed) => Ok(Ok(installed)),
            Err(e) if unknown_state(&e) => Err(self.lose(what, e)),
            Err(e) => Ok(Err(e.into())),
        }
    }

    /// The pattern template of `plan`'s pattern `index`, made or reused by shape.
    fn pattern(
        &mut self,
        plan: &Plan,
        index: usize,
    ) -> Result<SharedPatternTemplate<'t, Ingress>, Error> {
        let pattern = &plan.patterns[index];
        if let Some((_, template)) = self.patterns.iter().find(|(s, _)| s == pattern.shapes()) {
            return Ok(Rc::clone(template));
        }
        let template = Rc::new(self.flows.pattern_template::<Ingress, _>(pattern)?);
        self.patterns
            .push((pattern.shapes().to_vec(), Rc::clone(&template)));
        Ok(template)
    }

    /// The actions template of `plan`'s actions `index`, made or reused.
    fn actions(
        &mut self,
        plan: &Plan,
        index: usize,
    ) -> Result<SharedActionsTemplate<'t, Ingress>, Error> {
        let actions = &plan.actions[index];
        if let Some((_, template)) = self.actions.iter().find(|(a, _)| a == actions) {
            return Ok(Rc::clone(template));
        }
        let template = Rc::new(self.flows.actions_template::<Ingress>(actions)?);
        self.actions.push((actions.clone(), Rc::clone(&template)));
        Ok(template)
    }

    /// Create `planned`'s table in `group`.
    fn table(
        &mut self,
        plan: &Plan,
        planned: &PlannedTable,
        group: FlowGroup,
    ) -> Result<Table<'t>, Error> {
        let pattern = self.pattern(plan, planned.pattern)?;
        let actions = planned
            .actions
            .iter()
            .map(|&a| self.actions(plan, a))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SharedTable::new(
            self.flows,
            TableConfig {
                group,
                priority: planned.priority,
                capacity: planned.capacity,
            },
            &[pattern],
            &actions,
        )?)
    }

    /// The arguments of a rule: groups numbered by `group`, meters from the installed ones.
    fn args(
        &self,
        args: &[Arg],
        group: &dyn Fn(Group) -> Option<FlowGroup>,
    ) -> Option<Vec<SharedArg<'t, Ingress>>> {
        args.iter()
            .map(|&arg| match arg {
                Arg::Jump(g) => group(g).map(SharedArg::Jump),
                Arg::Meter(m) => {
                    let installed = (*self.plan_meters.get(m)?)?;
                    Some(SharedArg::Meter(self.meters.get(installed)?.meter.clone()))
                }
            })
            .collect()
    }

    /// The group number of `group`, in a generation whose own groups are `own`.
    fn number(&self, group: Group, own: &BTreeMap<Group, FlowGroup>) -> Option<FlowGroup> {
        match group {
            Group::Root => Some(FlowGroup(0)),
            Group::Switch => Some(SWITCH),
            Group::Color(m) => {
                let installed = (*self.plan_meters.get(m)?)?;
                Some(self.meters.get(installed)?.group)
            }
            Group::Deny(_) | Group::Police(_) => own.get(&group).copied(),
        }
    }

    /// Make sure of the switch table, its catch-all and the root, in that order.
    fn fixed(&mut self, plan: &Plan) -> Result<(), Error> {
        let [root, switch, catch_all] = plan.fixed.as_slice() else {
            return Ok(());
        };
        if self.switch.is_none() {
            let table = self.table(plan, switch, SWITCH)?;
            let catch_all_table = self.table(plan, catch_all, SWITCH)?;
            let catch_all = self.insert(
                "inserting the switch's catch-all",
                &catch_all_table,
                &catch_all.rules[0],
                &[],
            )??;
            self.switch = Some(Switch {
                rules: BTreeMap::new(),
                catch_all,
                table,
            });
        }
        if self.root.is_none() {
            let table = self.table(plan, root, FlowGroup(0))?;
            self.root =
                Some(self.insert("inserting the root rule", &table, &root.rules[0], &[])??);
        }
        Ok(())
    }

    /// Make sure of `plan`'s meters, reusing installed ones by key; a meter that cannot be made
    /// is left out, and so are the rules that charge it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Lost`] if the port was lost; refusals are returned by meter.
    fn meters(&mut self, plan: &Plan) -> Result<Vec<(usize, Error)>, Error> {
        let mut failed = Vec::new();
        self.plan_meters = Vec::with_capacity(plan.meters.len());
        for (index, planned) in plan.meters.iter().enumerate() {
            if let Some(found) = self.meters.iter().position(|m| m.key == planned.key) {
                self.plan_meters.push(Some(found));
                continue;
            }
            match self.meter(plan, index)? {
                Ok(meter) => {
                    self.meters.push(meter);
                    self.plan_meters.push(Some(self.meters.len() - 1));
                }
                Err(e) => {
                    failed.push((index, e));
                    self.plan_meters.push(None);
                }
            }
        }
        Ok(failed)
    }

    /// Make the meter `index` of `plan` and its color group: `Ok(Err(..))` if refused (what was
    /// made of it is removed again), `Err` if the port was lost.
    fn meter(
        &mut self,
        plan: &Plan,
        index: usize,
    ) -> Result<Result<InstalledMeter<'t>, Error>, Error> {
        let planned = &plan.meters[index];
        self.next_profile += 1;
        let profile = match self
            .flows
            .meter_profile(MeterProfileId(self.next_profile), &planned.key.profile)
        {
            Ok(profile) => Rc::new(profile),
            Err(e) => return Ok(Err(e.into())),
        };
        let meter = match SharedMeter::new(self.flows, &profile) {
            Ok(meter) => meter,
            Err(e) if unknown_state(&e) => return Err(self.lose("making a meter", e)),
            Err(e) => return Ok(Err(e.into())),
        };
        let group = match self.groups.take() {
            Ok(group) => group,
            Err(e) => return Ok(Err(e)),
        };
        let table = match self.table(plan, &planned.colors, group) {
            Ok(table) => table,
            Err(e) => {
                self.groups.give(group);
                return Ok(Err(e));
            }
        };
        let mut rules = Vec::new();
        for rule in &planned.colors.rules {
            let Role::Color(_, color) = rule.role else {
                unreachable!("a color table holds color rules")
            };
            match self.insert("inserting a color rule", &table, rule, &[])? {
                Ok(installed) => rules.push((color, installed)),
                Err(e) => {
                    self.destroy_rules("removing a refused meter's color rules", rules)?;
                    self.destroy_tables(
                        "removing a refused meter's color table",
                        [table],
                        [group],
                    )?;
                    return Ok(Err(e));
                }
            }
        }
        Ok(Ok(InstalledMeter {
            key: planned.key.clone(),
            rules,
            table,
            group,
            meter,
        }))
    }

    /// Remove an installed meter: its color rules, then its table, then (with its handle) the
    /// meter; its group is handed out again.
    fn unmake(&mut self, meter: InstalledMeter<'t>) -> Result<(), Error> {
        let InstalledMeter {
            rules,
            table,
            group,
            ..
        } = meter;
        self.destroy_rules("removing a meter's color rules", rules)?;
        self.destroy_tables("removing a meter's color table", [table], [group])
    }

    /// Build `planned`'s generation, unreachable; on a refusal, what was built is removed again
    /// and the refused rules returned.
    fn build(
        &mut self,
        plan: &Plan,
        planned: &PlannedVpc,
    ) -> Result<Result<Generation<'t>, Vec<(Role, Error)>>, Error> {
        let mut own = BTreeMap::new();
        let mut generation = Generation {
            spec: planned.spec.clone(),
            entry: FlowGroup(0),
            rules: Vec::new(),
            tables: Vec::new(),
            groups: Vec::new(),
        };
        let mut refused = Vec::new();
        for table in &planned.tables {
            if let std::collections::btree_map::Entry::Vacant(entry) = own.entry(table.group) {
                let group = self.groups.take()?;
                entry.insert(group);
                generation.groups.push(group);
            }
        }
        generation.entry = own[&planned.entry];
        for planned_table in &planned.tables {
            let number = own[&planned_table.group];
            let table = match self.table(plan, planned_table, number) {
                Ok(table) => table,
                Err(e) => {
                    let mut rules = planned_table.rules.iter();
                    if let Some(first) = rules.next() {
                        refused.push((first.role, e));
                        refused.extend(rules.map(|r| (r.role, Error::TableRefused)));
                    }
                    continue;
                }
            };
            for rule in &planned_table.rules {
                let group = |g| self.number(g, &own);
                let Some(args) = self.args(&rule.args, &group) else {
                    refused.push((rule.role, Error::MeterNotMade));
                    continue;
                };
                match self.insert("inserting a generation's rule", &table, rule, &args) {
                    Ok(Ok(installed)) => generation.rules.push((rule.role, installed)),
                    Ok(Err(e)) => refused.push((rule.role, e)),
                    Err(lost) => {
                        // What is already built stays, unreachable, with the port lost.
                        generation.tables.push(table);
                        Self::forget(generation);
                        return Err(lost);
                    }
                }
            }
            generation.tables.push(table);
        }
        if refused.is_empty() {
            return Ok(Ok(generation));
        }
        self.teardown(generation)?;
        Ok(Err(refused))
    }

    /// Remove a detached generation's rules, then its tables, and take its groups back.
    fn teardown(&mut self, generation: Generation<'t>) -> Result<(), Error> {
        let Generation {
            rules,
            tables,
            groups,
            ..
        } = generation;
        self.destroy_rules("removing a generation's rules", rules)?;
        self.destroy_tables("removing a generation's tables", tables, groups)
    }

    /// Keep what a generation holds in the NIC, unreachable, once the port is lost: its handles go
    /// without removing it (the port's stop does).
    fn forget(generation: Generation<'t>) {
        std::mem::forget(generation);
    }

    /// Remove everything: the root first, then the rest.
    fn clear(&mut self) -> Result<(), Error> {
        if let Some(root) = self.root.take()
            && let Err(e) = root.destroy()
        {
            return Err(self.lose("removing the root rule", e));
        }
        let vnis: Vec<Vni> = self.vpcs.keys().copied().collect();
        for vni in vnis {
            self.remove(vni)?;
        }
        if let Some(switch) = self.switch.take() {
            let Switch {
                rules,
                catch_all,
                table,
            } = switch;
            let rules = rules
                .into_iter()
                .map(|(vni, rule)| (Some(vni), rule))
                .chain([(None, catch_all)]);
            self.destroy_rules("removing the switch rules", rules)?;
            drop(table);
        }
        for meter in std::mem::take(&mut self.meters) {
            self.unmake(meter)?;
        }
        self.plan_meters.clear();
        Ok(())
    }

    /// Drop templates no table uses any more.
    fn prune(&mut self) {
        self.patterns.retain(|(_, t)| Rc::strong_count(t) > 1);
        self.actions.retain(|(_, t)| Rc::strong_count(t) > 1);
    }

    /// What each counting rule has counted so far, by role, for the plan last reconciled.
    /// Hardware counters lag (by about half a second on a BlueField-3).
    #[must_use]
    pub fn counts(&self) -> Vec<(Role, Counts)> {
        let mut counts: Vec<(Role, Counts)> = self
            .vpcs
            .values()
            .flat_map(|g| &g.rules)
            .filter(|(role, _)| matches!(role, Role::Deny(_)))
            .map(|(role, rule)| (*role, rule.counts().unwrap_or_default()))
            .collect();
        for (index, installed) in self.plan_meters.iter().enumerate() {
            let Some(meter) = installed.and_then(|i| self.meters.get(i)) else {
                continue;
            };
            for (color, rule) in &meter.rules {
                counts.push((
                    Role::Color(index, *color),
                    rule.counts().unwrap_or_default(),
                ));
            }
        }
        counts
    }

    /// How many installed rules have a role `which` accepts.
    #[must_use]
    pub fn installed(&self, which: impl Fn(Role) -> bool) -> usize {
        self.vpcs
            .values()
            .flat_map(|g| &g.rules)
            .filter(|(role, _)| which(*role))
            .count()
    }
}

impl SyncObserve for Port<'_> {
    type Observation<'a>
        = Observed
    where
        Self: 'a;

    fn observe(&self) -> Observed {
        Observed {
            vpcs: self
                .vpcs
                .iter()
                .map(|(&vni, g)| (vni, g.spec.clone()))
                .collect(),
            meters: self.meters.iter().map(|m| m.key.clone()).collect(),
            poisoned: self.poisoned,
        }
    }
}

impl SyncCreate for Port<'_> {
    /// A plan, and the VPC of it to attach.
    type Requirement<'a>
        = (&'a Plan, Vni)
    where
        Self: 'a;
    /// The refused rules, if the generation was not attached; an error if the port failed.
    type Outcome<'a>
        = Result<Vec<(Role, Error)>, Error>
    where
        Self: 'a;

    /// Build the VPC's generation aside, then attach it with its switch rule.
    fn create<'a>(&mut self, (plan, vni): (&'a Plan, Vni)) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        let Some(planned) = plan.vpcs.get(&vni) else {
            return Ok(Vec::new());
        };
        let generation = match self.build(plan, planned)? {
            Ok(generation) => generation,
            Err(refused) => return Ok(refused),
        };
        let Some(rule) = plan
            .fixed
            .get(1)
            .and_then(|t| t.rules.iter().find(|r| r.role == Role::Switch(vni)))
        else {
            self.teardown(generation)?;
            return Ok(Vec::new());
        };
        let entry = generation.entry;
        let Some(switch) = self.switch.take() else {
            self.teardown(generation)?;
            return Err(Error::NoSwitch);
        };
        let inserted = self.insert(
            "inserting a switch rule",
            &switch.table,
            rule,
            &[SharedArg::Jump(entry)],
        );
        let mut switch = switch;
        match inserted {
            Ok(Ok(installed)) => {
                switch.rules.insert(vni, installed);
                self.switch = Some(switch);
                self.vpcs.insert(vni, generation);
                Ok(Vec::new())
            }
            Ok(Err(e)) => {
                self.switch = Some(switch);
                let mut refused = vec![(Role::Switch(vni), e)];
                refused.extend(
                    generation
                        .rules
                        .iter()
                        .map(|(role, _)| (*role, Error::SwitchRefused)),
                );
                self.teardown(generation)?;
                Ok(refused)
            }
            Err(lost) => {
                self.switch = Some(switch);
                Self::forget(generation);
                Err(lost)
            }
        }
    }
}

impl SyncRemove for Port<'_> {
    /// The VPC to detach.
    type Observation<'a>
        = Vni
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), Error>
    where
        Self: 'a;

    /// Detach the VPC (its traffic goes to software), then tear its generation down.
    fn remove<'a>(&mut self, vni: Vni) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        if let Some(rule) = self.switch.as_mut().and_then(|s| s.rules.remove(&vni))
            && let Err(e) = rule.destroy()
        {
            return Err(self.lose("removing a switch rule", e));
        }
        match self.vpcs.remove(&vni) {
            Some(generation) => self.teardown(generation),
            None => Ok(()),
        }
    }
}

impl SyncReconcile for Port<'_> {
    type Requirement<'a>
        = &'a Plan
    where
        Self: 'a;
    type Observation<'a>
        = Observed
    where
        Self: 'a;
    type Outcome<'a>
        = Result<Reconciled, Error>
    where
        Self: 'a;

    /// Detach the VPCs whose policy changed or went, make sure of the fixed rules and the
    /// meters, and attach the VPCs not attached.
    fn reconcile<'a>(&mut self, plan: &'a Plan, observed: Observed) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        if observed.poisoned {
            return Err(Error::Poisoned);
        }
        for (vni, spec) in &observed.vpcs {
            if plan
                .vpcs
                .get(vni)
                .is_none_or(|planned| planned.spec != *spec)
            {
                self.remove(*vni)?;
            }
        }
        if plan.vpcs.is_empty() {
            self.clear()?;
            self.prune();
            return Ok(Reconciled::default());
        }
        self.fixed(plan)?;
        let mut reconciled = Reconciled::default();
        for (meter, why) in self.meters(plan)? {
            let mut charging = plan
                .vpcs
                .values()
                .flat_map(|vpc| vpc.tables.iter().flat_map(|t| &t.rules))
                .filter(|r| r.args.contains(&Arg::Meter(meter)));
            if let Some(first) = charging.next() {
                reconciled.refused.push((first.role, why));
                reconciled
                    .refused
                    .extend(charging.map(|r| (r.role, Error::MeterNotMade)));
            }
        }
        let attach: Vec<Vni> = plan
            .vpcs
            .keys()
            .filter(|vni| !self.vpcs.contains_key(vni))
            .copied()
            .collect();
        for vni in attach {
            reconciled.refused.extend(self.create((plan, vni))?);
        }
        // Meters no generation charges any more go, after the generations that charged them.
        let wanted: Vec<&MeterKey> = plan.meters.iter().map(|m| &m.key).collect();
        let mut kept = Vec::new();
        for meter in std::mem::take(&mut self.meters) {
            if wanted.contains(&&meter.key) {
                kept.push(meter);
            } else {
                self.unmake(meter)?;
            }
        }
        self.meters = kept;
        self.plan_meters = plan
            .meters
            .iter()
            .map(|p| self.meters.iter().position(|m| m.key == p.key))
            .collect();
        self.prune();
        Ok(reconciled)
    }
}

impl Drop for Port<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.clear() {
            warn!("the NIC's rules could not all be removed: {e}");
        }
    }
}

/// The rules of a plan while it is installed by [`with_installed`].
#[derive(Debug)]
pub struct Installed<'a, 't> {
    port: &'a Port<'t>,
    refused: &'a [(Role, Error)],
}

impl Installed<'_, '_> {
    /// The rules of the program the NIC refused, and why: their VPCs were not attached.
    #[must_use]
    pub fn refused(&self) -> &[(Role, Error)] {
        self.refused
    }

    /// What each counting rule has counted so far, by role; see [`Port::counts`].
    #[must_use]
    pub fn counts(&self) -> Vec<(Role, Counts)> {
        self.port.counts()
    }

    /// How many installed rules have a role `which` accepts.
    #[must_use]
    pub fn installed(&self, which: impl Fn(Role) -> bool) -> usize {
        self.port.installed(which)
    }
}

/// Install `plan` on `flows`' port, call `f` while it is installed, and remove it again.
///
/// VPCs with a rule the NIC refused are not attached: their rules are listed in
/// [`Installed::refused`].
///
/// # Errors
///
/// Returns the first failure of what the plan cannot do without (the root, the switch); whatever
/// was installed is removed again.
pub fn with_installed<'t, R>(
    flows: &'t TemplateFlows<'t>,
    plan: &Plan,
    f: impl FnOnce(&Installed<'_, 't>) -> R,
) -> Result<R, Error> {
    let mut port = Port::new(flows);
    let observed = port.observe();
    let reconciled = port.reconcile(plan, observed)?;
    let result = f(&Installed {
        port: &port,
        refused: &reconciled.refused,
    });
    drop(port);
    Ok(result)
}

/// The peerings of the rules in `refused`, which `program` has.
fn peerings(program: &Program, refused: &[(Role, Error)]) -> BTreeSet<Peering> {
    refused
        .iter()
        .filter_map(|(role, _)| match *role {
            Role::Police(rule) => program.rules.get(rule).map(|r| r.peering),
            Role::Deny(deny) => program.denies.get(deny).map(|d| d.peering),
            _ => None,
        })
        .collect()
}

/// Program `dev` with what the published ACLs and rate limits allow, and follow them until `stop`
/// says so.
///
/// `fate` is where traffic the NIC lets through goes: the driver's data queues.
pub fn run(
    dev: &Dev<'_, Started>,
    port_name: &str,
    policy: &Policy,
    fate: &TemplateAction,
    stop: &dyn Fn() -> bool,
) {
    let (acls, reader, routing) = (&policy.acls, &policy.rate_limits, &policy.routing);
    let flows = match TemplateFlows::new(dev) {
        Ok(flows) => flows,
        Err(e) => {
            warn!("port {port_name}: no NIC offload: {e}");
            return;
        }
    };
    let mut port = Port::new(&flows);
    while !stop() {
        let (filter, limits, routes) = (acls.load(), reader.load(), routing.load());
        let changed = || {
            stop()
                || !concurrency::sync::Arc::ptr_eq(&acls.load(), &filter)
                || !concurrency::sync::Arc::ptr_eq(&reader.load(), &limits)
                || !concurrency::sync::Arc::ptr_eq(&routing.load(), &routes)
        };
        let destinations = routes.destinations();
        if !limits.attempt_offloads() {
            info!(
                "port {port_name}: NIC offload is turned off; software alone enforces the policy"
            );
        }
        let (program, excluded) = install_policy(
            &mut port,
            port_name,
            &filter,
            &limits,
            &destinations,
            fate,
            &changed,
        );
        if let Some(program) = &program
            && (!program.denies.is_empty() || !program.rules.is_empty())
        {
            info!(
                "port {port_name}: NIC enforcing {} ACL deny(s) and {} rate limit(s) for {} source VPC(s)",
                port.installed(|role| matches!(role, Role::Deny(_))),
                port.installed(|role| matches!(role, Role::Police(_))),
                port.vpcs.len(),
            );
        }
        let in_software = program.as_ref().map_or(0, |p| {
            p.refused
                .iter()
                .map(|(peering, ..)| *peering)
                .chain(excluded.iter().copied())
                .collect::<BTreeSet<_>>()
                .len()
        });
        state(port_name, &port, in_software);
        let mut next_report = clock::deadline(REPORT);
        while !changed() {
            std::thread::sleep(POLL);
            if clock::now() >= next_report {
                report(port_name, &port);
                next_report = clock::deadline(REPORT);
            }
        }
        report(port_name, &port);
    }
}

/// Compile the policy into a program, and reconcile `port` with it: the program installed (or
/// `None` if offload failed, or the policy changed meanwhile), and the peerings left in software
/// because the NIC refused them or ran out of meters.
fn install_policy(
    port: &mut Port<'_>,
    port_name: &str,
    filter: &acl_filter::AclFilterContext,
    limits: &rate_limit::RateLimits<rate_limit::PeeringRules>,
    destinations: &[flow_filter::Destination],
    fate: &TemplateAction,
    changed: &dyn Fn() -> bool,
) -> (Option<Program>, BTreeSet<Peering>) {
    // Peerings left in software: refused by the NIC, or over its meters.
    let mut excluded = BTreeSet::new();
    let program = loop {
        let program = Program::compile(filter, limits, destinations, &excluded);
        if program.meters.len() > RESOURCES.meters as usize {
            // The peerings of the last meters stay in software until the rest fit.
            let last = program.meters.len() - 1;
            excluded.extend(
                program
                    .rules
                    .iter()
                    .filter(|r| r.meter == last)
                    .map(|r| r.peering),
            );
            continue;
        }
        // The ACLs, the rate limits and the routing are published apart: compile only from what
        // was seen together.
        if changed() {
            break None;
        }
        let mut reported = BTreeSet::new();
        for (peering, origin, refusal) in &program.refused {
            if reported.insert(*peering) {
                info!("port {port_name}: the {peering} stays in software: {origin}: {refusal:?}");
            }
        }
        let outcome = super::Plan::new(&program, fate).and_then(|plan| {
            let observed = port.observe();
            port.reconcile(&plan, observed)
        });
        match outcome {
            Ok(reconciled) if reconciled.refused.is_empty() => break Some(program),
            Ok(reconciled) => {
                let refused = peerings(&program, &reconciled.refused);
                for (role, why) in &reconciled.refused {
                    let origin = match *role {
                        Role::Police(rule) => {
                            program.rules.get(rule).map(|r| Origin::RateLimit(r.rule))
                        }
                        Role::Deny(deny) => program.denies.get(deny).map(|d| d.origin),
                        _ => None,
                    };
                    if let Some(origin) = origin {
                        warn!("port {port_name}: the NIC refused {origin}: {why}");
                    }
                }
                if refused.is_subset(&excluded) {
                    break Some(program);
                }
                excluded.extend(refused);
            }
            Err(e @ (Error::Lost { .. } | Error::Poisoned)) => {
                error!("port {port_name}: {e}");
                break None;
            }
            Err(e) => {
                // Nothing of an old policy may stay in the NIC while software enforces a new
                // one.
                match port.clear() {
                    Ok(()) => error!(
                        "port {port_name}: NIC offload failed, software only until the next change: {e}"
                    ),
                    Err(lost) => {
                        error!("port {port_name}: NIC offload failed ({e}), and {lost}");
                    }
                }
                break None;
            }
        }
    };
    (program, excluded)
}

/// Export the port's offload state: the source VPCs attached, whether the port is lost, and how
/// many peerings stay in software.
fn state(port_name: &str, port: &Port<'_>, in_software: usize) {
    let port_label = port_name.to_string();
    #[allow(clippy::cast_precision_loss)] // counts far below 2^52
    {
        metrics::gauge!("nic_offload_vpcs", "port" => port_label.clone())
            .set(port.vpcs.len() as f64);
        metrics::gauge!("nic_offload_peerings_in_software", "port" => port_label.clone())
            .set(in_software as f64);
    }
    metrics::gauge!("nic_offload_poisoned", "port" => port_label).set(if port.poisoned() {
        1.0
    } else {
        0.0
    });
}

/// Log and export what each meter passed and dropped in hardware, and what ACL denies dropped.
fn report(port_name: &str, port: &Port<'_>) {
    let denied: u64 = port
        .counts()
        .iter()
        .filter(|(role, _)| matches!(role, Role::Deny(_)))
        .map(|(_, c)| c.packets)
        .sum();
    metrics::counter!("acl_nic_dropped_packets_total", "port" => port_name.to_string())
        .absolute(denied);
    for meter in &port.meters {
        let mut passed = Counts::default();
        let mut dropped = Counts::default();
        for (color, rule) in &meter.rules {
            let counts = rule.counts().unwrap_or_default();
            let sum = if *color == Color::Red {
                &mut dropped
            } else {
                &mut passed
            };
            sum.packets += counts.packets;
            sum.bytes += counts.bytes;
        }
        info!(
            "port {port_name}: meter {} in the NIC: passed {} packets, dropped {} packets",
            meter.key.name, passed.packets, dropped.packets
        );
        for (result, counts) in [("conforming", passed), ("over_limit", dropped)] {
            metrics::counter!(
                "rate_limit_nic_packets_total",
                "port" => port_name.to_string(),
                "meter" => meter.key.name.clone(),
                "result" => result
            )
            .absolute(counts.packets);
        }
    }
}
