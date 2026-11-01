// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The rules for the configured limits, and their installation on a port.
//!
//! ```text
//! group 0     eth / ipv4|ipv6 / udp dst <vxlan port>              -> jump 1
//!             (anything else misses, and the kernel gets it)
//! group 1     one table per kind of match, most specific first:
//!             eth / ip / udp / vxlan vni [/ eth / ip dst <prefix>] -> meter(limit) / jump 2 + limit
//!             last: eth                                            -> count / send to kernel
//! group 2+i   meter color green, yellow                            -> count / send to kernel
//!             meter color red                                      -> count / drop
//! ```
//!
//! Each limit has a meter and its own color group, so its counters say what it passed and dropped.
//! The meter counts outer IP bytes.
//! Every limit is installed for both underlay families.

use std::cmp::Reverse;
use std::net::{Ipv4Addr, Ipv6Addr};

use dpdk::flow::template::{
    ActionsTemplate, Color, Complete, Counts, Meter, MeterAlgorithm, MeterError, MeterProfile,
    MeterProfileHandle, MeterProfileId, MeterUnit, Pattern, PatternTemplate, RuleArg, TableConfig,
    TemplateAction, TemplateConfig, TemplateError, TemplateFlows, TemplateRule, TemplateTable,
};
use dpdk::flow::{
    EthMatch, FlowError, FlowGroup, Ingress, Ipv4Match, Ipv4Prefix, Ipv6Match, Ipv6Prefix,
    Priority, UdpMatch, VxlanMatch,
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use net::vxlan::Vni;

use crate::config::{Config, Limit};

/// The group every limit's match is in.
const CLASSIFY: FlowGroup = FlowGroup(1);

/// Room for operations in flight; each waits for its completion, so few are.
const QUEUE_SIZE: u32 = 64;

/// The color group of limit `index`.
fn color_group(index: usize) -> FlowGroup {
    // Configurations are far smaller than 2^32 limits.
    FlowGroup(2 + u32::try_from(index).unwrap_or(u32::MAX - 2))
}

/// An IP family.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Family {
    V4,
    V6,
}

const FAMILIES: [Family; 2] = [Family::V4, Family::V6];

/// What a group 1 table matches: the underlay family, and the inner destination prefix length
/// beyond the VNI, if any.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct Class {
    outer: Family,
    inner: Option<(Family, u8)>,
}

impl Class {
    fn of(outer: Family, limit: &Limit) -> Class {
        let inner = limit.inner_dst.map(|dst| match dst {
            IpNet::V4(net) => (Family::V4, net.prefix_len()),
            IpNet::V6(net) => (Family::V6, net.prefix_len()),
        });
        Class { outer, inner }
    }

    /// Lower ranks match first: longer inner prefixes, then the VNI alone.
    /// Classes of one rank never match the same packet.
    fn rank(self) -> Reverse<i16> {
        Reverse(self.inner.map_or(-1, |(_, len)| i16::from(len)))
    }

    /// The pattern of the class's template, or with `vni` and `inner_dst`, of one of its rules.
    fn pattern(self, vni: Vni, inner_dst: Option<IpNet>) -> Pattern<Complete> {
        let any = EthMatch::default();
        let udp = match self.outer {
            Family::V4 => Pattern::new()
                .eth(any)
                .ipv4(Ipv4Match::default())
                .udp(UdpMatch::default()),
            Family::V6 => Pattern::new()
                .eth(any)
                .ipv6(Ipv6Match::default())
                .udp(UdpMatch::default()),
        };
        let vxlan = udp.vxlan(VxlanMatch::default().vni(vni));
        match inner_dst {
            None => vxlan.complete(),
            Some(IpNet::V4(net)) => vxlan
                .inner_eth(any)
                .ipv4(Ipv4Match::default().dst(Ipv4Prefix::prefix(net.network(), net.prefix_len())))
                .complete(),
            Some(IpNet::V6(net)) => vxlan
                .inner_eth(any)
                .ipv6(Ipv6Match::default().dst(Ipv6Prefix::prefix(net.network(), net.prefix_len())))
                .complete(),
        }
    }

    /// The pattern of the class's template: values are placeholders.
    fn template_pattern(self) -> Pattern<Complete> {
        // Prefix lengths come from valid prefixes, so they are in range.
        let placeholder = self.inner.map(|(family, len)| match family {
            Family::V4 => IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, len).unwrap_or_default()),
            Family::V6 => IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, len).unwrap_or_default()),
        });
        let vni = Vni::new_checked(Vni::MIN).unwrap_or_else(|_| unreachable!());
        self.pattern(vni, placeholder)
    }
}

/// The root rule's pattern for one underlay family.
fn root_pattern(outer: Family, port: u16) -> Pattern<Complete> {
    let any = EthMatch::default();
    let udp = UdpMatch::default().dst(port);
    match outer {
        Family::V4 => Pattern::new()
            .eth(any)
            .ipv4(Ipv4Match::default())
            .udp(udp)
            .complete(),
        Family::V6 => Pattern::new()
            .eth(any)
            .ipv6(Ipv6Match::default())
            .udp(udp)
            .complete(),
    }
}

/// The group 1 tables, in match order, and the limits each holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    classes: Vec<(Class, Vec<usize>)>,
}

impl Plan {
    /// Group the limits by class.
    #[must_use]
    pub fn new(config: &Config) -> Plan {
        let mut classes: Vec<(Class, Vec<usize>)> = Vec::new();
        for outer in FAMILIES {
            for (index, limit) in config.limits.iter().enumerate() {
                let class = Class::of(outer, limit);
                match classes.iter_mut().find(|(c, _)| *c == class) {
                    Some((_, limits)) => limits.push(index),
                    None => classes.push((class, vec![index])),
                }
            }
        }
        classes.sort_by_key(|(class, _)| (class.rank(), class.outer, class.inner));
        Plan { classes }
    }

    /// What the port must reserve for these limits.
    #[must_use]
    pub fn resources(config: &Config) -> TemplateConfig {
        let limits = u32::try_from(config.limits.len()).unwrap_or(u32::MAX);
        TemplateConfig {
            queue_size: QUEUE_SIZE,
            // Three colors per limit, and the catch-all.
            counters: limits.saturating_mul(3).saturating_add(1),
            meters: limits,
        }
    }
}

/// Failures installing the rules.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// The PMD rejected a template, table or meter.
    #[error(transparent)]
    Flow(#[from] FlowError),
    /// A table or rule could not be created.
    #[error(transparent)]
    Template(#[from] TemplateError),
    /// A rule could not be inserted.
    #[error("the {rule} rule: {source}")]
    Rule {
        /// Which rule.
        rule: String,
        /// Why.
        source: TemplateError,
    },
    /// A table could not be created.
    #[error("the {table} table: {source}")]
    Table {
        /// Which table.
        table: String,
        /// Why.
        source: TemplateError,
    },
    /// A meter profile could not be added.
    #[error(transparent)]
    Meter(#[from] MeterError),
}

/// The templates and meter profiles of a port.
pub struct Templates<'d> {
    root: Vec<PatternTemplate<'d, Ingress>>,
    classes: Vec<PatternTemplate<'d, Ingress>>,
    any: PatternTemplate<'d, Ingress>,
    color: PatternTemplate<'d, Ingress>,
    jump: ActionsTemplate<'d, Ingress>,
    meter: ActionsTemplate<'d, Ingress>,
    to_kernel: ActionsTemplate<'d, Ingress>,
    drop: ActionsTemplate<'d, Ingress>,
    profiles: Vec<MeterProfileHandle<'d>>,
}

impl<'d> Templates<'d> {
    /// Create the templates and one meter profile per limit.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error.
    pub fn new(
        flows: &TemplateFlows<'d>,
        plan: &Plan,
        config: &Config,
    ) -> Result<Templates<'d>, InstallError> {
        let root = FAMILIES
            .iter()
            .map(|&f| flows.pattern_template(&root_pattern(f, config.vxlan_port)))
            .collect::<Result<_, _>>()?;
        let classes = plan
            .classes
            .iter()
            .map(|(class, _)| flows.pattern_template(&class.template_pattern()))
            .collect::<Result<_, _>>()?;
        let profiles = config
            .limits
            .iter()
            .enumerate()
            .map(|(index, limit)| {
                flows.meter_profile(
                    MeterProfileId(u32::try_from(index).unwrap_or(u32::MAX)),
                    &MeterProfile {
                        algorithm: MeterAlgorithm::Srtcm {
                            cir: limit.cir_bytes,
                            cbs: limit.cbs_bytes,
                            ebs: 0,
                        },
                        unit: MeterUnit::Bytes,
                    },
                )
            })
            .collect::<Result<_, _>>()?;
        Ok(Templates {
            root,
            classes,
            any: flows.pattern_template(&Pattern::new().eth(EthMatch::default()))?,
            color: flows.pattern_template(&Pattern::meter_color(Color::Green))?,
            // No count here: mlx5 counts in the root group only if DPDK was built against an
            // rdma-core that offers it (`mlx5dr_action_counter_root_is_supported`).
            jump: flows.actions_template(&[TemplateAction::Jump(CLASSIFY)])?,
            meter: flows.actions_template(&[TemplateAction::Meter, TemplateAction::JumpPerRule])?,
            to_kernel: flows
                .actions_template(&[TemplateAction::Count, TemplateAction::SendToKernel])?,
            drop: flows.actions_template(&[TemplateAction::Count, TemplateAction::Drop])?,
            profiles,
        })
    }
}

/// The tables and meters of a port.
pub struct Tables<'t> {
    root: Vec<TemplateTable<'t, Ingress>>,
    classes: Vec<TemplateTable<'t, Ingress>>,
    any: TemplateTable<'t, Ingress>,
    colors: Vec<TemplateTable<'t, Ingress>>,
    meters: Vec<Meter<'t, Ingress>>,
}

/// A table's capacity for `rules` rules.
fn capacity(rules: usize) -> u32 {
    u32::try_from(rules.max(1)).unwrap_or(u32::MAX)
}

impl<'t> Tables<'t> {
    /// Create the tables and one meter per limit.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error.
    pub fn new(
        flows: &'t TemplateFlows<'t>,
        templates: &'t Templates<'_>,
        plan: &Plan,
    ) -> Result<Tables<'t>, InstallError> {
        let named = |table: String| move |source| InstallError::Table { table, source };
        // One table per family: mlx5 refuses a root table with several pattern templates.
        let root = FAMILIES
            .iter()
            .zip(&templates.root)
            .map(|(family, pattern)| {
                flows
                    .table(
                        TableConfig {
                            group: FlowGroup(0),
                            priority: Priority(0),
                            capacity: 1,
                        },
                        &[pattern],
                        &[&templates.jump],
                    )
                    .map_err(named(format!("{family:?} root")))
            })
            .collect::<Result<_, _>>()?;
        let mut classes = Vec::with_capacity(plan.classes.len());
        let mut rank = 0;
        let mut previous = None;
        for ((class, limits), pattern) in plan.classes.iter().zip(&templates.classes) {
            // Classes of a rank share a priority; each new rank comes after the last.
            if previous.is_some_and(|p| p != class.rank()) {
                rank += 1;
            }
            previous = Some(class.rank());
            classes.push(
                flows
                    .table(
                        TableConfig {
                            group: CLASSIFY,
                            priority: Priority(rank),
                            capacity: capacity(limits.len()),
                        },
                        &[pattern],
                        &[&templates.meter],
                    )
                    .map_err(named(format!("{class:?} (priority {rank})")))?,
            );
        }
        let any = flows
            .table(
                TableConfig {
                    group: CLASSIFY,
                    priority: Priority(rank + 1),
                    capacity: 1,
                },
                &[&templates.any],
                &[&templates.to_kernel],
            )
            .map_err(named("catch-all".to_string()))?;
        let colors = (0..templates.profiles.len())
            .map(|index| {
                flows
                    .table(
                        TableConfig {
                            group: color_group(index),
                            priority: Priority(0),
                            capacity: capacity(Color::ALL.len()),
                        },
                        &[&templates.color],
                        &[&templates.to_kernel, &templates.drop],
                    )
                    .map_err(named(format!("color {index}")))
            })
            .collect::<Result<_, _>>()?;
        let meters = templates
            .profiles
            .iter()
            .map(|profile| flows.meter(profile))
            .collect::<Result<_, _>>()?;
        Ok(Tables {
            root,
            classes,
            any,
            colors,
            meters,
        })
    }
}

/// One limit's rules: its matches, then a rule per color.
struct LimitRules<'r> {
    matches: Vec<TemplateRule<'r>>,
    passed: [TemplateRule<'r>; 2],
    dropped: TemplateRule<'r>,
}

/// The counts of `rules`, added up.
fn sum(rules: &[TemplateRule<'_>]) -> Result<Counts, TemplateError> {
    rules.iter().try_fold(Counts::default(), |total, rule| {
        let counts = rule.counts()?;
        Ok(Counts {
            packets: total.packets + counts.packets,
            bytes: total.bytes + counts.bytes,
        })
    })
}

/// What a port's rules have counted so far.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortCounts {
    /// All VXLAN traffic: every packet the root rules divert lands in exactly one limit's color
    /// rules or the catch-all, so this is their sum.
    pub vxlan: Counts,
    /// VXLAN traffic no limit matched, returned to the kernel.
    pub unlimited: Counts,
    /// Each limit, in configuration order.
    pub limits: Vec<LimitCounts>,
}

/// What a limit passed and dropped so far.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct LimitCounts {
    /// Green and yellow traffic, returned to the kernel.
    pub passed: Counts,
    /// Red traffic, dropped.
    pub dropped: Counts,
}

/// The rules of a port. Fields drop in order: the root rules go first, so no packet enters a group
/// whose rules are being removed.
pub struct Rules<'r> {
    root: Vec<TemplateRule<'r>>,
    any: TemplateRule<'r>,
    limits: Vec<LimitRules<'r>>,
}

impl<'r> Rules<'r> {
    /// Insert the rules, deepest groups first, so traffic only enters complete groups.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error.
    pub fn new(
        tables: &'r Tables<'_>,
        plan: &Plan,
        config: &Config,
    ) -> Result<Rules<'r>, InstallError> {
        let named = |rule: String| move |source| InstallError::Rule { rule, source };
        let mut limits: Vec<LimitRules<'r>> = Vec::with_capacity(config.limits.len());
        for (index, table) in tables.colors.iter().enumerate() {
            let color = |c, actions| {
                table
                    .insert(0, &Pattern::meter_color(c), actions, &[])
                    .map_err(named(format!("{c:?} for limit {index}")))
            };
            limits.push(LimitRules {
                matches: Vec::new(),
                passed: [color(Color::Green, 0)?, color(Color::Yellow, 0)?],
                dropped: color(Color::Red, 1)?,
            });
        }
        for ((class, members), table) in plan.classes.iter().zip(&tables.classes) {
            for &index in members {
                let limit = &config.limits[index];
                let rule = table
                    .insert(
                        0,
                        &class.pattern(limit.vni, limit.inner_dst),
                        0,
                        &[
                            RuleArg::Meter(&tables.meters[index]),
                            RuleArg::Jump(color_group(index)),
                        ],
                    )
                    .map_err(named(format!("{class:?} match for {limit}")))?;
                limits[index].matches.push(rule);
            }
        }
        let any = tables
            .any
            .insert(0, &Pattern::new().eth(EthMatch::default()), 0, &[])
            .map_err(named("catch-all".to_string()))?;
        let root = FAMILIES
            .iter()
            .zip(&tables.root)
            .map(|(&f, table)| {
                table
                    .insert(0, &root_pattern(f, config.vxlan_port), 0, &[])
                    .map_err(named(format!("{f:?} root")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Rules { root, any, limits })
    }

    /// Every counter of the port.
    ///
    /// # Errors
    ///
    /// Returns the PMD's error if a counter cannot be read.
    pub fn counts(&self) -> Result<PortCounts, TemplateError> {
        let limits: Vec<LimitCounts> = self
            .limits
            .iter()
            .map(|limit| {
                Ok(LimitCounts {
                    passed: sum(&limit.passed)?,
                    dropped: limit.dropped.counts()?,
                })
            })
            .collect::<Result<_, TemplateError>>()?;
        let unlimited = self.any.counts()?;
        let vxlan = limits
            .iter()
            .flat_map(|limit| [limit.passed, limit.dropped])
            .fold(unlimited, |total, counts| Counts {
                packets: total.packets + counts.packets,
                bytes: total.bytes + counts.bytes,
            });
        Ok(PortCounts {
            vxlan,
            unlimited,
            limits,
        })
    }

    /// How many root rules divert VXLAN traffic into the limits.
    #[must_use]
    pub fn root_rules(&self) -> usize {
        self.root.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml: &str) -> Config {
        Config::parse(yaml).unwrap()
    }

    #[test]
    fn longer_prefixes_match_first_and_every_limit_covers_both_underlays() {
        let config = config(
            "
limits:
  - {vni: 1, rate_bps: 8000}
  - {vni: 1, inner_dst: 10.0.0.0/8, rate_bps: 8000}
  - {vni: 2, inner_dst: 10.1.0.0/16, rate_bps: 8000}
  - {vni: 3, inner_dst: 2001:db8::/32, rate_bps: 8000}
  - {vni: 4, rate_bps: 8000}
",
        );
        let plan = Plan::new(&config);
        let lens: Vec<_> = plan
            .classes
            .iter()
            .map(|(class, _)| class.inner.map(|(_, len)| len))
            .collect();
        assert_eq!(
            lens,
            [
                Some(32),
                Some(32),
                Some(16),
                Some(16),
                Some(8),
                Some(8),
                None,
                None
            ]
        );
        for index in 0..config.limits.len() {
            let underlays: Vec<_> = plan
                .classes
                .iter()
                .filter(|(_, members)| members.contains(&index))
                .map(|(class, _)| class.outer)
                .collect();
            assert_eq!(underlays.len(), 2, "limit {index}");
            assert!(underlays.contains(&Family::V4) && underlays.contains(&Family::V6));
        }
    }

    /// A rule's pattern has its class template's shape, whatever the values.
    #[test]
    fn rule_patterns_fit_their_templates() {
        let config = config(
            "
limits:
  - {vni: 77, rate_bps: 8000}
  - {vni: 77, inner_dst: 192.0.2.0/24, rate_bps: 8000}
  - {vni: 78, inner_dst: 2001:db8:1::/48, rate_bps: 8000}
",
        );
        let plan = Plan::new(&config);
        for (class, members) in &plan.classes {
            for &index in members {
                let limit = &config.limits[index];
                assert_eq!(
                    format!("{:?}", class.pattern(limit.vni, limit.inner_dst)),
                    format!("{:?}", class.template_pattern()),
                );
            }
        }
    }

    #[test]
    fn resources_cover_every_counter_and_meter() {
        let config = config("limits: [{vni: 1, rate_bps: 8}, {vni: 2, rate_bps: 8}]");
        let resources = Plan::resources(&config);
        assert_eq!((resources.counters, resources.meters), (7, 2));
    }
}
