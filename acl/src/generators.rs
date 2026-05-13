// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bolero `TypeGenerator` and `ValueGenerator` implementations for
//! ACL types.
//!
//! `TypeGenerator` impls are covering: they will eventually produce
//! every legal value for the type.
//!
//! `ValueGenerator` impls target interesting subsets (boundary
//! conditions, common patterns, known-tricky cases).
//!
//! Generators compose: compound types delegate to their components'
//! generators via `driver.produce::<T>()`.

// ---- Leaf types ----

mod priority_gen {
    use crate::priority::Priority;
    use bolero::TypeGenerator;
    use std::num::NonZero;

    impl TypeGenerator for Priority {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            let nz = driver.produce::<NonZero<u32>>()?;
            Some(Priority::new(nz.get()).unwrap_or_else(|_| {
                // NonZero<u32> is always >= 1, so this can't fail.
                unreachable!()
            }))
        }
    }
}

// Ipv4Prefix and Ipv6Prefix TypeGenerator impls are provided by the
// lpm crate (behind its `testing` feature, enabled via our `bolero` feature).

/// Generate a random inclusive port range.
///
/// We can't impl `TypeGenerator for RangeInclusive<u16>` due to the
/// orphan rule (both trait and type are foreign).  This helper is
/// used by the `TcpMatch` and `UdpMatch` generators instead.
fn gen_port_range<D: bolero::Driver>(driver: &mut D) -> Option<std::ops::RangeInclusive<u16>> {
    let a = driver.produce::<u16>()?;
    let b = driver.produce::<u16>()?;
    let (min, max) = if a <= b { (a, b) } else { (b, a) };
    Some(min..=max)
}

/// Generate a random `FieldMatch<RangeInclusive<u16>>`.
fn gen_port_field<D: bolero::Driver>(
    driver: &mut D,
) -> Option<crate::match_expr::FieldMatch<std::ops::RangeInclusive<u16>>> {
    use crate::match_expr::FieldMatch;
    if driver.produce::<bool>()? {
        Some(FieldMatch::Select(gen_port_range(driver)?))
    } else {
        Some(FieldMatch::Ignore)
    }
}

// ---- FieldMatch<T> ----

mod field_match_gen {
    use crate::match_expr::FieldMatch;
    use bolero::TypeGenerator;

    impl<T: TypeGenerator> TypeGenerator for FieldMatch<T> {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            // ~50% Ignore, ~50% Select  --  biased toward producing
            // both variants equally.
            if driver.produce::<bool>()? {
                Some(FieldMatch::Select(driver.produce::<T>()?))
            } else {
                Some(FieldMatch::Ignore)
            }
        }
    }
}

// ---- Match field structs ----

mod match_field_gen {
    use crate::match_fields::*;
    use bolero::TypeGenerator;

    impl TypeGenerator for EthMatch {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src_mac: driver.produce()?,
                dst_mac: driver.produce()?,
                ether_type: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for VlanMatch {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                vid: driver.produce()?,
                pcp: driver.produce()?,
                inner_ether_type: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Ipv4Match {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src: driver.produce()?,
                dst: driver.produce()?,
                protocol: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Ipv6Match {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src: driver.produce()?,
                dst: driver.produce()?,
                protocol: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for TcpMatch {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src: super::gen_port_field(driver)?,
                dst: super::gen_port_field(driver)?,
            })
        }
    }

    impl TypeGenerator for UdpMatch {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src: super::gen_port_field(driver)?,
                dst: super::gen_port_field(driver)?,
            })
        }
    }

    impl TypeGenerator for Icmp4Match {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                icmp_type: driver.produce()?,
                icmp_code: driver.produce()?,
            })
        }
    }
}

// ---- Action types ----

mod action_gen {
    use crate::action::{ActionSequence, Fate, Step, TableId};
    use bolero::TypeGenerator;

    impl TypeGenerator for Step {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            match driver.produce::<u8>()? % 5 {
                0 => Some(Step::Mark(driver.produce()?)),
                1 => Some(Step::Meta(driver.produce()?)),
                2 => Some(Step::Tag {
                    index: driver.produce::<u8>()? % 8,
                    value: driver.produce()?,
                }),
                3 => Some(Step::Flag),
                _ => Some(Step::Count(driver.produce()?)),
            }
        }
    }

    impl TypeGenerator for Fate {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            match driver.produce::<u8>()? % 5 {
                0 => Some(Fate::Drop),
                1 => Some(Fate::Trap),
                2 => Some(Fate::Accept),
                3 => Some(Fate::Learn),
                _ => Some(Fate::Jump(driver.produce::<TableId>()?)),
            }
        }
    }

    impl TypeGenerator for ActionSequence {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            // 0-4 steps, then a fate.
            let step_count = driver.produce::<u8>()? % 5;
            let mut steps = Vec::with_capacity(step_count as usize);
            for _ in 0..step_count {
                steps.push(driver.produce()?);
            }
            let fate = driver.produce()?;
            Some(ActionSequence::new(steps, fate))
        }
    }
}

// ---- AclRule (without builder  --  direct construction for testing) ----

mod rule_gen {
    use crate::action::ActionSequence;
    use crate::builder::AclRuleBuilder;
    use crate::match_fields::{EthMatch, Ipv4Match, TcpMatch, UdpMatch, Icmp4Match, Ipv6Match};
    use crate::priority::Priority;
    use crate::rule::AclRule;
    use bolero::TypeGenerator;

    impl TypeGenerator for AclRule {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            // Generate via the builder to get valid match field combinations
            // with proper conform() behavior (e.g., adding TCP sets
            // protocol=TCP on the IPv4 match).
            let has_eth = driver.produce::<bool>()?;

            let builder = AclRuleBuilder::new();
            if has_eth {
                let eth: EthMatch = driver.produce()?;
                let builder2 = builder.eth(|e| *e = eth);

                let ip_choice = driver.produce::<u8>()? % 3;
                match ip_choice {
                    0 => {
                        let ipv4: Ipv4Match = driver.produce()?;
                        let builder3 = builder2.ipv4(|ip| *ip = ipv4);
                        let transport = driver.produce::<u8>()? % 4; // AGENT: ideally this number would be derived from the enum size.  Maybe strum can help
                        let pri = driver.produce::<Priority>()?;
                        let actions = driver.produce::<ActionSequence>()?;
                        return Some(match transport {
                            0 => {
                                let tcp: TcpMatch = driver.produce()?;
                                builder3.tcp(|t| *t = tcp).action(actions, pri)
                            }
                            1 => {
                                let udp: UdpMatch = driver.produce()?;
                                builder3.udp(|u| *u = udp).action(actions, pri)
                            }
                            2 => {
                                let icmp: Icmp4Match = driver.produce()?;
                                builder3.icmp4(|i| *i = icmp).action(actions, pri)
                            }
                            _ => builder3.action(actions, pri),
                        });
                    }
                    1 => {
                        let ipv6: Ipv6Match = driver.produce()?;
                        let builder3 = builder2.ipv6(|ip| *ip = ipv6);
                        let transport = driver.produce::<u8>()? % 3;
                        let pri = driver.produce::<Priority>()?;
                        let actions = driver.produce::<ActionSequence>()?;
                        return Some(match transport {
                            0 => {
                                let tcp: TcpMatch = driver.produce()?;
                                builder3.tcp(|t| *t = tcp).action(actions, pri)
                            }
                            1 => {
                                let udp: UdpMatch = driver.produce()?;
                                builder3.udp(|u| *u = udp).action(actions, pri)
                            }
                            _ => builder3.action(actions, pri),
                        });
                    }
                    _ => {
                        let pri = driver.produce::<Priority>()?;
                        let actions = driver.produce::<ActionSequence>()?;
                        return Some(builder2.action(actions, pri));
                    }
                }
            }

            let pri = driver.produce::<Priority>()?;
            let actions = driver.produce::<ActionSequence>()?;
            Some(builder.action(actions, pri))
        }
    }
}

// ---- ValueGenerators for targeted testing ----

/// Generate an [`AclTable`] with a controlled number of rules.
///
/// Rules are deduplicated by priority (last writer wins) to avoid
/// ambiguous priority ordering.  The actual table size may be smaller
/// than `rule_count` if priority collisions occur, but will tend
/// toward `rule_count` for large priority spaces.
pub struct GenerateAclTable {
    /// Target number of rules in the generated table.
    pub rule_count: usize,
}

impl bolero::ValueGenerator for GenerateAclTable {
    type Output = crate::table::AclTable;

    fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        use crate::action::Fate;
        use crate::rule::AclRule;
        use crate::table::AclTableBuilder;
        use std::collections::HashSet;

        let default_fate = if driver.produce::<bool>()? {
            Fate::Drop
        } else {
            Fate::Accept
        };

        let mut builder = AclTableBuilder::new(default_fate);
        let mut seen_priorities = HashSet::new();

        for _ in 0..self.rule_count {
            let rule: AclRule = driver.produce()?;
            if seen_priorities.insert(rule.priority()) {
                builder.push_rule(rule);
            }
        }

        Some(builder.build())
    }
}

/// Generate a pair of [`AclTable`]s where the second is a mutation
/// of the first (simulating an update).
///
/// The mutation adds, removes, and modifies a controlled number of
/// rules, exercising the update planning logic.
pub struct GenerateTablePair {
    /// Target number of rules in the base table.
    pub base_rule_count: usize,
    /// Number of rules to add in the updated table.
    pub add_count: usize,
    /// Number of rules to remove in the updated table.
    pub remove_count: usize,
    /// Number of rules to modify (change action) in the updated table.
    pub modify_count: usize,
}

impl bolero::ValueGenerator for GenerateTablePair {
    type Output = (crate::table::AclTable, crate::table::AclTable);

    fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        use crate::action::{ActionSequence, Fate};
        use crate::rule::AclRule;

        // Generate the base table.
        let base = GenerateAclTable {
            rule_count: self.base_rule_count,
        }
        .generate(driver)?;

        // Mutate to produce the updated table.
        let mut builder = base.to_builder();
        let old_rules: Vec<_> = base.rules().to_vec();

        // Remove some rules.
        let removable = old_rules.len().min(self.remove_count);
        for i in 0..removable {
            // Remove by priority of the i-th rule.
            builder.remove_by_priority(old_rules[i].priority());
        }

        // Modify some rules (change action, keep priority + match).
        let modifiable = old_rules.len().saturating_sub(removable).min(self.modify_count);
        for i in removable..removable + modifiable {
            let old = &old_rules[i];
            // Toggle the fate: Accept ↔ Drop.
            let new_fate = if old.actions().fate() == Fate::Accept {
                Fate::Drop
            } else {
                Fate::Accept
            };
            builder.remove_by_priority(old.priority());
            let new_rule = AclRule::new(
                old.packet_match().clone(),
                (),
                ActionSequence::just(new_fate),
                old.priority(),
            );
            builder.push_rule(new_rule);
        }

        // Add new rules.
        for _ in 0..self.add_count {
            let rule: AclRule = driver.produce()?;
            builder.push_rule(rule);
        }

        let updated = builder.build();
        Some((base, updated))
    }
}
