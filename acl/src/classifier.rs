// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Compiled ACL classifier.
//!
//! [`Classifier<M>`] is the user-facing type returned by
//! [`AclTable::compile()`](crate::table::AclTable).  It hides the
//! backend implementation (linear scan, DPDK ACL trie, two-tier
//! delta+base) behind a single type.
//!
//! The internal representation is a private enum  --  the set of backends
//! is closed and the classify hot path uses static dispatch (match on
//! enum variant, no vtable).

use net::headers::Headers;

use crate::action::Fate;
use crate::classify::{self, ClassifyOutcome};
use crate::metadata::Metadata;
use crate::rule::AclRule;
use crate::table::AclTable;

/// The internal classifier representation.
///
/// Private  --  users interact with [`Classifier`] and never see this.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Cascade used in update support
enum ClassifierInner<M: Metadata> {
    /// Linear scan of sorted rules.  Reference implementation.
    Linear {
        rules: Vec<AclRule<M>>,
        default_fate: Fate,
    },

    /// Ordered cascade: try each stage in sequence, return the first
    /// match.  The last stage's default fate is the cascade's default.
    ///
    /// Used for two-tier delta+base updates:
    /// - `[Linear(delta), Linear(base)]`  --  two-tier update
    ///
    /// Per-flow state caches (NAT flow tables, MAC learning) are
    /// owned by the network function and sit *in front of* the
    /// classifier, not inside it.  Rules that require flow state
    /// creation use [`Fate::Learn`] to signal the NF.
    Cascade(Vec<ClassifierInner<M>>),

    // Future variants:
    // DpdkAcl { context: ..., default_fate: Fate },
    // RteFlow { ... },
}

impl<M: Metadata> ClassifierInner<M> {
    fn classify<'a>(
        &'a self,
        headers: &Headers,
        metadata: &M::Values,
    ) -> ClassifyOutcome<'a> {
        match self {
            Self::Linear {
                rules,
                default_fate,
            } => {
                for rule in rules {
                    if classify::rule_matches_headers(rule.packet_match(), headers)
                        && rule.metadata().matches_values(metadata)
                    {
                        return ClassifyOutcome::Matched(rule.actions());
                    }
                }
                ClassifyOutcome::Default(*default_fate)
            }

            Self::Cascade(stages) => {
                for stage in stages {
                    let outcome = stage.classify(headers, metadata);
                    if matches!(outcome, ClassifyOutcome::Matched(_)) {
                        return outcome;
                    }
                }
                // No match in any stage → default from last stage.
                stages
                    .last()
                    .map_or(ClassifyOutcome::Default(Fate::Drop), |s| {
                        ClassifyOutcome::Default(s.default_fate())
                    })
            }
        }
    }

    fn default_fate(&self) -> Fate {
        match self {
            Self::Linear { default_fate, .. } => *default_fate,
            Self::Cascade(stages) => stages
                .last()
                .map_or(Fate::Drop, ClassifierInner::default_fate),
        }
    }
}

/// A compiled ACL classifier.
///
/// Created by [`AclTable::compile()`].  The internal representation
/// (linear scan, trie, two-tier) is hidden  --  the user calls
/// [`classify()`](Classifier::classify) and gets a
/// [`ClassifyOutcome`].
///
/// `M` is the metadata match type, defaulting to `()` (no metadata).
#[derive(Debug, Clone)]
pub struct Classifier<M: Metadata = ()>(ClassifierInner<M>);

impl<M: Metadata> Classifier<M> {
    /// Classify a packet's headers and metadata against the compiled
    /// rule set.
    ///
    /// Returns the [`ClassifyOutcome`]: either the matched rule's
    /// [`ActionSequence`](crate::ActionSequence) or the table's
    /// default [`Fate`].
    #[must_use]
    pub fn classify<'a>(
        &'a self,
        headers: &Headers,
        metadata: &M::Values,
    ) -> ClassifyOutcome<'a> {
        self.0.classify(headers, metadata)
    }

    /// The default fate when no rule matches.
    #[must_use]
    pub fn default_fate(&self) -> Fate {
        self.0.default_fate()
    }

    /// The sorted rules in the classifier (for introspection/testing).
    #[must_use]
    pub fn rules(&self) -> &[AclRule<M>] {
        match &self.0 {
            ClassifierInner::Linear { rules, .. } => rules,
            ClassifierInner::Cascade(_) => &[],
        }
    }

    /// Build a Cascade classifier from multiple stages.
    ///
    /// Stages are tried in order; first match wins.
    #[must_use]
    pub fn cascade(stages: Vec<Classifier<M>>) -> Classifier<M> {
        let inners = stages.into_iter().map(|c| c.0).collect();
        Classifier(ClassifierInner::Cascade(inners))
    }
}

impl<M: Metadata + Clone> AclTable<M> {
    /// Compile the table into a [`Classifier`].
    ///
    /// The compiler picks the best internal representation.
    /// Currently uses linear scan; future versions will select
    /// DPDK ACL, `rte_flow`, or two-tier based on rule set size
    /// and available backends.
    #[must_use]
    pub fn compile(&self) -> Classifier<M> {
        let mut rules: Vec<AclRule<M>> = self.rules().to_vec();
        rules.sort_by_key(AclRule::priority);

        Classifier(ClassifierInner::Linear {
            rules,
            default_fate: self.default_fate(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::action::Fate;
    use lpm::prefix::{IpPrefix, Ipv4Prefix};
    use crate::{AclRuleBuilder, AclTableBuilder, FieldMatch, Priority};
    use net::headers::builder::HeaderStack;
    use net::tcp::port::TcpPort;
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn compile_returns_classifier() {
        let table = AclTableBuilder::new(Fate::Drop)
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        );
                    })
                    .tcp(|tcp| {
                        tcp.dst = FieldMatch::Select(80u16..=80u16);
                    })
                    .permit(pri(100)),
            )
            .build();

        let classifier = table.compile();

        // Matching packet
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(
                    net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
                );
            })
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();

        assert_eq!(classifier.classify(&headers, &()).fate(), Fate::Accept);

        // Non-matching packet → default Drop
        let headers2 = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(
                    net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap(),
                );
            })
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();

        assert_eq!(classifier.classify(&headers2, &()).fate(), Fate::Drop);
    }

    #[test]
    fn priority_ordering_through_compile() {
        let table = AclTableBuilder::new(Fate::Drop)
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        );
                    })
                    .permit(pri(200)),
            )
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap(),
                        );
                    })
                    .deny(pri(100)),
            )
            .build();

        let classifier = table.compile();

        // Test several packets
        let test_ips = [
            (Ipv4Addr::new(10, 1, 2, 3), Fate::Drop),     // matches both → deny (pri 100)
            (Ipv4Addr::new(10, 2, 0, 1), Fate::Accept),   // matches /8 only → permit
            (Ipv4Addr::new(192, 168, 1, 1), Fate::Drop),   // matches neither → default
        ];

        for (ip, expected) in test_ips {
            let headers = HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip_hdr| {
                    ip_hdr.set_source(
                        net::ipv4::UnicastIpv4Addr::new(ip).unwrap(),
                    );
                })
                .tcp(|_| {})
                .build_headers()
                .unwrap();

            assert_eq!(
                classifier.classify(&headers, &()).fate(),
                expected,
                "mismatch for source IP {ip}"
            );
        }
    }
}
