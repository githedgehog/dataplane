// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Opaque compiled classifier.
//!
//! [`Classifier`] is the user-facing type returned by
//! [`AclTable::compile()`](crate::table::AclTable).  It hides the
//! backend implementation (linear scan, DPDK ACL trie, two-tier
//! delta+base) behind a single type.
//!
//! The internal representation is a private enum — the set of backends
//! is closed and the classify hot path uses static dispatch (match on
//! enum variant, no vtable).

use net::headers::Headers;

use crate::action::{ActionSequence, Fate};
use crate::builder::AclMatchFields;
use crate::classify::{self, ClassifyOutcome};
use crate::metadata::Metadata;
use crate::priority::Priority;
use crate::rule::AclRule;
use crate::table::AclTable;

/// A compiled rule with metadata erased.
///
/// The classifier only needs match fields, actions, and priority —
/// it doesn't need the user's metadata type `M`.
#[derive(Debug, Clone)]
struct CompiledEntry {
    packet_match: AclMatchFields,
    actions: ActionSequence,
    priority: Priority,
}

impl CompiledEntry {
    fn from_rule<M: Metadata>(rule: &AclRule<M>) -> Self {
        Self {
            packet_match: rule.packet_match().clone(),
            actions: rule.actions().clone(),
            priority: rule.priority(),
        }
    }
}

/// The internal classifier representation.
///
/// Private — users interact with [`Classifier`] and never see this.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Tiered variant used in future update support
enum ClassifierInner {
    /// Linear scan of sorted rules.  Reference implementation.
    Linear {
        rules: Vec<CompiledEntry>,
        default_fate: Fate,
    },
    /// Two-tier: check delta first, fall through to base.
    Tiered {
        delta: Box<ClassifierInner>,
        base: Box<ClassifierInner>,
    },
    // Future variants:
    // DpdkAcl { context: ..., default_fate: Fate },
    // RteFlow { ... },
}

impl ClassifierInner {
    fn classify<'a>(&'a self, headers: &Headers) -> ClassifyOutcome<'a> {
        match self {
            Self::Linear {
                rules,
                default_fate,
            } => {
                for entry in rules {
                    if classify::rule_matches_headers(&entry.packet_match, headers) {
                        return ClassifyOutcome::Matched(&entry.actions);
                    }
                }
                ClassifyOutcome::Default(*default_fate)
            }
            Self::Tiered { delta, base } => {
                let outcome = delta.classify(headers);
                if matches!(outcome, ClassifyOutcome::Matched(_)) {
                    return outcome;
                }
                base.classify(headers)
            }
        }
    }

    fn default_fate(&self) -> Fate {
        match self {
            Self::Linear { default_fate, .. } => *default_fate,
            Self::Tiered { base, .. } => base.default_fate(),
        }
    }
}

/// An opaque compiled ACL classifier.
///
/// Created by [`AclTable::compile()`].  The internal representation
/// (linear scan, trie, two-tier) is hidden — the user calls
/// [`classify()`](Classifier::classify) and gets a
/// [`ClassifyOutcome`].
///
/// For testing and debugging, [`AclTable::compile_linear()`] returns
/// a [`LinearClassifier`](crate::LinearClassifier) with full
/// introspection (access to sorted rules, priority, etc.).
#[derive(Debug, Clone)]
pub struct Classifier(ClassifierInner);

impl Classifier {
    /// Classify a packet's headers against the compiled rule set.
    ///
    /// Returns the [`ClassifyOutcome`]: either the matched rule's
    /// [`ActionSequence`] or the table's default [`Fate`].
    #[must_use]
    pub fn classify<'a>(&'a self, headers: &Headers) -> ClassifyOutcome<'a> {
        self.0.classify(headers)
    }

    /// The default fate when no rule matches.
    #[must_use]
    pub fn default_fate(&self) -> Fate {
        self.0.default_fate()
    }
}

impl<M: Metadata + Clone> AclTable<M> {
    /// Compile the table into an opaque [`Classifier`].
    ///
    /// The compiler picks the best internal representation.
    /// Currently uses linear scan; future versions will select
    /// DPDK ACL, `rte_flow`, or two-tier based on rule set size
    /// and available backends.
    #[must_use]
    pub fn compile(&self) -> Classifier {
        let mut entries: Vec<CompiledEntry> = self
            .rules()
            .iter()
            .map(CompiledEntry::from_rule)
            .collect();
        entries.sort_by_key(|e| e.priority);

        Classifier(ClassifierInner::Linear {
            rules: entries,
            default_fate: self.default_fate(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::action::Fate;
    use crate::range::{Ipv4Prefix, PortRange};
    use crate::{AclRuleBuilder, AclTableBuilder, FieldMatch, Priority};
    use net::headers::builder::HeaderStack;
    use net::tcp::port::TcpPort;
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn compile_returns_opaque_classifier() {
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
                        tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
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

        assert_eq!(classifier.classify(&headers).fate(), Fate::Forward);

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

        assert_eq!(classifier.classify(&headers2).fate(), Fate::Drop);
    }

    #[test]
    fn compile_matches_compile_linear() {
        // The opaque Classifier must produce identical results to
        // the reference LinearClassifier.
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

        let opaque = table.compile();
        let reference = table.compile_linear();

        // Test several packets and verify identical fates
        let test_ips = [
            Ipv4Addr::new(10, 1, 2, 3),   // matches both → deny (pri 100)
            Ipv4Addr::new(10, 2, 0, 1),   // matches /8 only → permit
            Ipv4Addr::new(192, 168, 1, 1), // matches neither → drop (default)
        ];

        for ip in test_ips {
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
                opaque.classify(&headers).fate(),
                reference.classify(&headers).fate(),
                "mismatch for source IP {ip}"
            );
        }
    }
}
