// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL category system for shape-aware classification.
//!
//! Categories partition an ACL table's rules by their match shape
//! (e.g., "IPv4 + TCP", "IPv6 + UDP").  This enables:
//!
//! - **Typed dispatch after classification** — the category tells
//!   downstream code exactly which header fields were examined,
//!   without `Option` soup.
//! - **Backend optimization** — DPDK ACL maps categories directly to
//!   `category_mask` for parallel classification.  `rte_flow` and
//!   `tc-flower` can use categories to group rules by pattern shape.
//! - **Compile-time shape validation** — each category declares its
//!   expected match layers, and the table builder validates rules
//!   against their declared category.
//!
//! # Design
//!
//! Users define categories by implementing [`Category`] for an enum:
//!
//! ```ignore
//! use net::acl::category::*;
//! use net::acl::match_fields::*;
//!
//! enum MyCategories {
//!     Ipv4Tcp,
//!     Ipv4Udp,
//!     Ipv6Tcp,
//!     Ipv6Udp,
//! }
//!
//! impl CategorySet for MyCategories {
//!     const COUNT: usize = 4;
//!
//!     fn index(&self) -> usize {
//!         *self as usize
//!     }
//!
//!     fn expects(&self, fields: &AclMatchFields) -> bool {
//!         match self {
//!             Self::Ipv4Tcp => fields.ipv4().is_some() && fields.tcp().is_some(),
//!             Self::Ipv4Udp => fields.ipv4().is_some() && fields.udp().is_some(),
//!             Self::Ipv6Tcp => fields.ipv6().is_some() && fields.tcp().is_some(),
//!             Self::Ipv6Udp => fields.ipv6().is_some() && fields.udp().is_some(),
//!         }
//!     }
//! }
//! ```
//!
//! The [`CategorizedTable`] groups rules by category and validates
//! that each rule's match fields satisfy its category's expectations.
//!
//! # Backend compilation
//!
//! The [`Compiler`] trait transforms a [`CategorizedTable`] into a
//! backend-specific classifier.  Each backend maps categories to its
//! native grouping mechanism:
//!
//! - **DPDK ACL**: `category_mask` bits on each `rte_acl_rule`
//! - **`rte_flow`**: separate flow groups per category
//! - **`tc-flower`**: separate filter chains per category
//! - **Software**: per-category lookup tables

use crate::action::Action;
use crate::builder::AclMatchFields;
use crate::metadata::Metadata;
use crate::rule::AclRule;

/// Maximum number of categories (matches DPDK's `RTE_ACL_MAX_CATEGORIES`).
pub const MAX_CATEGORIES: usize = 16;

/// A user-defined set of ACL categories.
///
/// Each category represents a match field shape (e.g., "IPv4 + TCP").
/// Implement this trait for an enum to define the categories your
/// table supports.
pub trait CategorySet: Copy {
    /// The number of categories in this set.  Must be `<= MAX_CATEGORIES`.
    const COUNT: usize;

    /// The numeric index of this category (0-based).
    fn index(&self) -> usize;

    /// Validate that `fields` has the correct shape for this category.
    fn expects(&self, fields: &AclMatchFields) -> bool;
}

/// Error adding a rule to a [`CategorizedTable`].
#[derive(Debug, thiserror::Error)]
pub enum CategoryError {
    /// The rule's match fields don't satisfy the category's shape.
    #[error("rule does not match expected shape for category {category_index}")]
    ShapeMismatch {
        /// The category index the rule was assigned to.
        category_index: usize,
    },
    /// The category count exceeds [`MAX_CATEGORIES`].
    #[error("category count {count} exceeds maximum {MAX_CATEGORIES}")]
    TooManyCategories {
        /// The number of categories that was attempted.
        count: usize,
    },
}

/// A rule associated with one or more categories.
///
/// The `category_mask` is a bitmask where bit N means "this rule
/// participates in category N."  For DPDK ACL this maps directly
/// to `rte_acl_rule_data::category_mask`.
#[derive(Debug, Clone)]
pub struct CategorizedRule<M: Metadata = ()> {
    /// The underlying rule.
    rule: AclRule<M>,
    /// Bitmask of categories this rule applies to.
    category_mask: u16,
}

impl<M: Metadata> CategorizedRule<M> {
    /// The underlying rule.
    #[must_use]
    pub fn rule(&self) -> &AclRule<M> {
        &self.rule
    }

    /// The category bitmask.
    #[must_use]
    pub fn category_mask(&self) -> u16 {
        self.category_mask
    }
}

/// An ACL table with rules grouped by category.
///
/// Generic over the category set `C`, which defines the valid shapes
/// and their indices.
#[derive(Debug)]
pub struct CategorizedTable<C: CategorySet, M: Metadata = ()> {
    rules: Vec<CategorizedRule<M>>,
    default_action: Action,
    _categories: std::marker::PhantomData<C>,
}

impl<C: CategorySet, M: Metadata> CategorizedTable<C, M> {
    /// Create a new empty categorized table.
    ///
    /// # Errors
    ///
    /// Returns [`CategoryError::TooManyCategories`] if `C::COUNT`
    /// exceeds [`MAX_CATEGORIES`].
    pub fn new(default_action: Action) -> Result<Self, CategoryError> {
        if C::COUNT > MAX_CATEGORIES {
            return Err(CategoryError::TooManyCategories { count: C::COUNT });
        }
        Ok(Self {
            rules: Vec::new(),
            default_action,
            _categories: std::marker::PhantomData,
        })
    }

    /// Add a rule to a single category.
    ///
    /// Validates that the rule's match fields satisfy the category's
    /// expected shape.
    ///
    /// # Errors
    ///
    /// Returns [`CategoryError::ShapeMismatch`] if the rule doesn't
    /// match the category's expected shape.
    pub fn add_rule(mut self, category: C, rule: AclRule<M>) -> Result<Self, CategoryError> {
        let idx = category.index();
        if !category.expects(rule.packet_match()) {
            return Err(CategoryError::ShapeMismatch {
                category_index: idx,
            });
        }
        self.rules.push(CategorizedRule {
            category_mask: 1u16 << idx,
            rule,
        });
        Ok(self)
    }

    /// Add a rule to multiple categories.
    ///
    /// The rule's match fields must satisfy *every* category in the list.
    ///
    /// # Errors
    ///
    /// Returns [`CategoryError::ShapeMismatch`] for the first category
    /// whose shape the rule doesn't match.
    pub fn add_rule_multi(
        mut self,
        categories: &[C],
        rule: AclRule<M>,
    ) -> Result<Self, CategoryError> {
        let mut mask = 0u16;
        for cat in categories {
            if !cat.expects(rule.packet_match()) {
                return Err(CategoryError::ShapeMismatch {
                    category_index: cat.index(),
                });
            }
            mask |= 1u16 << cat.index();
        }
        self.rules.push(CategorizedRule {
            category_mask: mask,
            rule,
        });
        Ok(self)
    }

    /// All categorized rules.
    #[must_use]
    pub fn rules(&self) -> &[CategorizedRule<M>] {
        &self.rules
    }

    /// The default action when no rule matches.
    #[must_use]
    pub fn default_action(&self) -> Action {
        self.default_action
    }
}

/// Result of classifying a single packet.
///
/// Contains one result per category: the action from the highest-priority
/// matching rule, or the default action if no rule matched.
#[derive(Debug)]
pub struct ClassifyResult<C: CategorySet> {
    /// Per-category results.  Index by `category.index()`.
    results: Vec<Action>,
    _categories: std::marker::PhantomData<C>,
}

impl<C: CategorySet> ClassifyResult<C> {
    /// Create a result filled with the default action.
    #[must_use]
    pub fn with_default(default_action: Action) -> Self {
        Self {
            results: vec![default_action; C::COUNT],
            _categories: std::marker::PhantomData,
        }
    }

    /// Get the action for a specific category.
    #[must_use]
    pub fn action(&self, category: C) -> Action {
        self.results[category.index()]
    }
}

/// Backend-specific ACL compiler.
///
/// Transforms a [`CategorizedTable`] into a backend-specific classifier.
/// The classifier type and any errors are defined by the implementation.
///
/// # Backends
///
/// - **DPDK ACL**: compiles to `rte_acl_ctx` with `category_mask` per rule
/// - **`rte_flow`**: emits flow rules grouped by category
/// - **`tc-flower`**: emits filter chains grouped by category
/// - **Software**: builds per-category lookup tables
pub trait Compiler<C: CategorySet, M: Metadata = ()> {
    /// The compiled classifier type.
    type Classifier;
    /// Error type for compilation failures.
    type Error;

    /// Compile a categorized table into a backend-specific classifier.
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` if compilation fails (e.g., backend
    /// resource limits, unsupported match fields).
    fn compile(&self, table: &CategorizedTable<C, M>) -> Result<Self::Classifier, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::ClassifyResult;
    use crate::match_expr::FieldMatch;
    use crate::priority::Priority;
    use crate::range::{Ipv4Prefix, PortRange};
    use crate::AclRuleBuilder;
    use net::tcp::port::TcpPort;
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[derive(Debug, Clone, Copy)]
    #[allow(dead_code)] // variants used for index mapping, not all constructed in tests
    enum TestCat {
        Ipv4Tcp,
        Ipv4Udp,
        Ipv6Tcp,
        Ipv6Udp,
    }

    impl CategorySet for TestCat {
        const COUNT: usize = 4;

        fn index(&self) -> usize {
            *self as usize
        }

        fn expects(&self, fields: &AclMatchFields) -> bool {
            match self {
                Self::Ipv4Tcp => fields.ipv4().is_some() && fields.tcp().is_some(),
                Self::Ipv4Udp => fields.ipv4().is_some() && fields.udp().is_some(),
                Self::Ipv6Tcp => fields.ipv6().is_some() && fields.tcp().is_some(),
                Self::Ipv6Udp => fields.ipv6().is_some() && fields.udp().is_some(),
            }
        }
    }

    #[test]
    fn add_rule_to_matching_category() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::exact(TcpPort::new_checked(80).unwrap()));
            })
            .permit(pri(100));

        let table = CategorizedTable::<TestCat>::new(Action::Deny)
            .unwrap()
            .add_rule(TestCat::Ipv4Tcp, rule)
            .unwrap();

        assert_eq!(table.rules().len(), 1);
        assert_eq!(table.rules()[0].category_mask(), 1 << 0);
    }

    #[test]
    fn reject_rule_with_wrong_shape() {
        // IPv4+UDP rule assigned to Ipv4Tcp category — should fail
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .udp(|_| {})
            .deny(pri(100));

        let result = CategorizedTable::<TestCat>::new(Action::Deny)
            .unwrap()
            .add_rule(TestCat::Ipv4Tcp, rule);

        assert!(result.is_err());
    }

    #[test]
    fn multi_category_rule() {
        // A rule matching just IPv4 (no transport) could apply to both
        // Ipv4Tcp and Ipv4Udp if the category allows it.
        // But our TestCat requires transport, so let's use a different category set.

        #[derive(Debug, Clone, Copy)]
        #[allow(dead_code)]
        enum BroadCat {
            AnyIpv4,
            AnyIpv6,
        }

        impl CategorySet for BroadCat {
            const COUNT: usize = 2;

            fn index(&self) -> usize {
                *self as usize
            }

            fn expects(&self, fields: &AclMatchFields) -> bool {
                match self {
                    Self::AnyIpv4 => fields.ipv4().is_some(),
                    Self::AnyIpv6 => fields.ipv6().is_some(),
                }
            }
        }

        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .permit(pri(50));

        // This rule has IPv4 match, should pass AnyIpv4 but fail AnyIpv6
        let result = CategorizedTable::<BroadCat>::new(Action::Deny)
            .unwrap()
            .add_rule_multi(&[BroadCat::AnyIpv4], rule);

        assert!(result.is_ok());
    }

    #[test]
    fn classify_result_dispatch() {
        let mut result = ClassifyResult::<TestCat>::with_default(Action::Deny);
        // Simulate: Ipv4Tcp matched with Permit
        result.results[TestCat::Ipv4Tcp.index()] = Action::Permit;

        assert_eq!(result.action(TestCat::Ipv4Tcp), Action::Permit);
        assert_eq!(result.action(TestCat::Ipv4Udp), Action::Deny); // default
        assert_eq!(result.action(TestCat::Ipv6Tcp), Action::Deny);
    }
}
