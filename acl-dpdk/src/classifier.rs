// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! High-level DPDK ACL classifier.
//!
//! [`DpdkAclClassifier`] is the user-facing type that compiles an
//! [`AclTable`] into an optimised DPDK ACL context and provides
//! safe single-call classification.
//!
//! # Usage
//!
//! ```ignore
//! let classifier = DpdkAclClassifier::compile(&table, SocketId::ANY)?;
//! let fate = classifier.classify(&headers);
//! ```

use acl::{AclTable, Fate, FieldSignature, Metadata};
use dpdk::acl::classifier::{AclClassifier, AclClassifierBuilder, AclRule};
use dpdk::acl::rule::RuleData;
use dpdk::socket::SocketId;
use net::headers::Headers;

use crate::compiler;
use crate::input;

/// Error during DPDK ACL classifier compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// The table has no rules that can be compiled to DPDK ACL.
    #[error("no compilable rules in table")]
    EmptyTable,
    /// DPDK context creation failed.
    #[error("DPDK context creation failed: {0}")]
    CreateFailed(#[from] dpdk::acl::error::AclCreateError),
    /// DPDK rule addition failed.
    #[error("DPDK rule addition failed: {0}")]
    AddRulesFailed(#[from] dpdk::acl::error::AclAddRulesError),
    /// DPDK context build failed.
    #[error("DPDK context build failed: {0}")]
    BuildFailed(#[from] dpdk::acl::error::AclBuildError),
}

/// A compiled DPDK ACL classifier.
///
/// Wraps a DPDK ACL context and provides safe, single-call
/// classification against packet headers.  All DPDK details
/// (field signatures, categories, compact buffers, priority
/// resolution) are handled internally.
///
/// Created by [`DpdkAclClassifier::compile`].
pub struct DpdkAclClassifier<M: Metadata = ()> {
    /// The compiled DPDK ACL context.
    context: AclClassifier,
    /// The union field signature (determines compact buffer layout).
    signature: FieldSignature,
    /// Number of categories used in classification.
    num_categories: u32,
    /// The original table (needed for result resolution).
    table: AclTable<M>,
}

impl<M: Metadata + Clone> DpdkAclClassifier<M> {
    /// Compile an [`AclTable`] into a DPDK ACL classifier.
    ///
    /// Allocates DPDK memory on [`SocketId::ANY`].  Use
    /// [`compile_for_socket`](Self::compile_for_socket) to pin
    /// allocation to a specific NUMA socket.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] if the table is empty, or if DPDK
    /// rejects the rules or configuration.
    pub fn compile(table: &AclTable<M>) -> Result<Self, CompileError> {
        Self::compile_for_socket(table, SocketId::ANY)
    }

    /// Compile an [`AclTable`] into a DPDK ACL classifier, allocating
    /// memory on the specified NUMA socket.
    ///
    /// Uses the category-aware compilation path: all signature groups
    /// are merged into a single DPDK ACL context with per-group
    /// categories.  Classification requires only a single DPDK call.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] if the table is empty, or if DPDK
    /// rejects the rules or configuration.
    pub fn compile_for_socket(
        table: &AclTable<M>,
        socket_id: SocketId,
    ) -> Result<Self, CompileError> {
        let comp = compiler::compile_categories(table)
            .ok_or(CompileError::EmptyTable)?;

        let group = &comp.group;
        let num_fields = group.field_count();
        let num_rules = group.rules().len();

        let mut builder = AclClassifierBuilder::new(
            "acl_classifier",
            socket_id,
            num_rules as u32,
            num_fields,
        )?;

        // Convert CompiledRules to the dpdk crate's AclRule type.
        let rules: Vec<AclRule> = group
            .rules()
            .iter()
            .map(|cr| AclRule {
                data: cr.data,
                fields: cr.fields.clone(),
            })
            .collect();

        builder.add_rules(&rules)?;
        let context = builder.build(comp.num_categories, group.field_defs())?;

        Ok(Self {
            context,
            signature: group.signature(),
            num_categories: comp.num_categories,
            table: table.clone(),
        })
    }

    /// Classify a packet's headers against the compiled rule set.
    ///
    /// Returns a [`ClassifyOutcome`] — either the matched rule's
    /// full [`ActionSequence`](acl::ActionSequence) (with Mark, Meta,
    /// Tag, Flag values accessible via convenience methods), or the
    /// table's default [`Fate`] if no rule matched.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let outcome = classifier.classify(&headers);
    /// match outcome {
    ///     ClassifyOutcome::Matched(seq) => {
    ///         let fate = seq.fate();
    ///         let vpc_id = seq.meta();    // Option<u32>
    ///         let nat_flags = seq.mark(); // Option<u32>
    ///     }
    ///     ClassifyOutcome::Default(fate) => { /* no rule matched */ }
    /// }
    /// ```
    #[must_use]
    pub fn classify<'a>(&'a self, headers: &Headers) -> acl::ClassifyOutcome<'a> {
        let acl_input = input::assemble_compact_input(headers, self.signature);
        let mut results = vec![0u32; self.num_categories as usize];

        // SAFETY: the compact input buffer is assembled by our compiler
        // to match the field layout used to build the DPDK context.
        // The results buffer is correctly sized for num_categories.
        #[allow(unsafe_code)]
        let classify_result = unsafe {
            self.context
                .classify(acl_input.as_ptr(), &mut results, self.num_categories)
        };
        if classify_result.is_err() {
            return acl::ClassifyOutcome::Default(self.table.default_fate());
        }

        let best = compiler::resolve_categories(
            &self.table,
            &results,
            self.num_categories,
        );

        if best == 0 {
            return acl::ClassifyOutcome::Default(self.table.default_fate());
        }

        let idx = (best - 1) as usize;
        match self.table.rules().get(idx) {
            Some(rule) => acl::ClassifyOutcome::Matched(rule.actions()),
            None => acl::ClassifyOutcome::Default(self.table.default_fate()),
        }
    }

    /// Classify and return just the terminal [`Fate`].
    ///
    /// Convenience wrapper around [`classify`](Self::classify) for
    /// callers that only need the fate, not the full action sequence.
    #[must_use]
    pub fn classify_fate(&self, headers: &Headers) -> Fate {
        self.classify(headers).fate()
    }

    /// The union field signature used by this classifier.
    #[must_use]
    pub fn signature(&self) -> FieldSignature {
        self.signature
    }

    /// The number of categories in the compiled context.
    #[must_use]
    pub fn num_categories(&self) -> u32 {
        self.num_categories
    }

    /// The default fate when no rule matches.
    #[must_use]
    pub fn default_fate(&self) -> Fate {
        self.table.default_fate()
    }
}
