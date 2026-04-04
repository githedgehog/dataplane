// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL action model: ordered steps followed by a terminal fate.
//!
//! A rule's action is an [`ActionSequence`]: zero or more [`Step`]s
//! (mutations, observations) followed by exactly one [`Fate`]
//! (what ultimately happens to the packet).
//!
//! The two-type split (`Step` + `Fate`) provides a compile-time
//! guarantee that every rule has exactly one fate and it's always
//! the terminal operation.
//!
//! # Jump cycle detection
//!
//! `Fate::Jump(TableId)` enables multi-table classification chains.
//! Cycle detection (A→B→A) is a compiler-pass concern, not a type-
//! system concern — cycles can span multiple tables and no single-
//! table const generic can catch them.

/// Identifier for a table in a multi-table jump chain.
pub type TableId = u32;

/// A non-terminal action step applied to a matched packet.
///
/// Steps are applied in order before the terminal [`Fate`].
/// The ordering is significant — steps do not commute in general
/// (e.g., "push VLAN then count bytes" differs from "count then push").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Step {
    // ---- Observation (side effects, no packet modification) ----
    /// Increment a counter associated with this rule.
    Count(u32),
    /// Attach a u32 mark value to the packet metadata.
    Mark(u32),

    // ---- Mutation (packet modification) ----
    // Placeholder variants — will grow as we integrate rte_flow
    // SetFlowField, encap/decap, VLAN push/pop, etc.
}

/// The terminal fate of a matched packet.
///
/// Exactly one `Fate` must appear per [`ActionSequence`], as the
/// final operation.  This is enforced structurally — `Fate` is a
/// separate field, not part of the step vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fate {
    /// Drop the packet.
    Drop,
    /// Punt the packet to software processing.
    ///
    /// Used by the cascade compiler when a rule can't be offloaded
    /// to hardware.  In software, this is a no-op (the packet is
    /// already in software).
    Trap,
    /// Allow the packet to continue through the pipeline.
    ///
    /// This is the "permit" / "accept" / "pass" action.
    Forward,
    /// Evaluate the packet against another table.
    ///
    /// Enables multi-stage classification.  Jump cycle detection
    /// is a compiler-pass concern.
    Jump(TableId),
}

/// An ordered sequence of action steps followed by a terminal fate.
///
/// This is the complete action specification for an ACL rule.
/// Steps are applied in order, then the fate determines what
/// ultimately happens to the packet.
///
/// # Examples
///
/// ```
/// # use dataplane_acl::{ActionSequence, Fate, Step};
/// // Simple permit (no steps)
/// let permit = ActionSequence::just(Fate::Forward);
///
/// // Drop with counter
/// let deny = ActionSequence::new(vec![Step::Count(1)], Fate::Drop);
///
/// // Mark then forward
/// let mark_and_pass = ActionSequence::new(
///     vec![Step::Mark(42)],
///     Fate::Forward,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionSequence {
    /// Ordered non-terminal steps.
    steps: Vec<Step>,
    /// Terminal fate.
    fate: Fate,
}

impl ActionSequence {
    /// Create a new action sequence with steps and a fate.
    #[must_use]
    pub fn new(steps: Vec<Step>, fate: Fate) -> Self {
        Self { steps, fate }
    }

    /// Create an action sequence with no steps — just a fate.
    #[must_use]
    pub fn just(fate: Fate) -> Self {
        Self {
            steps: Vec::new(),
            fate,
        }
    }

    /// Shorthand for `Forward` with no steps (the common "permit" case).
    #[must_use]
    pub fn forward() -> Self {
        Self::just(Fate::Forward)
    }

    /// Shorthand for `Drop` with no steps (the common "deny" case).
    #[must_use]
    pub fn drop_packet() -> Self {
        Self::just(Fate::Drop)
    }

    /// Shorthand for `Trap` with no steps.
    #[must_use]
    pub fn trap() -> Self {
        Self::just(Fate::Trap)
    }

    /// The ordered non-terminal steps.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// The terminal fate.
    #[must_use]
    pub fn fate(&self) -> Fate {
        self.fate
    }
}
