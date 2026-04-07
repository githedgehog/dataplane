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
//! system concern  --  cycles can span multiple tables and no single-
//! table const generic can catch them.

/// Identifier for a table in a multi-table jump chain.
pub type TableId = u32;

/// A non-terminal action step applied to a matched packet.
///
/// Steps are applied in order before the terminal [`Fate`].
/// The ordering is significant  --  steps do not commute in general
/// (e.g., "push VLAN then count bytes" differs from "count then push").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Step {
    // ---- Metadata annotation ----
    //
    // These attach opaque u32 values to the packet.  The ACL system
    // does not interpret them  --  the caller ascribes meaning.
    //
    // Maps to rte_flow metadata actions.  Any type implementing
    // `TryFrom<u32>` can be encoded as a metadata value.

    /// Attach a mark value to the packet.
    ///
    /// Maps to `rte_flow` `MARK` action.  One per packet.
    /// The mark is readable after classification via the matched
    /// rule's action sequence.
    Mark(u32),

    /// Attach a metadata value to the packet.
    ///
    /// Maps to `rte_flow` `META` action.  One per packet.
    /// Semantically identical to `Mark` but uses a different
    /// hardware slot on NICs that distinguish them.
    Meta(u32),

    /// Attach a tagged value to an indexed slot.
    ///
    /// Maps to `rte_flow` `TAG` action.  Multiple slots available
    /// (typically up to 8, NIC-dependent).  The index selects which
    /// slot; the value is the u32 payload.
    Tag {
        /// Slot index (0-based, NIC-dependent maximum).
        index: u8,
        /// The u32 value to store in this slot.
        value: u32,
    },

    /// Set a boolean flag on the packet (no value payload).
    ///
    /// Maps to `rte_flow` `FLAG` action.
    Flag,

    // ---- Observation ----

    /// Increment a counter associated with this rule.
    ///
    /// The counter ID is scoped per cascade tier.  Each tier
    /// (hardware base, software delta, etc.) maintains its own
    /// counter state.  A packet that matches at multiple tiers
    /// increments counters at each tier independently  --  the
    /// counts represent "packets seen at this tier," not "packets
    /// that ultimately matched this rule."
    ///
    /// The observation API (to be developed) reports counters
    /// per-tier.  Backends implement counting differently:
    /// hardware via NIC counter resources, software via atomics.
    /// The compiler ensures counter IDs don't collide across
    /// tiers within a cascade.
    Count(u32),

    // ---- Mutation (packet modification) ----
    // Placeholder variants  --  will grow as we integrate rte_flow
    // SetFlowField, encap/decap, VLAN push/pop, etc.
}

/// The terminal fate of a matched packet.
///
/// Exactly one `Fate` must appear per [`ActionSequence`], as the
/// final operation.  This is enforced structurally  --  `Fate` is a
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
    /// Equivalent to `TC_ACT_OK` (tc-flower), `PASSTHRU` (rte_flow),
    /// `ACCEPT` (iptables/nftables).
    Accept,
    /// Evaluate the packet against another table.
    ///
    /// Enables multi-stage classification.  Jump cycle detection
    /// is a compiler-pass concern.
    Jump(TableId),
    /// The matched rule requires the network function to create
    /// per-flow state (e.g., NAT mappings, MAC learning entries).
    ///
    /// The NF inspects the action sequence's metadata steps
    /// (Mark/Meta/Tag) to determine what state to create and how
    /// to populate its own flow cache.  The ACL system does not
    /// prescribe the learning mechanism  --  that is NF-specific.
    ///
    /// In hardware backends this lowers to [`Trap`](Fate::Trap)
    /// (punt to software), since hardware cannot create flow state.
    Learn,
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
/// let permit = ActionSequence::just(Fate::Accept);
///
/// // Drop with counter
/// let deny = ActionSequence::new(vec![Step::Count(1)], Fate::Drop);
///
/// // Mark then forward
/// let mark_and_pass = ActionSequence::new(
///     vec![Step::Mark(42)],
///     Fate::Accept,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionSequence {
    /// Ordered non-terminal steps.
    steps: Vec<Step>, // AGENT: I'm wondering about making this an ArrayVec<Step, 16> or something.
    /// Terminal fate.
    fate: Fate,
}

impl ActionSequence {
    /// Create a new action sequence with steps and a fate.
    #[must_use]
    pub fn new(steps: Vec<Step>, fate: Fate) -> Self {
        Self { steps, fate }
    }

    /// Create an action sequence with no steps  --  just a fate.
    #[must_use]
    pub fn just(fate: Fate) -> Self {
        Self {
            steps: Vec::new(),
            fate,
        }
    }

    /// Shorthand for `Accept` with no steps (the common "permit" case).
    #[must_use]
    pub fn accept() -> Self {
        Self::just(Fate::Accept)
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

    /// Shorthand for `Learn` with no steps.
    ///
    /// Typically combined with metadata steps so the NF knows
    /// what to learn: e.g.,
    /// `ActionSequence::new(vec![Step::Meta(dst_vpcd)], Fate::Learn)`.
    #[must_use]
    pub fn learn() -> Self {
        Self::just(Fate::Learn)
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

    // ---- Metadata accessors ----
    //
    // Convenience methods for extracting metadata values set by action
    // steps.  Each returns the value from the first matching step in
    // the sequence (if any).  `None` means "no such step present"  -- 
    // `Some(0)` is a legitimate value.

    /// The mark value, if a [`Step::Mark`] is present.
    ///
    /// Returns the value from the first `Mark` step.  In `rte_flow`
    /// this maps to `mbuf->hash.fdir.hi` (one per packet).
    #[must_use]
    pub fn mark(&self) -> Option<u32> {
        self.steps.iter().find_map(|s| match s {
            Step::Mark(v) => Some(*v),
            _ => None,
        })
    }

    /// The metadata value, if a [`Step::Meta`] is present.
    ///
    /// Returns the value from the first `Meta` step.  In `rte_flow`
    /// this maps to the dynamic metadata field (one per packet).
    #[must_use]
    pub fn meta(&self) -> Option<u32> {
        self.steps.iter().find_map(|s| match s {
            Step::Meta(v) => Some(*v),
            _ => None,
        })
    }

    /// The tag value at the given index, if a [`Step::Tag`] with
    /// that index is present.
    ///
    /// Returns the value from the first `Tag` step matching `index`.
    /// In `rte_flow` tags are pipeline-internal (NIC-side only,
    /// not delivered to software).
    #[must_use]
    pub fn tag(&self, index: u8) -> Option<u32> {
        self.steps.iter().find_map(|s| match s {
            Step::Tag { index: i, value } if *i == index => Some(*value),
            _ => None,
        })
    }

    /// Whether a [`Step::Flag`] is present in the sequence.
    ///
    /// In `rte_flow` this sets `RTE_MBUF_F_RX_FDIR` on the mbuf.
    #[must_use]
    pub fn flag(&self) -> bool {
        self.steps.iter().any(|s| matches!(s, Step::Flag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_accessor() {
        let seq = ActionSequence::new(vec![Step::Mark(42)], Fate::Accept);
        assert_eq!(seq.mark(), Some(42));
    }

    #[test]
    fn mark_zero_is_valid() {
        let seq = ActionSequence::new(vec![Step::Mark(0)], Fate::Accept);
        assert_eq!(seq.mark(), Some(0));
    }

    #[test]
    fn mark_absent() {
        let seq = ActionSequence::just(Fate::Drop);
        assert_eq!(seq.mark(), None);
    }

    #[test]
    fn meta_accessor() {
        let seq = ActionSequence::new(vec![Step::Meta(7)], Fate::Accept);
        assert_eq!(seq.meta(), Some(7));
    }

    #[test]
    fn tag_accessor() {
        let seq = ActionSequence::new(
            vec![
                Step::Tag { index: 0, value: 100 },
                Step::Tag { index: 3, value: 999 },
            ],
            Fate::Accept,
        );
        assert_eq!(seq.tag(0), Some(100));
        assert_eq!(seq.tag(3), Some(999));
        assert_eq!(seq.tag(1), None);
    }

    #[test]
    fn flag_accessor() {
        let with_flag = ActionSequence::new(vec![Step::Flag], Fate::Accept);
        assert!(with_flag.flag());

        let without = ActionSequence::just(Fate::Accept);
        assert!(!without.flag());
    }

    #[test]
    fn first_mark_wins() {
        let seq = ActionSequence::new(
            vec![Step::Mark(1), Step::Mark(2)],
            Fate::Accept,
        );
        assert_eq!(seq.mark(), Some(1));
    }

    #[test]
    fn mixed_steps() {
        let seq = ActionSequence::new(
            vec![
                Step::Count(0),
                Step::Mark(0xDEAD),
                Step::Meta(0xBEEF),
                Step::Tag { index: 2, value: 42 },
                Step::Flag,
            ],
            Fate::Accept,
        );
        assert_eq!(seq.mark(), Some(0xDEAD));
        assert_eq!(seq.meta(), Some(0xBEEF));
        assert_eq!(seq.tag(2), Some(42));
        assert!(seq.flag());
    }
}
