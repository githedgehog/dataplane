// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Specification requirements, stated as things the program can execute.
//!
//! A duvet citation is a quoted sentence in a comment. It records that somebody read the
//! requirement; it cannot record that the code still does what the sentence says, and it cannot
//! record that the test cited `type=test` checks the same thing as the code cited
//! `type=implementation`. Those two citations are independent readings of one sentence, and a
//! refactor can separate them without either comment changing.
//!
//! A [`Requirement`] here is the predicate itself, written once. The implementation calls it from a
//! [`debug_assert!`]; the test that carries the `type=test` citation calls it directly. The two
//! citations are then provably about the same predicate, because there is only one.
//!
//! This does not make a citation non-vacuous on its own -- a test can still feed inputs that never
//! reach the interesting case, which is what the `MIN_REACHED` counters in [`fuzz`](super::fuzz)
//! and `cargo-mutants` are for. It rules out the other failure: a test that checks something
//! unrelated to the requirement it names.
//!
//! # The citation is checked at compile time
//!
//! [`Requirement::SPEC`] and [`Requirement::ID`] are not decoration. duvet emits one TOML file per
//! specification section under `.duvet/requirements/`, so the tree already holds a machine-readable
//! copy of every requirement we track. Each contract asserts in a `const` block that the section it
//! names really does state the requirement it claims. A contract citing a requirement its
//! specification does not contain -- or citing a specification since dropped from
//! `.duvet/config.toml` -- fails the build rather than the review.
//!
//! `include_str!` is recorded in rustc's dependency information, so re-extracting a specification
//! rebuilds these checks rather than leaving them stale.
//!
//! # What belongs here
//!
//! Only requirements that are **local predicates** -- decidable from values available at one point
//! in the program. Most are not. RFC 4787 REQ-1 relates two mappings made at different times,
//! REQ-6 relates a packet to a timer, REQ-11 is a statement about the answers to the other
//! requirements. Those can only be properties, and they stay in [`fuzz`](super::fuzz).
//!
//! Where a requirement can be encoded more strongly it should be, and then it does not belong here
//! either. `development/code/avoid-global-reasoning.md` ranks the options: make the illegal state
//! unrepresentable, then encode it in a type, and only then check it at runtime. A constraint on a
//! `const` -- RFC 4787 REQ-5 bounds timers that are `const`s -- is a `const` assertion and fails
//! the build, which beats anything this trait can do. Such requirements are deliberately not
//! [`Requirement`]s: a trait method cannot be `const fn` on stable.
//!
//! # Naming
//!
//! `rfc<number>::<the specification's own identifier>`. The section number is deliberately absent
//! from the module path: it is already in [`Requirement::SPEC`], and a second copy is a second
//! thing to keep correct. Where a specification numbers nothing -- RFC 4884 has no `REQ-` clauses,
//! its unit is a sentence in a section -- name the contract for what it says rather than inventing
//! an index the specification does not have.

use crate::common::NatFlowStatus;

/// A specification requirement that can be decided from values available at one point.
///
/// Implementors are constructed where the requirement applies, carrying exactly the values it is
/// about, and asked whether it holds.
pub(crate) trait Requirement {
    /// What a violation carries. One type per requirement, because the evidence differs and
    /// `development/code/error-handling.md` asks for a dedicated error type rather than a string.
    type Error: core::error::Error;

    /// The citation target, in the same form as duvet's `//=` marker.
    const SPEC: &'static str;

    /// The specification's own identifier, such as `REQ-12`.
    const ID: &'static str;

    /// Whether the requirement holds for these values.
    ///
    /// # Errors
    ///
    /// Returns the evidence that it does not.
    fn check(&self) -> Result<(), Self::Error>;
}

/// Whether `haystack` contains `needle`, in a `const` context.
///
/// Exists because the cross-check against duvet's extracted requirements has to run before the
/// program does, and `str::contains` is not `const` on stable.
const fn contains(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    if n.is_empty() {
        return true;
    }
    if h.len() < n.len() {
        return false;
    }
    let mut i = 0;
    while i <= h.len() - n.len() {
        let mut j = 0;
        while j < n.len() && h[i + j] == n[j] {
            j += 1;
        }
        if j == n.len() {
            return true;
        }
        i += 1;
    }
    false
}

/// [RFC 4787](https://www.rfc-editor.org/rfc/rfc4787), NAT behavioural requirements for UDP.
pub(crate) mod rfc4787 {
    use super::{NatFlowStatus, Requirement, contains};

    /// What duvet extracted from the section [`Req12`] cites.
    const SECTION_9: &str =
        include_str!("../../../.duvet/requirements/www.rfc-editor.org/rfc/rfc4787/section-9.toml");

    /// > REQ-12: Receipt of any sort of ICMP message MUST NOT terminate the NAT mapping.
    ///
    /// Terminating a mapping is what releases the public address and port it holds, so this reads
    /// as: an ICMP packet may not move a live flow into a state that ends it. A flow already in a
    /// terminal state stays there -- the requirement forbids ICMP *causing* termination, not the
    /// flow having been terminated by something else.
    ///
    /// RFC 5382 REQ-10 is the same sentence for TCP and is kept by this same check: masquerade's
    /// ICMP transition runs for every ICMP packet regardless of the protocol of the flow it
    /// belongs to. RFC 5382 states the stronger obligation -- the mapping *or the TCP connection*
    /// -- but the second half is about not injecting a reset, which this stage never does.
    ///
    /// A `rfc5382::Req10` alias was written and deleted: nothing called it, and an uncalled
    /// contract is the decoration this module exists to replace.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Req12 {
        before: NatFlowStatus,
        after: NatFlowStatus,
    }

    /// An ICMP packet ended a mapping that was live.
    ///
    /// Carries both states because "the requirement broke" is not actionable and
    /// `Established -> Closed` is.
    #[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
    #[error("an ICMP packet moved a live flow from {before:?} to {after:?}")]
    pub(crate) struct Req12Violated {
        before: NatFlowStatus,
        after: NatFlowStatus,
    }

    impl Req12 {
        /// State the requirement over one ICMP-driven transition.
        pub(crate) const fn new(before: NatFlowStatus, after: NatFlowStatus) -> Self {
            Self { before, after }
        }

        /// The states in which the mapping is over and the tuple is released.
        const fn terminal(status: NatFlowStatus) -> bool {
            matches!(status, NatFlowStatus::Closed | NatFlowStatus::Reset)
        }
    }

    impl Requirement for Req12 {
        type Error = Req12Violated;
        const SPEC: &'static str = "https://www.rfc-editor.org/rfc/rfc4787#section-9";
        const ID: &'static str = "REQ-12";

        fn check(&self) -> Result<(), Self::Error> {
            if Self::terminal(self.after) && !Self::terminal(self.before) {
                return Err(Req12Violated {
                    before: self.before,
                    after: self.after,
                });
            }
            Ok(())
        }
    }

    // The specification we cite must state the requirement we claim. This is what `SPEC` and `ID`
    // are `const` for: a citation that has gone stale stops the build.
    const _: () = assert!(
        contains(SECTION_9, <Req12 as Requirement>::ID),
        "rfc4787#section-9 does not state REQ-12"
    );
}

#[cfg(test)]
mod test {
    use super::rfc4787::Req12;
    use super::{Requirement, contains};
    use crate::common::NatFlowStatus;

    /// Every status the machine can be in, terminal ones last.
    const STATUSES: [NatFlowStatus; 10] = [
        NatFlowStatus::OneWay,
        NatFlowStatus::TwoWay,
        NatFlowStatus::Established,
        NatFlowStatus::CClosing,
        NatFlowStatus::SClosing,
        NatFlowStatus::CHalfClose,
        NatFlowStatus::SHalfClose,
        NatFlowStatus::LastAck,
        NatFlowStatus::Reset,
        NatFlowStatus::Closed,
    ];

    /// The compile-time cross-check is only worth having if it can fail.
    ///
    /// A `const` assertion cannot demonstrate its own negative case -- getting it wrong stops the
    /// build rather than reporting -- so the search it relies on is exercised here instead.
    #[test]
    fn the_specification_search_can_fail() {
        assert!(contains("REQ-12:  Receipt of any", "REQ-12"));
        assert!(!contains("REQ-12:  Receipt of any", "REQ-42"));
        assert!(!contains("REQ-1", "REQ-12"), "a prefix is not a match");
        assert!(
            contains("anything", ""),
            "the empty needle is always present"
        );
    }

    /// The contract is only worth calling if it can fail, and only correct if it fails on exactly
    /// the transitions the requirement forbids.
    ///
    /// This tests the *statement*, not the implementation that satisfies it. Without it a contract
    /// that returned `Ok` unconditionally would make every caller pass, including the
    /// `debug_assert!` and the state machine test, which is the failure mode this whole pattern
    /// exists to prevent.
    #[test]
    fn the_contract_rejects_exactly_the_forbidden_transitions() {
        let terminal = |s| matches!(s, NatFlowStatus::Closed | NatFlowStatus::Reset);
        let mut rejected = 0;
        for before in STATUSES {
            for after in STATUSES {
                let forbidden = terminal(after) && !terminal(before);
                assert_eq!(
                    Req12::new(before, after).check().is_err(),
                    forbidden,
                    "{before:?} -> {after:?}"
                );
                rejected += usize::from(forbidden);
            }
        }
        assert_eq!(
            rejected, 16,
            "8 live statuses times 2 terminal ones must be the whole forbidden set"
        );
    }

    /// A violation names both states, because that is what makes it actionable.
    #[test]
    fn a_violation_reports_the_transition_that_caused_it() {
        let err = Req12::new(NatFlowStatus::Established, NatFlowStatus::Closed)
            .check()
            .expect_err("an established flow moved to closed must violate REQ-12");
        assert_eq!(
            err.to_string(),
            "an ICMP packet moved a live flow from Established to Closed"
        );
    }
}
