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
//! A type in this module is the predicate itself, written once. The implementation calls it from a
//! [`debug_assert!`]; the test that carries the `type=test` citation calls it directly. The two
//! citations are then provably about the same predicate, because there is only one.
//!
//! This does not make a citation non-vacuous on its own -- a test can still feed inputs that never
//! reach the interesting case, which is what the `MIN_REACHED` counters in
//! [`fuzz`](super::fuzz) and `cargo-mutants` are for. It rules out the other failure: a test that
//! checks something unrelated to the requirement it names.
//!
//! # What belongs here
//!
//! Only requirements that are **local predicates** -- decidable from values available at one point
//! in the program. Most are not. RFC 4787 REQ-1 relates two mappings made at different times,
//! REQ-6 relates a packet to a timer, REQ-11 is a statement about the answers to the other
//! requirements. Those can only be properties, and they stay in [`fuzz`](super::fuzz).
//!
//! Where a requirement can be encoded more strongly, it should be, and then it does not belong
//! here either. `development/code/avoid-global-reasoning.md` ranks the options: make the illegal
//! state unrepresentable, then encode it in a type, and only then check it at runtime. A
//! constraint on a `const` is a `const` assertion and fails the build, which beats any of this.
//!
//! # Naming
//!
//! `rfc<number>::<the specification's own identifier>`. The section number is deliberately absent:
//! it is already in the `//=` URL of the citation, and a second copy is a second thing to keep
//! correct. Where a specification numbers nothing -- RFC 4884 has no `REQ-` clauses, its unit is a
//! sentence in a section -- name the contract for what it says rather than inventing an index the
//! specification does not have.

use crate::common::NatFlowStatus;

/// A requirement did not hold.
///
/// Carries the values that broke it, because a `debug_assert!` that says only `false` costs more
/// time than it saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Violation {
    /// The requirement, as `rfc4787#section-9 REQ-12`.
    pub(crate) requirement: &'static str,
    /// What went wrong, in the specification's own terms.
    pub(crate) detail: &'static str,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.requirement, self.detail)
    }
}

/// [RFC 4787](https://www.rfc-editor.org/rfc/rfc4787), NAT behavioural requirements for UDP.
pub(crate) mod rfc4787 {
    use super::{NatFlowStatus, Violation};

    /// > REQ-12: Receipt of any sort of ICMP message MUST NOT terminate the NAT mapping.
    ///
    /// Terminating a mapping is what releases the public address and port it holds, so this is
    /// read as: an ICMP packet may not move a live flow into a state that ends it. A flow already
    /// in a terminal state stays there -- the requirement forbids ICMP *causing* termination, not
    /// the flow having been terminated by something else.
    ///
    /// RFC 5382 REQ-10 is the same sentence for TCP, and is kept by this same check: masquerade's
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

    impl Req12 {
        /// State the requirement over one ICMP-driven transition.
        pub(crate) const fn new(before: NatFlowStatus, after: NatFlowStatus) -> Self {
            Self { before, after }
        }

        /// Whether an ICMP packet has ended a mapping that was live.
        pub(crate) const fn check(self) -> Result<(), Violation> {
            if Self::terminal(self.after) && !Self::terminal(self.before) {
                return Err(Violation {
                    requirement: "rfc4787#section-9 REQ-12 / rfc5382#section-8 REQ-10",
                    detail: "an ICMP packet moved a live flow into a terminal state",
                });
            }
            Ok(())
        }

        /// The states in which the mapping is over and the tuple is released.
        const fn terminal(status: NatFlowStatus) -> bool {
            matches!(status, NatFlowStatus::Closed | NatFlowStatus::Reset)
        }
    }
}

#[cfg(test)]
mod test {
    use super::rfc4787::Req12;
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
}
