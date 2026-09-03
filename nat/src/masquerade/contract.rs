// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::common::NatFlowStatus;

pub(crate) trait Requirement {
    type Error: core::error::Error;

    const SPEC: &'static str;

    const ID: &'static str;

    fn check(&self) -> Result<(), Self::Error>;
}

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

pub(crate) mod rfc4787 {
    use super::{NatFlowStatus, Requirement, contains};

    const SECTION_9: &str =
        include_str!("../../../.duvet/requirements/www.rfc-editor.org/rfc/rfc4787/section-9.toml");

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Req12 {
        before: NatFlowStatus,
        after: NatFlowStatus,
    }

    #[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
    #[error("an ICMP packet moved a live flow from {before:?} to {after:?}")]
    pub(crate) struct Req12Violated {
        before: NatFlowStatus,
        after: NatFlowStatus,
    }

    impl Req12 {
        pub(crate) const fn new(before: NatFlowStatus, after: NatFlowStatus) -> Self {
            Self { before, after }
        }

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
