// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::common::NatFlowStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) requirement: &'static str,
    pub(crate) detail: &'static str,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.requirement, self.detail)
    }
}

pub(crate) mod rfc4787 {
    use super::{NatFlowStatus, Violation};

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Req12 {
        before: NatFlowStatus,
        after: NatFlowStatus,
    }

    impl Req12 {
        pub(crate) const fn new(before: NatFlowStatus, after: NatFlowStatus) -> Self {
            Self { before, after }
        }

        pub(crate) const fn check(self) -> Result<(), Violation> {
            if Self::terminal(self.after) && !Self::terminal(self.before) {
                return Err(Violation {
                    requirement: "rfc4787#section-9 REQ-12 / rfc5382#section-8 REQ-10",
                    detail: "an ICMP packet moved a live flow into a terminal state",
                });
            }
            Ok(())
        }

        const fn terminal(status: NatFlowStatus) -> bool {
            matches!(status, NatFlowStatus::Closed | NatFlowStatus::Reset)
        }
    }
}

#[cfg(test)]
mod test {
    use super::rfc4787::Req12;
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
