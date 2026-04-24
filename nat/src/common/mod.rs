// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NatAction {
    DstNat,
    SrcNat,
}
impl Display for NatAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatAction::DstNat => write!(f, "dnat"),
            NatAction::SrcNat => write!(f, "snat"),
        }
    }
}
