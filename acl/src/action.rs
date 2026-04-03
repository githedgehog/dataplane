// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/// Action to take when a packet matches an ACL rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Allow the packet through.
    Permit,
    /// Drop the packet.
    Deny,
}
