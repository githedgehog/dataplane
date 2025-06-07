// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct NatPool {
    ips: BTreeSet<IpAddr>,
    allocated: NatAllocations,
}

#[derive(Debug, Clone)]
struct NatAllocations {}
