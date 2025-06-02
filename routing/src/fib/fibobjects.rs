// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that contains definitions and methods for fib objects

use crate::interfaces::interface::IfIndex;
use crate::rib::encapsulation::Encapsulation;
use std::net::IpAddr;

#[allow(dead_code)]
#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
/// An `EgressObject` indicates the interface over which a packet
/// has to be sent and, optionally, a next-hop ip address. If
/// no address is provided, ND/ARP is required.
pub struct EgressObject {
    pub(crate) ifindex: Option<IfIndex>,
    pub(crate) address: Option<IpAddr>,
}

impl EgressObject {
    #[must_use]
    pub fn new(ifindex: Option<IfIndex>, address: Option<IpAddr>) -> Self {
        Self { ifindex, address }
    }
    #[cfg(test)]
    pub fn with_ifindex(ifindex: IfIndex, address: Option<IpAddr>) -> Self {
        Self {
            ifindex: Some(ifindex),
            address,
        }
    }
    #[must_use]
    pub fn ifindex(&self) -> &Option<IfIndex> {
        &self.ifindex
    }
    #[must_use]
    pub fn address(&self) -> &Option<IpAddr> {
        &self.address
    }
    /// merge two egress objects appearing in a next-hop or a Fib entry. This is used as part
    /// of the resolution to ensure correctness
    pub fn merge(&mut self, other: &Self) {
        if self.ifindex.is_none() {
            self.ifindex = other.ifindex;
        }
        if other.address.is_some() {
            self.address = other.address;
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
/// A `FibGroup` is a set of [`FibEntry`]s that may be used to forward an IP packet.
/// A single entry may be used for each packet. In spite of this being a set, we implement it with a
/// vector for the following reasons:
///   * a `FibGroup` may contain typically a small number of `FibEntry`s
///   * a vector allows us to mutably iterate over the elements easily as compared to `BtreeSet` or a `HashSet`.
///   * we do not merge duplicates. This does not pose any functional issue and may be exploited
///     to weigh paths on the forwarding path.
pub struct FibGroup {
    pub(crate) entries: Vec<FibEntry>,
}

#[allow(dead_code)]
impl FibGroup {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    #[must_use]
    pub fn with_entry(entry: FibEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }
    pub fn add(&mut self, entry: FibEntry) {
        self.entries.push(entry);
    }
    pub fn iter(&self) -> impl Iterator<Item = &FibEntry> {
        self.entries.iter()
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut FibEntry> {
        self.entries.iter_mut()
    }
    pub fn extend(&mut self, other: &Self) {
        self.entries.extend_from_slice(&other.entries);
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// merge multiple fib entry groups
    pub fn append(&mut self, other: &mut Self) {
        self.entries.append(&mut other.entries);
    }
    #[must_use]
    pub fn entries(&self) -> &Vec<FibEntry> {
        &self.entries
    }
}

#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
/// A Fib entry is made of a sequence of [`PktInstruction`] s to be executed for an IP packet
/// in order to forward it.
pub struct FibEntry {
    pub(crate) instructions: Vec<PktInstruction>,
}

#[allow(dead_code)]
impl FibEntry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
        }
    }
    #[must_use]
    pub fn with_inst(instruction: PktInstruction) -> Self {
        Self {
            instructions: vec![instruction],
        }
    }
    pub fn add(&mut self, instruction: PktInstruction) {
        self.instructions.push(instruction);
    }
    pub fn extend_from_slice(&mut self, instructions: &[PktInstruction]) {
        self.instructions.extend_from_slice(instructions);
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.instructions.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &PktInstruction> {
        self.instructions.iter()
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PktInstruction> {
        self.instructions.iter_mut()
    }
    pub(crate) fn squash(&mut self) {
        if self.instructions.len() == 1 {
            return;
        }
        let mut out: Vec<PktInstruction> = Vec::new();
        let mut merged = EgressObject::default();
        for inst in &self.instructions {
            if let PktInstruction::Egress(e) = &inst {
                merged.merge(e);
            } else {
                out.push(inst.clone());
            }
        }
        if merged.ifindex.is_some() {
            out.push(PktInstruction::Egress(merged));
        }
        self.instructions = out;
    }
}

#[derive(Clone, Default, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[allow(unused)]
/// A `PktInstruction` represents an action to be performed by the packet processor on a packet.
pub enum PktInstruction {
    #[default]
    Drop, /* drop the packet */
    Local(IfIndex),       /* packet is destined to gw */
    Encap(Encapsulation), /* encapsulate the packet */
    Egress(EgressObject), /* send the packet over interface to some ip */
    Nat,
}
