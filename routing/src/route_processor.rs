// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements route processing

use std::net::IpAddr;
use tracing::warn;

use crate::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::interface::IfIndex;
use crate::nexthop::{FwAction, Nhop, NhopStore};
use crate::rmac::{RmacStore, Vtep};

#[allow(dead_code)]
#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
/// An EgressObject indicates the interface over which a packet
/// has to be sent and, optionally, a next-hop ip address. If
/// no address is provided, ND/ARP is required.
pub struct EgressObject {
    pub(crate) ifindex: Option<IfIndex>,
    pub(crate) address: Option<IpAddr>,
}

#[allow(dead_code)]
impl EgressObject {
    fn new(ifindex: Option<IfIndex>, address: Option<IpAddr>) -> Self {
        Self { ifindex, address }
    }
    fn with_ifindex(ifindex: IfIndex, address: Option<IpAddr>) -> Self {
        Self {
            ifindex: Some(ifindex),
            address,
        }
    }
    fn empty() -> Self {
        Self::new(None, None)
    }
}

/* ============================== FIbEntry Group ========================================= */
#[allow(dead_code)]
#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
/// A `FibEntryGroup` is a set of [`FibEntries`] that may be used to forward an IP packet.
/// A single entry may be used for each packet. In spite of this being a set, we implement it with a
/// vector for the following reasons:
///   * a FibGroup may contain typically a small number of FibEntries
///   * a vector allows us to mutably iterate over the elements easily as compared to BtreeSet or HashSet.
///   * we do not merge duplicates. This does not pose any functional issue and may be exploited
///     to weigh paths on the forwarding path.
pub struct FibGroup {
    entries: Vec<FibEntry>,
}

#[allow(dead_code)]
impl FibGroup {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
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

    /// merge multiple fib entry groups
    pub fn append(&mut self, other: &mut Self) {
        self.entries.append(&mut other.entries);
    }
}

/* =================================== FIbEntry ========================================= */

#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
/// A Fib entry is made of a sequence of [`PktInstruction`] s to be executed for an IP packet
/// in order to forward it.
pub struct FibEntry {
    instructions: Vec<PktInstruction>,
}

#[allow(dead_code)]
impl FibEntry {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
        }
    }
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
    pub fn len(&self) -> usize {
        self.instructions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &PktInstruction> {
        self.instructions.iter()
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PktInstruction> {
        self.instructions.iter_mut()
    }
    fn squash(&mut self) {
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

/* ============================ Packet instruction ======================================== */

#[derive(Clone, Default, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[allow(unused)]
/// A `PktInstruction` represents an action to be performed by the packet processor on a packet.
pub enum PktInstruction {
    #[default]
    Drop, /* drop the packet */
    Local(IfIndex),       /* packet is destined to gw */
    Encap(Encapsulation), /* encapsulate the packet */
    Egress(EgressObject), /* send the packet over interface to some ip */
    Nat,                  //    Push(Header),
                          //    Modify(PktModify),
}

/* ============================ Nhop processing ======================================== */
#[allow(dead_code)]
impl Nhop {
    /// Build the vector of packet instructions for a next-hop.
    /// This process is independent of the resolvers for a next-hop. Hence it does not
    /// depend on the routing table.
    #[inline]
    fn build_pkt_instructions(&self) -> Vec<PktInstruction> {
        let mut instructions = Vec::with_capacity(2);
        if self.key.fwaction == FwAction::Drop {
            instructions.push(PktInstruction::Drop);
            return instructions;
        }
        if let Some(encap) = self.key.encap {
            instructions.push(PktInstruction::Encap(encap));
            let egress = EgressObject::new(self.key.ifindex, self.key.address);
            instructions.push(PktInstruction::Egress(egress));
            return instructions;
        }
        if self.key.ifindex.is_some() {
            let egress = EgressObject::new(self.key.ifindex, self.key.address);
            instructions.push(PktInstruction::Egress(egress));
            return instructions;
        }
        instructions
    }

    /// Given a next-hop, build its packet instructions and resolve them
    /// In this implementation, the next-hop owns the packet instructions
    /// So, they are not shared and have to be resolved per next-hop.
    fn resolve_instructions(&self, rstore: &RmacStore, vtep: &Vtep) {
        if let Ok(mut instructions) = self.instructions.write() {
            // build the instruction vector. This drops any prior vector
            *instructions = self.build_pkt_instructions();
            // resolve each PktInstruction
            for inst in instructions.iter_mut() {
                inst.resolve(rstore, vtep);
            }
        }
    }

    /// N.B. provides clone: TODO: remove this when RWlock is removed
    fn get_packet_instructions(&self) -> Vec<PktInstruction> {
        if let Ok(instructions) = self.instructions.read() {
            instructions.clone()
        } else {
            panic!("poisoned") // changing this because we'll remove the locking
        }
    }

    /// Recursive helper to build [`FibGroup`] for a next-hop
    fn __as_fib_entry_group_lazy(&self, fibgroup: &mut FibGroup, mut entry: FibEntry) {
        // add the instructions for a next-hop (already completed) to the entry
        let instructions = self.get_packet_instructions();
        entry.extend_from_slice(&instructions);

        // check the instructions of the resolving next-hops
        if let Ok(resolvers) = self.resolvers.read() {
            if resolvers.is_empty() {
                // squash entry before committing it to the group
                entry.squash();
                // add fib entry to group
                fibgroup.add(entry);
            } else {
                for resolver in resolvers.iter() {
                    resolver.__as_fib_entry_group_lazy(fibgroup, entry.clone());
                }
            }
        } else {
            panic!("Poisoned");
        }
    }

    #[allow(unused)]
    pub(crate) fn as_fib_entry_group_lazy(&self) -> FibGroup {
        let mut out = FibGroup::new();
        self.__as_fib_entry_group_lazy(&mut out, FibEntry::new());
        out
    }

    pub(crate) fn refresh_fibgroup(&self, rstore: &RmacStore, vtep: &Vtep) {
        self.resolve_instructions(rstore, vtep);
        if let Ok(mut fibgroup) = self.fibgroup.write() {
            *fibgroup = self.as_fib_entry_group_lazy();
        } else {
            panic!("poisoned");
        }
    }
}

#[allow(dead_code)]
impl NhopStore {
    pub fn resolve_nhop_instructions(&self, rstore: &RmacStore, vtep: &Vtep) {
        for nhop in self.iter() {
            nhop.resolve_instructions(rstore, vtep);
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
impl Nhop {
    /// Internal: build a single [`PktInstruction`] for a given next-hop
    /// This is old. This is when we collect first all the instructions and then
    /// resolve them, which requires resolving many more times than resolving first
    /// and then collectiong
    fn as_pkt_instruction(&self, prev: Option<IpAddr>) -> Option<PktInstruction> {
        if self.key.fwaction == FwAction::Drop {
            return Some(PktInstruction::Drop);
        }
        if let Some(ifindex) = self.key.ifindex {
            let egress = if self.key.address.is_some() {
                EgressObject::with_ifindex(ifindex, self.key.address)
            } else {
                EgressObject::with_ifindex(ifindex, prev)
            };
            return Some(PktInstruction::Egress(egress));
        }
        if let Some(encap) = self.key.encap {
            return Some(PktInstruction::Encap(encap));
        }
        None
    }

    /// Internal: helper for [`as_fib_entry_group`].
    ///
    /// **NOTE**: This function is recursive.
    fn __as_fib_entry_group(
        &self,
        fibgroup: &mut FibGroup,
        mut entry: FibEntry,
        prev: Option<IpAddr>,
    ) {
        if let Some(inst) = self.as_pkt_instruction(prev) {
            entry.add(inst);
        }
        if let Ok(resolvers) = self.resolvers.read() {
            if resolvers.is_empty() {
                fibgroup.add(entry);
            } else {
                for resolver in resolvers.iter() {
                    resolver.__as_fib_entry_group(fibgroup, entry.clone(), self.key.address);
                }
            }
        } else {
            panic!("Poisoned");
        }
    }

    /// Build a [`FibEntryGroup`] for a next-hop, considering its resolvers. That is,
    /// without needing to do any LPM operation.
    /// A [`FibEntryGroup`] contains a set of [`FibEntry`]es, each containing a sequence
    /// of [`PktInstruction`]s.
    pub(crate) fn as_fib_entry_group(&self) -> FibGroup {
        let mut out = FibGroup::new();
        self.__as_fib_entry_group(&mut out, FibEntry::new(), None);
        out
    }
}

/* ============================== Resolution =========================================== */

#[allow(dead_code)]
impl EgressObject {
    /// merge two egress objects appearing in a next-hop or a Fib entry
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
impl VxlanEncapsulation {
    /// Resolve a Vxlan encapsulation object with the local vtep config
    fn resolve_with_vtep(&mut self, vtep: &Vtep) {
        self.local = vtep.get_ip();
        self.smac = vtep.get_mac();
        if self.local.is_none() {
            warn!("Warning, VTEP local ip address is not set");
        }
        if self.smac.is_none() {
            warn!("Warning, VTEP local mac address is not set");
        }
    }
    /// Resolve the dst inner mac of a Vxlan encapsulation object from a
    /// router-mac entry from the [`RmacStore`].
    fn resolve_with_rmac(&mut self, rstore: &RmacStore) {
        self.dmac = rstore.get_rmac(self.vni, self.remote).map(|e| e.mac);
        if self.dmac.is_none() {
            warn!(
                "Router mac for vni {} remote {} is not known!",
                self.vni.as_u32(),
                self.remote
            );
        }
    }

    /// Resolve a Vxlan encapsulation object
    fn resolve(&mut self, rstore: &RmacStore, vtep: &Vtep) {
        self.resolve_with_vtep(vtep);
        self.resolve_with_rmac(rstore);
    }
}

#[allow(dead_code)]
impl PktInstruction {
    /// Resolve a packet instruction, depending on its type
    fn resolve(&mut self, rstore: &RmacStore, vtep: &Vtep) {
        match self {
            PktInstruction::Drop => {}
            PktInstruction::Local(_) => {}
            PktInstruction::Egress(_egress) => {}
            PktInstruction::Encap(encapsulation) => match encapsulation {
                Encapsulation::Vxlan(vxlan) => vxlan.resolve(rstore, vtep),
                Encapsulation::Mpls(_label) => {}
            },
            PktInstruction::Nat => {}
        }
    }
}

#[cfg(test)]
// No longer used. These are for the implementation that builds entries & groups
// first and then resolves them.
#[allow(dead_code)]
impl FibEntry {
    pub fn resolve(&mut self, rstore: &RmacStore, vtep: &Vtep) {
        for inst in self.instructions.iter_mut() {
            inst.resolve(rstore, vtep);
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
impl FibGroup {
    pub fn resolve(&mut self, rstore: &RmacStore, vtep: &Vtep) {
        for entry in self.entries.iter_mut() {
            entry.resolve(rstore, vtep);
        }
    }
}
