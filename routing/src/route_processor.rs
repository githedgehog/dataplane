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
    pub(crate) ifindex: IfIndex,
    pub(crate) address: Option<IpAddr>,
}

#[allow(dead_code)]
impl EgressObject {
    fn new(ifindex: IfIndex, address: Option<IpAddr>) -> Self {
        Self { ifindex, address }
    }
    fn empty() -> Self {
        Self::new(0, None)
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
    pub fn add(&mut self, entry: FibEntry) {
        self.entries.push(entry);
    }
    pub fn iter(&self) -> impl Iterator<Item = &FibEntry> {
        self.entries.iter()
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut FibEntry> {
        self.entries.iter_mut()
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
    /// This is a sanity when adjacent next-hops don't have interface resolution but
    /// instead resolve to interface-only next-hops. Since we want to derive the next-hop
    /// instructions without considering their resolvers (i.e. without considering the
    /// routing table), in this case fib entry will end with two consecutive Egress objects.
    /// If that happens, this method merges the egress instructions into one.
    pub fn squash(&mut self) {
        if self.instructions.len() == 1 {
            return;
        }
        let mut sq: Vec<PktInstruction> = Vec::new();
        let mut it: Vec<PktInstruction> = self.instructions.iter().rev().cloned().collect();
        let mut aggregate = EgressObject::empty();
        while let Some(inst) = it.pop() {
            if let PktInstruction::Egress(egress) = &inst {
                aggregate.merge(egress);
            } else {
                sq.push(inst.clone());
            }
        }
        if aggregate.ifindex != 0 {
            sq.push(PktInstruction::Egress(aggregate));
        }
        self.instructions = sq;
    }
}

/* ============================ Packet instruction ======================================== */

#[derive(Clone, Default, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[allow(unused)]
/// A `PktInstruction` represents an action to be performed by the packet processor on a packet.
pub enum PktInstruction {
    #[default]
    Drop, /* drop the packet */
    Encap(Encapsulation), /* encapsulate the packet */
    Egress(EgressObject), /* send the packet over interface to some ip */
    Nat,                  //    Push(Header),
                          //    Modify(PktModify),
}

/* ============================ Nhop processing ======================================== */
#[allow(dead_code)]
impl Nhop {
    /// Tell if a next-hop resolves directly to an interface (i.e. is adjacency).
    /// In most cases, this should not need to take the lock to read since the
    /// next-hop will have an ifindex.
    fn resolves_via_interface(&self) -> Option<(IpAddr, IfIndex)> {
        if let Some(address) = self.key.address {
            if let Some(ifindex) = self.key.ifindex {
                return Some((address, ifindex)); /* happy path not needing resolvers (FRR) */
            } else if let Ok(resolvers) = self.resolvers.read() {
                if resolvers.len() == 1 {
                    if let Some(ifindex) = resolvers[0].key.ifindex {
                        return Some((address, ifindex));
                    }
                }
            }
        }
        None
    }

    /// Build the vector of packet instructions for a next-hop. This process does not
    /// depend on the routing table, with the exception of adjacent next-hops.
    fn build_pkt_instructions(&self) -> Vec<PktInstruction> {
        let mut instructions = Vec::with_capacity(2);
        if self.key.fwaction == FwAction::Drop {
            instructions.push(PktInstruction::Drop);
            return instructions;
        }
        if let Some(encap) = self.key.encap {
            instructions.push(PktInstruction::Encap(encap));
        }
        if let Some((address, ifindex)) = self.resolves_via_interface() {
            let egress = EgressObject::new(ifindex, Some(address));
            instructions.push(PktInstruction::Egress(egress));
            return instructions;
        } else if let Some(ifindex) = self.key.ifindex {
            let egress = EgressObject::new(ifindex, self.key.address);
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
            instructions.clear(); // not needed
            // build the instruction vector for this next-hop
            *instructions = self.build_pkt_instructions();
            // resolve each PktInstruction of the vector
            for inst in instructions.iter_mut() {
                inst.resolve(rstore, vtep);
            }
        }
    }
}

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
                EgressObject::new(ifindex, self.key.address)
            } else {
                EgressObject::new(ifindex, prev)
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

    /* ======== */

    // unused
    //    fn set_packet_instruction_no_clone(&self, prev: Option<IpAddr>) {
    //        if let Ok(mut instruction) = self.instruction.write() {
    //            *instruction = self.as_pkt_instruction(prev);
    //        }
    //    }

    /*
       /// N.B. provides clone
       fn set_packet_instruction(&self, prev: Option<IpAddr>) -> Option<PktInstruction> {
           if let Ok(mut instruction) = self.instruction.write() {
               *instruction = self.as_pkt_instruction(prev);
               instruction.clone()
           } else {
               None
           }
       }

       /// N.B. provides clone
       fn check_set_instruction(&self, prev: Option<IpAddr>) -> Option<PktInstruction> {
           let mut resolve: bool = false;
           if let Ok(instruction) = self.instruction.read() {
               if instruction.is_none() {
                   resolve = true;
               }
           }
           if resolve {
               self.set_packet_instruction(prev)
           } else {
               self.get_packet_instruction()
           }
       }

       fn __as_fib_entry_group_fast(
           &self,
           fibgroup: &mut FibEntryGroup,
           mut entry: FibEntry,
           prev: Option<IpAddr>,
       ) {
           if let Some(instruction) = self.check_set_instruction(prev) {
               entry.add(instruction);
           }

           if let Ok(resolvers) = self.resolvers.write() {
               if resolvers.is_empty() {
                   fibgroup.add(entry);
               } else {
                   for resolver in resolvers.iter() {
                       resolver.__as_fib_entry_group_fast(fibgroup, entry.clone(), self.key.address);
                   }
               }
           } else {
               panic!("Poisoned");
           }
       }

       pub(crate) fn as_fib_entry_group_fast(&self) -> FibEntryGroup {
           let mut out = FibEntryGroup::new();
           self.__as_fib_entry_group_fast(&mut out, FibEntry::new(), None);
           out
       }
    */
}

impl Nhop {
    /// N.B. provides clone
    fn get_packet_instructions(&self) -> Option<Vec<PktInstruction>> {
        //self.instruction.read().map(|inst| inst.clone()).ok()
        if let Ok(instructions) = self.instructions.read() {
            Some(instructions.clone())
        } else {
            None
        }
    }

    // RO: this is the latest and assumes that the instructions for a next-hop have
    // already been "resolved".
    fn __as_fib_entry_group_lazy(&self, fibgroup: &mut FibGroup, mut entry: FibEntry) {
        // add the instructions for a next-hop (already completed) to the entry
        if let Some(instructions) = self.get_packet_instructions() {
            entry.extend_from_slice(&instructions);
        }
        // check the instructions of the resolving next-hops
        if let Ok(resolvers) = self.resolvers.read() {
            if resolvers.is_empty() {
                // squash the entry before committing it to the group
                entry.squash();
                // create new fib entry
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
}

#[allow(dead_code)]
impl NhopStore {
    /// Derive next-hop instructions. Each next-hop may yield, non-recursively
    /// one or more instructions. The instructions derived may need to be further
    /// completed or resolved with missing pieces of information. This method just
    /// iterates over all next-hops to "resolve" their instructions. Note: this does
    /// the resolution of instructions without considering nhop resolvers.
    pub fn resolve_nhop_instructions(&self, rstore: &RmacStore, vtep: &Vtep) {
        for nhop in self.iter() {
            nhop.resolve_instructions(rstore, vtep);
        }
    }
}

/* ============================== Resolution =========================================== */

#[allow(dead_code)]
impl EgressObject {
    /// merge two egress objects appearing in a next-hop or a Fib entry
    pub fn merge(&mut self, other: &Self) {
        if self.ifindex == 0 {
            self.ifindex = other.ifindex;
        }
        if self.address.is_none() {
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
            PktInstruction::Egress(_egress) => {}
            PktInstruction::Encap(encapsulation) => match encapsulation {
                Encapsulation::Vxlan(vxlan) => vxlan.resolve(rstore, vtep),
                Encapsulation::Mpls(_label) => {}
            },
            PktInstruction::Nat => {}
        }
    }

    /// merge two packet instructions if they are both of xmit (egress) type. If they are not,
    /// this method does nothing.
    pub fn merge(&mut self, other: &Self) {
        if let PktInstruction::Egress(egress) = self {
            if let PktInstruction::Egress(egress_other) = other {
                egress.merge(egress_other);
            }
        }
    }
}

//#[cfg(any())]
// No longer used. These are for the implementation that builds entries & groups
// first and then resolves them.
#[allow(dead_code)]
impl FibEntry {
    pub fn resolve(&mut self, rstore: &RmacStore, vtep: &Vtep) {
        // FIXME signature
        for inst in self.instructions.iter_mut() {
            inst.resolve(rstore, vtep);
        }
    }
}

//#[cfg(any())]
#[allow(dead_code)]
impl FibGroup {
    pub fn resolve(&mut self, rstore: &RmacStore, vtep: &Vtep) {
        // FIXME signature
        for entry in self.entries.iter_mut() {
            entry.resolve(rstore, vtep);
        }
    }
}
