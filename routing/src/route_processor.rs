// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements route processing

use net::eth::mac::Mac;
use std::net::IpAddr;
use tracing::warn;

use crate::adjacency::AdjacencyTable;
use crate::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::interface::{IfIndex, IfTable};
use crate::nexthop::{FwAction, Nhop};
use crate::rmac::{RmacStore, Vtep};

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
/// An EgressObject contains the information needed to send a packet
/// over an Ethernet interface.
pub struct EgressObject {
    pub(crate) ifindex: IfIndex,
    pub(crate) address: Option<IpAddr>, /* none means ARP/ND is needed */
    pub(crate) smac: Option<Mac>,
    pub(crate) dmac: Option<Mac>,
}

#[allow(dead_code)]
impl EgressObject {
    fn new(ifindex: IfIndex, address: Option<IpAddr>) -> Self {
        Self {
            ifindex,
            address,
            ..Default::default()
        }
    }
}

/* ============================== FIbEntry Group ========================================= */
#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
/// A `FibEntryGroup` is a set of [`FibEntries`] that may be used to forward an IP packet.
/// A single entry may be used for each packet. In spite of this being a set, we implement it with a
/// vector for the following reasons:
///   * a FibGroup may contain typically a small number of FibEntries
///   * a vector allows us to mutably iterate over the elements easily as compared to BtreeSet or HashSet.
///   * we do not merge duplicates. This does not pose any functional issue and may be exploited
///     to weigh paths on the forwarding path.
pub struct FibEntryGroup {
    entries: Vec<FibEntry>,
}

#[allow(dead_code)]
impl FibEntryGroup {
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

#[derive(Debug, Default, Clone)]
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
}

/* ============================ Packet instruction ======================================== */

#[derive(Clone, Default, Debug)]
#[allow(unused)]
/// A `PktInstruction` represents an action to be performed by the packet processor on a packet.
pub enum PktInstruction {
    #[default]
    Drop, /* drop the packet */
    Encap(Encapsulation), /* encapsulate the packet */
    Xmit(EgressObject),   /* send the packet over interface to some ip */
    Nat,                  //    Push(Header),
                          //    Modify(PktModify),
}

/* ============================ Nhop processing ======================================== */
#[allow(dead_code)]
impl Nhop {
    /// Internal: build a single [`PktInstruction`] for a given next-hop
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
            return Some(PktInstruction::Xmit(egress));
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
        program: &mut FibEntryGroup,
        mut routine: FibEntry,
        prev: Option<IpAddr>,
    ) {
        if let Some(inst) = self.as_pkt_instruction(prev) {
            routine.add(inst);
        }
        if let Ok(resolvers) = self.resolvers.read() {
            if resolvers.is_empty() {
                program.add(routine);
            } else {
                for resolver in resolvers.iter() {
                    let routine = routine.clone();
                    resolver.__as_fib_entry_group(program, routine, self.key.address);
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
    pub(crate) fn as_fib_entry_group(&self) -> FibEntryGroup {
        let mut out = FibEntryGroup::new();
        self.__as_fib_entry_group(&mut out, FibEntry::new(), None);
        out
    }
}

/* ============================== Resolution =========================================== */

#[allow(dead_code)]
impl EgressObject {
    fn resolve_source(&mut self, iftable: &IfTable) {
        if let Some(interface) = iftable.get_interface(self.ifindex) {
            self.smac = interface.get_mac().copied();
        }
    }
    fn resolve_destination(&mut self, atable: &AdjacencyTable) {
        if let Some(address) = self.address {
            self.dmac = atable
                .get_adjacency(address, self.ifindex)
                .map(|adj| adj.get_mac());
        }
    }
    fn resolve(&mut self, iftable: &IfTable, atable: &AdjacencyTable) {
        self.resolve_source(iftable);
        self.resolve_destination(atable);
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
    fn resolve(
        &mut self,
        rstore: &RmacStore,
        vtep: &Vtep,
        iftable: &IfTable,
        atable: &AdjacencyTable,
    ) {
        match self {
            PktInstruction::Drop => {}
            PktInstruction::Xmit(egress) => egress.resolve(iftable, atable),
            PktInstruction::Encap(encapsulation) => match encapsulation {
                Encapsulation::Vxlan(vxlan) => vxlan.resolve(rstore, vtep),
                Encapsulation::Mpls(_label) => {}
            },
            PktInstruction::Nat => {}
        }
    }
}

#[allow(dead_code)]
impl FibEntry {
    pub fn resolve(
        &mut self,
        rstore: &RmacStore,
        vtep: &Vtep,
        iftable: &IfTable,
        atable: &AdjacencyTable,
    ) {
        // FIXME signature
        for inst in self.instructions.iter_mut() {
            inst.resolve(rstore, vtep, iftable, atable);
        }
    }
}

#[allow(dead_code)]
impl FibEntryGroup {
    pub fn resolve(
        &mut self,
        rstore: &RmacStore,
        vtep: &Vtep,
        iftable: &IfTable,
        atable: &AdjacencyTable,
    ) {
        // FIXME signature
        for entry in self.entries.iter_mut() {
            entry.resolve(rstore, vtep, iftable, atable);
        }
    }
}
