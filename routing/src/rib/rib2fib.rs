// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Rib to fib route processor

use tracing::warn;

use crate::evpn::RmacStore;
use crate::evpn::Vtep;
use crate::rib::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::rib::nexthop::{FwAction, Nhop, NhopStore};
use crate::rib::vrf::RouteOrigin;

use crate::fib::fibobjects::{EgressObject, FibEntry, FibGroup, PktInstruction};

#[cfg(test)]
use std::net::IpAddr;

impl Nhop {
    /// Build the vector of packet instructions for a next-hop.
    /// This process is independent of the resolvers for a next-hop. Hence it does not
    /// depend on the routing table.
    fn build_pkt_instructions(&self) -> Vec<PktInstruction> {
        let mut instructions = Vec::with_capacity(2);
        if self.key.origin == RouteOrigin::Local {
            instructions.push(PktInstruction::Local(self.key.ifindex.unwrap_or(0)));
            return instructions;
        }
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
        //let instructions = self.instructions.borrow_mut();
        // build the instruction vector. This drops any prior vector
        self.instructions.replace(self.build_pkt_instructions());
        // resolve each PktInstruction
        for inst in self.instructions.borrow_mut().iter_mut() {
            inst.resolve(rstore, vtep);
        }
    }

    /// Recursive helper to build [`FibGroup`] for a next-hop
    fn _as_fib_entry_group_lazy(&self, fibgroup: &mut FibGroup, mut entry: FibEntry) {
        // add the instructions for a next-hop (already completed) to the entry
        let instructions = self.instructions.borrow().clone();
        entry.extend_from_slice(&instructions);

        // check the instructions of the resolving next-hops
        if let Ok(resolvers) = self.resolvers.try_borrow() {
            if resolvers.is_empty() {
                entry.squash(); /* squash entry before committing it to the group */
                fibgroup.add(entry); /* add fib entry to group */
            } else {
                for resolver in resolvers.iter() {
                    resolver._as_fib_entry_group_lazy(fibgroup, entry.clone());
                }
            }
        } else {
            warn!("Warning, try-borrow failed!!!");
        }
    }

    pub(crate) fn as_fib_entry_group_lazy(&self) -> FibGroup {
        let mut out = FibGroup::new();
        self._as_fib_entry_group_lazy(&mut out, FibEntry::new());
        out
    }

    // resolve
    pub(crate) fn refresh_fibgroup(&self, rstore: &RmacStore, vtep: &Vtep) {
        self.resolve_instructions(rstore, vtep);
        self.fibgroup.replace(self.as_fib_entry_group_lazy());
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

impl PktInstruction {
    /// Resolve a packet instruction, depending on its type
    fn resolve(&mut self, rstore: &RmacStore, vtep: &Vtep) {
        match self {
            PktInstruction::Drop
            | PktInstruction::Local(_)
            | PktInstruction::Egress(_)
            | PktInstruction::Nat => {}
            PktInstruction::Encap(encapsulation) => match encapsulation {
                Encapsulation::Vxlan(vxlan) => vxlan.resolve(rstore, vtep),
                Encapsulation::Mpls(_label) => {}
            },
        }
    }
}

#[cfg(test)] /* Only testing */
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
        if let Ok(resolvers) = self.resolvers.try_borrow() {
            if resolvers.is_empty() {
                fibgroup.add(entry);
            } else {
                for resolver in resolvers.iter() {
                    resolver.__as_fib_entry_group(fibgroup, entry.clone(), self.key.address);
                }
            }
        } else {
            warn!("Try-borrow failed on resolvers!")
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

#[cfg(test)] /* Only testing */
impl FibEntry {
    pub fn resolve(&mut self, rstore: &RmacStore, vtep: &Vtep) {
        for inst in self.instructions.iter_mut() {
            inst.resolve(rstore, vtep);
        }
    }
}

#[cfg(test)] /* Only testing */
impl FibGroup {
    pub fn resolve(&mut self, rstore: &RmacStore, vtep: &Vtep) {
        for entry in self.entries.iter_mut() {
            entry.resolve(rstore, vtep);
        }
    }
}
