// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Rib to fib route processor

#[allow(unused)]
use tracing::{debug, warn};

use crate::evpn::RmacStore;
use crate::rib::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::rib::nexthop::{FwAction, Nhop};
use crate::rib::vrf::RouteOrigin;

use crate::fib::fibobjects::{EgressObject, FibEntry, FibGroup, PktInstruction};

impl Nhop {
    //////////////////////////////////////////////////////////////////////
    /// Build the vector of packet instructions for a next-hop.
    /// This process is independent of the resolvers for a next-hop.
    /// Hence it does not depend on the routing table.
    /// It does depend on the rmacs, though.
    //////////////////////////////////////////////////////////////////////
    fn build_pkt_instructions(&self, rstore: &RmacStore) -> Vec<PktInstruction> {
        let mut instructions = Vec::with_capacity(2);
        if self.key.origin == RouteOrigin::Local {
            match self.key.ifindex {
                Some(if_index) => instructions.push(PktInstruction::Local(if_index)),
                None => {
                    warn!("packet is locally destined but has no target interface index: dropping");
                    instructions.push(PktInstruction::Drop);
                }
            };
            return instructions;
        }
        if self.key.fwaction == FwAction::Drop {
            instructions.push(PktInstruction::Drop);
            return instructions;
        }
        if let Some(encap) = self.key.encap {
            let mut inst_encap = encap.clone();
            match inst_encap {
                Encapsulation::Vxlan(ref mut vxlan) => vxlan.resolve(rstore),
                Encapsulation::Mpls(_) => {}
            }
            instructions.push(PktInstruction::Encap(inst_encap));
            let egress =
                EgressObject::new(self.key.ifindex, self.key.address, self.key.ifname.clone());
            instructions.push(PktInstruction::Egress(egress));
            return instructions;
        }
        if self.key.ifindex.is_some() {
            let egress =
                EgressObject::new(self.key.ifindex, self.key.address, self.key.ifname.clone());
            instructions.push(PktInstruction::Egress(egress));
        }
        instructions
    }

    //////////////////////////////////////////////////////////////////////
    /// Given a next-hop, build its packet instructions and resolve them
    /// In this implementation, the next-hop owns the packet instructions
    /// So, they are not shared and have to be resolved per next-hop.
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn build_nhop_instructions(&self, rstore: &RmacStore) {
        // build new instruction vector for the next-hop
        let new_instructions = self.build_pkt_instructions(rstore);

        // replace instruction vector
        self.instructions.replace(new_instructions);
    }

    //////////////////////////////////////////////////////////////////////
    /// Recursive helper to build [`FibGroup`] for a next-hop. We accumulate
    /// a next-hop's packet instructions with those of its resolvers.
    //////////////////////////////////////////////////////////////////////
    fn build_nhop_fibgroup_rec(&self, fibgroup: &mut FibGroup, mut entry: FibEntry) {
        // add the instructions for a next-hop to the entry
        let instructions = self.instructions.borrow().clone();
        entry.extend_from_slice(&instructions);

        // check the instructions of the resolving next-hops
        let Ok(resolvers) = self.resolvers.try_borrow() else {
            warn!("Warning, try-borrow failed!!!");
            return;
        };
        if resolvers.is_empty() {
            entry.squash(); /* squash entry before committing it to the group */
            fibgroup.add(entry); /* add fib entry to group */
        } else {
            for resolver in resolvers.iter() {
                resolver.build_nhop_fibgroup_rec(fibgroup, entry.clone());
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Build a [`FibGroup`] for an [`Nhop`]
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn build_nhop_fibgroup(&self) -> FibGroup {
        let mut out = FibGroup::new();
        self.build_nhop_fibgroup_rec(&mut out, FibEntry::new());
        out
    }

    //////////////////////////////////////////////////////////////////////
    /// Determine instructions for a next-hop and build its fibgroup
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn set_fibgroup(&self, rstore: &RmacStore) -> bool {
        // determine nhop pkt instructions. This is independent of the routing table
        self.build_nhop_instructions(rstore);
        // build the fibgroup for a next-hop. This requires the nhop to be resolved
        // and its resolvers too, and that these have packet instructions up to date
        let fibgroup = self.build_nhop_fibgroup();
        let changed = fibgroup != *self.fibgroup.borrow();
        if changed {
            // FIXME(fredi): we need a way of enabling these logs at runtime
            //debug!("Fibgroup for nhop {self}\nchanged!");
            //debug!("\nold:\n{}", self.fibgroup.borrow());
            //debug!("\nnew:\n{}", fibgroup);
            self.fibgroup.replace(fibgroup);
        } else {
            //debug!("Fibgroup for nhop {self} did NOT change");
        }
        changed
    }
}

impl VxlanEncapsulation {
    /// Resolve a Vxlan encapsulation object. The local vtep information is not used
    /// in this process. We only resolve the destination mac.
    pub(crate) fn resolve(&mut self, rstore: &RmacStore) {
        self.dmac = rstore.get_rmac(self.vni, self.remote).map(|e| e.mac);
        if self.dmac.is_none() {
            warn!(
                "Router mac for vni {} and remote {} is not known!",
                self.vni.as_u32(),
                self.remote
            );
        }
    }
}
