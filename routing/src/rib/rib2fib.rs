// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Rib to fib route processor

#[allow(unused)]
use tracing::{debug, trace, warn};

use crate::evpn::RmacStore;
use crate::fib::fibobjects::{EgressObject, FibEntry, FibGroup, PktInstruction};
use crate::rib::encapsulation::{
    Encapsulation, ResolvedEncapsulation, ResolvedVxlan, VxlanEncapsulation,
};
use crate::rib::nexthop::{FwAction, Nhop, Visited};
use crate::rib::vrf::RouteOrigin;

use std::rc::Weak;

impl Nhop {
    //////////////////////////////////////////////////////////////////////
    /// Build the vector of packet instructions for a next-hop.
    /// This process is independent of the resolvers for a next-hop.
    /// Hence it does not depend on the routing table.
    /// It does depend on the rmacs, though.
    //////////////////////////////////////////////////////////////////////
    #[allow(clippy::single_match_else)]
    #[must_use]
    fn build_pkt_instructions(&self, rstore: &RmacStore) -> Vec<PktInstruction> {
        // mark as valid for the time being
        self.invalid.set(false);

        let mut instructions = Vec::with_capacity(2);

        // local route
        if self.key.origin == RouteOrigin::Local {
            match self.key.ifindex {
                Some(if_index) => instructions.push(PktInstruction::Local(if_index)),
                None => {
                    self.invalid.set(true);
                    warn!("Unknown ifindex for local next-hop. Will set action drop");
                    instructions.push(PktInstruction::Drop);
                }
            }
            return instructions;
        }

        // an explicit drop
        if self.key.fwaction == FwAction::Drop {
            instructions.push(PktInstruction::Drop);
            return instructions;
        }

        // a nexthop with encapsulation info. Will add action encap and egress object
        if let Some(encap) = self.key.encap {
            let resolved = match encap {
                Encapsulation::Vxlan(vxlan) => {
                    vxlan.resolve(rstore).map(ResolvedEncapsulation::Vxlan)
                }
                // set to Some for tests, actually unsupported
                Encapsulation::Mpls(label) => Some(ResolvedEncapsulation::Mpls(label)),
            };
            if let Some(resolved) = resolved {
                instructions.push(PktInstruction::Encap(resolved));
                let egress = EgressObject::new(self.key.ifindex, self.key.address);
                instructions.push(PktInstruction::Egress(egress));
            } else {
                // resolution of encap instructions failed. Keep the route with action drop and mark the nhop as invalid
                self.invalid.set(true);
                instructions = vec![PktInstruction::Drop];
                warn!("Nhop {self} became invalid");
            }
            return instructions;
        }
        // next-hop is not local, drop or encap. So it must represent either:
        //   a) another device not directly connected (must resolve it)
        //   b) another device, directly connected, already resolved to an interface
        //   c) another device, directly connected but not resolved to an interface
        // An egress object encodes these 3 possible cases.
        //
        // In the case of a next-hop with an address but no ifindex, we must resolve that
        // address with an ifindex. We emit an egress instruction for its address: it is the
        // address to resolve at layer 2 unless a next-hop deeper in the resolution chain provides
        // one of its own, which `EgressObject::merge()` takes care of by keeping the first ifindex
        // and the last address of the chain. Without this, the address of a recursive next-hop would
        // never reach the fib and the egress stage would resolve the destination of the packet instead
        // which is only correct if it is directly connected.
        if self.key.ifindex.is_some() || self.key.address.is_some() {
            let egress = EgressObject::new(self.key.ifindex, self.key.address);
            instructions.push(PktInstruction::Egress(egress));
        }
        instructions
    }

    //////////////////////////////////////////////////////////////////////
    /// Given a next-hop, build its packet instructions and attach them to it
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
    ///
    /// `path` holds the next-hops between the root of the walk and this one. A next-hop that turns
    /// up on its own resolution path closes a routing loop: following it would recurse until the
    /// stack ran out, so we stop there and contribute nothing. If that leaves no usable path at
    /// all, `build_nhop_fibgroup` injects a drop, which is what a packet caught in a routing loop
    /// should meet anyway.
    ///
    /// This makes the walk safe on any graph rather than only on the acyclic ones that
    /// `Nhop::resolves_with` lets `lazy_resolve` build. The two guards are deliberately
    /// independent: nothing in the types ties this recursion to the one that used to be its only
    /// protection, and a caller wiring resolvers by another route would lose it silently.
    //////////////////////////////////////////////////////////////////////
    fn build_nhop_fibgroup_rec(
        &self,
        fibgroup: &mut FibGroup,
        entry: FibEntry,
        path: &mut Visited,
    ) {
        if path.contains(&self.id()) {
            warn!("Resolution loop at next-hop {self}: will not use this path");
            return;
        }
        path.push(self.id());
        self.build_nhop_fibgroup_visit(fibgroup, entry, path);
        path.pop();
    }

    //////////////////////////////////////////////////////////////////////
    /// The body of [`Nhop::build_nhop_fibgroup_rec`], for a next-hop known not to be on its own
    /// resolution path already. Split out so that the push and the pop of `path` sit next to each
    /// other and no early return here can leave the path unbalanced.
    //////////////////////////////////////////////////////////////////////
    fn build_nhop_fibgroup_visit(
        &self,
        fibgroup: &mut FibGroup,
        mut entry: FibEntry,
        path: &mut Visited,
    ) {
        // add the instructions for a next-hop to the entry
        let instructions = self.instructions.borrow().clone();
        entry.extend_from_slice(&instructions);

        // check the instructions of the resolving next-hops, if any
        let Ok(resolvers) = self.resolvers.try_borrow() else {
            warn!("Warning, try-borrow failed!!!");
            return;
        };

        if resolvers.is_empty() {
            if self.must_be_resolved() {
                // Nhop has no resolver and must be resolved. This may only happen if:
                //  1) we forgot to resolve it (BUG) or
                //  2) we attempted resolution but stopped because a loop was detected
                warn!("Next-hop {self} is unresolved: will not use it");
                return;
            }

            // squash entry: this collapses egress instructions into a single one
            entry.squash();

            // validate entry and commit to the fibgroup if it is valid. If invalid,
            // we ignore it (instead of replacing with a drop), because the group may
            // have other valid ones and we don't want to drop if another path is viable.
            // Only if the fibgroup is empty, will we inject a drop.
            if entry.is_valid() {
                fibgroup.add(entry);
            }
        } else {
            for resolver in resolvers.iter().filter_map(Weak::upgrade) {
                resolver.build_nhop_fibgroup_rec(fibgroup, entry.clone(), path);
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Build a [`FibGroup`] for an [`Nhop`]. If the next-hop cannot be
    /// resolved and the fibgroup would be empty, artificially inject
    /// an entry with action DROP so that packets hitting the route
    /// don't get misrouted.
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn build_nhop_fibgroup(&self) -> FibGroup {
        let mut fibgroup = FibGroup::new();
        self.build_nhop_fibgroup_rec(&mut fibgroup, FibEntry::new(), &mut Visited::new());
        if fibgroup.is_empty() {
            warn!("Next-hop {self} has empty fibgroup: will add DROP FibEntry");
            fibgroup.add(FibEntry::drop_fibentry());
        }
        fibgroup
    }

    //////////////////////////////////////////////////////////////////////
    /// Determine instructions for a next-hop and build its `FibGroup`.
    /// Returns true if the `Fibgroup` associated to a next-hop changed.
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn set_fibgroup(&self, rstore: &RmacStore) -> bool {
        // determine nhop pkt instructions. This is independent of the routing table
        self.build_nhop_instructions(rstore);

        // build the fibgroup for a next-hop. This requires the nhop to be resolved
        // and its resolvers too, and that these have packet instructions up to date
        let fibgroup = self.build_nhop_fibgroup();
        let changed = fibgroup != *(self.fibgroup.borrow());
        if changed {
            trace!("Fibgroup for nhop {self}\nchanged. Will replace..");
            trace!("\nold:\n{}", self.fibgroup.borrow());
            trace!("\nnew:\n{}", fibgroup);
            self.fibgroup.replace(fibgroup);
        } else {
            trace!("Fibgroup for nhop {self} did NOT change");
        }
        changed
    }
}

impl VxlanEncapsulation {
    /// Resolve a Vxlan encapsulation object. The local vtep information is not used in this
    /// process; we only resolve the destination mac. A hit yields a [`ResolvedVxlan`] whether the
    /// entry is stale or not.
    ///
    /// This returns the resolved form rather than filling a field in place. `self` is reachable
    /// from a next-hop key that is live in a map, so resolving in place would mutate a stored
    /// key -- something that only a `Copy` at the call site used to prevent.
    pub(crate) fn resolve(&self, rstore: &RmacStore) -> Option<ResolvedVxlan> {
        let Some(entry) = rstore.get_rmac(self.vni, self.remote) else {
            warn!(
                "Router mac for vni {} and remote {} is not known!",
                self.vni.as_u32(),
                self.remote
            );
            return None;
        };
        Some(ResolvedVxlan {
            vni: self.vni,
            remote: self.remote,
            dmac: entry.mac,
        })
    }
}
