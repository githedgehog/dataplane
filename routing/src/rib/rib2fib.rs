// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Rib to fib route processor

#[allow(unused)]
use tracing::{debug, trace, warn};

use crate::fib::fibobjects::{EgressObject, FibEntry, FibGroup, PktInstruction};
use crate::rib::nexthop::{FwAction, Nhop, NhopKey};
use crate::rib::vrf::RouteOrigin;

use std::rc::Weak;

impl NhopKey {
    //////////////////////////////////////////////////////////////////////
    /// Build the vector of packet instructions for a next-hop key.
    //////////////////////////////////////////////////////////////////////
    #[allow(clippy::single_match_else)]
    pub(crate) fn as_pkt_instructions(&self) -> Vec<PktInstruction> {
        let mut instructions = Vec::with_capacity(2);

        // an explicit drop
        if self.fwaction == FwAction::Drop {
            instructions.push(PktInstruction::Drop);
            return instructions;
        }

        // local route
        if self.origin == RouteOrigin::Local {
            match self.ifindex {
                Some(if_index) => instructions.push(PktInstruction::Local(if_index)),
                None => {
                    warn!("Unknown ifindex for local next-hop. Will set action drop");
                    instructions.push(PktInstruction::Drop);
                }
            }
            return instructions;
        }

        // a nexthop with encapsulation info. Will add action encap and egress object
        if let Some(encap) = self.encap {
            instructions.push(PktInstruction::Encap(encap));
            let egress = EgressObject::new(self.ifindex, self.address);
            instructions.push(PktInstruction::Egress(egress));
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
        if self.ifindex.is_some() || self.address.is_some() {
            let egress = EgressObject::new(self.ifindex, self.address);
            instructions.push(PktInstruction::Egress(egress));
            return instructions;
        }

        // consistency
        debug_assert!(!self.is_valid());

        // invalid next-hop drops
        instructions.push(PktInstruction::Drop);
        instructions
    }
}

impl Nhop {
    //////////////////////////////////////////////////////////////////////
    /// Recursive helper to build [`FibGroup`] for a next-hop. We accumulate
    /// a next-hop's packet instructions with those of its resolvers. So,
    /// unlike the next-hop packet instructions, the outcome of this DOES
    /// depend on the next-hop resolvers. If a next-hop resolves to an invalid
    /// next-hop, it will end up having at least a Drop packet instruction.
    //////////////////////////////////////////////////////////////////////
    fn build_nhop_fibgroup_rec(&self, fibgroup: &mut FibGroup, mut entry: FibEntry) {
        // If we hit an invalid next-hop, clear the fib entry and return
        // the entry will not be part of the group
        if !self.is_valid() {
            entry.instructions.clear();
            return;
        }

        // add the instructions for a next-hop to the entry
        entry.extend_from_slice(self.instructions());

        // check the instructions of the resolving next-hops, if any
        let Some(resolvers) = self.get_resolvers() else {
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
                resolver.build_nhop_fibgroup_rec(fibgroup, entry.clone());
            }
        }
    }

    /////////////////////////////////////////////////////////////////////////////
    /// Build a [`FibGroup`] for a [`Nhop`]. Invalid next-hops or next-hops that
    /// could not be resolved, or next-hops that resolve to invalid next-hops,
    /// do not produce fib entries (not even drop ones) and are instead ignored.
    /// This is to allow other fibentries (paths) in the fib group to get all
    /// the traffic, if any. If the fib group would be empty, though, inject
    /// a fib entry with action DROP since dropping is better than mis-routing.
    ////////////////////////////////////////////////////////////////////////////
    pub(crate) fn build_nhop_fibgroup(&self) -> FibGroup {
        let mut fibgroup = FibGroup::new();
        self.build_nhop_fibgroup_rec(&mut fibgroup, FibEntry::new());
        if fibgroup.is_empty() {
            warn!("Next-hop {self} has empty fibgroup: will add DROP FibEntry");
            fibgroup.add(FibEntry::drop_fibentry());
        }
        fibgroup
    }

    //////////////////////////////////////////////////////////////////////
    /// Build a `FibGroup` from the next-hop instructions and that of its resolvers.
    /// This requires: 1) next-hops to have instructions 2) next-hops to be resolved.
    /// Returns true if the `Fibgroup` associated to a next-hop changed.
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn set_fibgroup(&self) -> bool {
        // build the fibgroup for a next-hop. This requires the nhop to be resolved
        // and its resolvers too, and that these have packet instructions, which
        // all next-hops should have
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

#[cfg(test)]
mod tests_nhop_pkt_instructions {
    use super::*;
    use crate::rib::encapsulation::{Encapsulation, VxlanEncapsulation};
    use bolero::{Driver, ValueGenerator};
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::InterfaceIndex;
    use net::vxlan::Vni;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ops::Bound::{Excluded, Included};

    const ORIGINS: [RouteOrigin; 7] = [
        RouteOrigin::Local,
        RouteOrigin::Connected,
        RouteOrigin::Static,
        RouteOrigin::Ospf,
        RouteOrigin::Isis,
        RouteOrigin::Bgp,
        RouteOrigin::Other,
    ];

    const ADDRS: [IpAddr; 2] = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    ];

    const MACS: [Mac; 2] = [
        Mac([0x02, 0xca, 0xfe, 0x0, 0x0, 0x01]),
        Mac([0x02, 0xba, 0xbe, 0x0, 0x0, 0x02]),
    ];

    /// Generate arbitrary next-hop keys, even if invalid
    /// (e.g. a forwarding key without address nor ifindex).
    #[derive(Debug, Clone, Copy, Default)]
    struct Keys;

    impl ValueGenerator for Keys {
        type Output = NhopKey;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<NhopKey> {
            let origin = ORIGINS[driver.gen_usize(Included(&0), Excluded(&ORIGINS.len()))?];
            let address = if driver.produce::<bool>()? {
                Some(ADDRS[driver.gen_usize(Included(&0), Excluded(&ADDRS.len()))?])
            } else {
                None
            };
            let ifindex = if driver.produce::<bool>()? {
                InterfaceIndex::try_new(u32::from(driver.gen_u8(Included(&1), Included(&3))?)).ok()
            } else {
                None
            };
            let mac = MACS[driver.gen_usize(Included(&0), Excluded(&MACS.len()))?];
            let encap = match driver.gen_u8(Included(&0), Included(&2))? {
                0 => None,
                1 => Some(Encapsulation::Mpls(u32::from(
                    driver.gen_u8(Included(&1), Included(&3))?,
                ))),
                _ => Some(Encapsulation::Vxlan(VxlanEncapsulation::new(
                    Vni::new_checked(u32::from(driver.gen_u8(Included(&1), Included(&3))?)).ok()?,
                    ADDRS[0],
                    SourceMac::try_from(mac).expect("Bad mac"),
                ))),
            };
            let fwaction = if driver.produce::<bool>()? {
                FwAction::Drop
            } else {
                FwAction::Forward
            };
            Some(NhopKey::new(0, origin, address, ifindex, encap, fwaction))
        }
    }

    // generate nhop keys and test the given property
    fn check(property: fn(&NhopKey, &[PktInstruction])) {
        bolero::check!()
            .with_generator(Keys)
            .cloned()
            .for_each(|key: NhopKey| property(&key, &key.as_pkt_instructions()));
    }

    #[test]
    fn a_local_key_delivers_locally_or_drops() {
        check(|key, instructions| {
            let local = instructions
                .iter()
                .any(|i| matches!(i, PktInstruction::Local(_)));
            // a drop wins over the origin
            let forwards = key.fwaction == FwAction::Forward;
            assert_eq!(
                local,
                forwards && key.origin == RouteOrigin::Local && key.ifindex.is_some(),
                "for {key:?}"
            );
            if forwards && key.origin == RouteOrigin::Local {
                let expected = key
                    .ifindex
                    .map_or(PktInstruction::Drop, PktInstruction::Local);
                assert_eq!(instructions, [expected], "for {key:?}");
            }
        });
    }

    #[test]
    fn a_drop_is_the_only_instruction() {
        check(|key, instructions| {
            let drops = instructions.contains(&PktInstruction::Drop);
            // a drop wins over the origin
            let should_drop = !key.is_valid() || key.fwaction == FwAction::Drop;
            assert_eq!(drops, should_drop, "for {key:?}");
            if drops {
                assert_eq!(instructions, [PktInstruction::Drop], "for {key:?}");
            }
        });
    }

    #[test]
    fn an_encapsulation_comes_first_and_is_the_keys() {
        check(|key, instructions| {
            let encaps: Vec<_> = instructions
                .iter()
                .filter_map(|i| match i {
                    PktInstruction::Encap(e) => Some(*e),
                    _ => None,
                })
                .collect();
            let forwards = key.origin != RouteOrigin::Local && key.fwaction == FwAction::Forward;
            match key.encap {
                Some(encap) if forwards => {
                    assert_eq!(encaps, [encap], "for {key:?}");
                    assert_eq!(instructions[0], PktInstruction::Encap(encap), "for {key:?}");
                }
                _ => assert!(encaps.is_empty(), "for {key:?}"),
            }
        });
    }

    #[test]
    fn egress_is_last_and_has_the_key_ifindex_and_address() {
        check(|key, instructions| {
            let egresses: Vec<_> = instructions
                .iter()
                .filter(|i| matches!(i, PktInstruction::Egress(_)))
                .collect();
            assert!(egresses.len() <= 1, "for {key:?}");
            if let Some(egress) = egresses.first() {
                let expected = PktInstruction::Egress(EgressObject::new(key.ifindex, key.address));
                assert_eq!(**egress, expected, "for {key:?}");
                assert_eq!(instructions.last(), Some(*egress), "for {key:?}");
            }
        });
    }

    #[test]
    fn invalid_nhop_keys_have_drop_instruction() {
        check(|key, instructions| {
            if key.is_valid() {
                // a valid next-hop always produces some instruction
                assert_ne!(instructions, []);
            } else {
                // an invalid next-hop only produces a drop instruction
                assert_eq!(instructions.len(), 1);
                assert_eq!(instructions[0], PktInstruction::Drop);
            }
        });
    }
}
