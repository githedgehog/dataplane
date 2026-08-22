// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that contains definitions and methods for fib objects

use crate::rib::encapsulation::ResolvedEncapsulation;
use net::interface::InterfaceIndex;
use net::vxlan::Vni;
use std::net::IpAddr;

#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(test, derive(Hash))]
/// An `EgressObject` indicates the interface over which a packet
/// has to be sent and, optionally, a next-hop ip address. If
/// no address is provided, ND/ARP is required.
pub struct EgressObject {
    pub(crate) ifindex: Option<InterfaceIndex>,
    pub(crate) address: Option<IpAddr>,
}

impl EgressObject {
    #[must_use]
    pub fn new(ifindex: Option<InterfaceIndex>, address: Option<IpAddr>) -> Self {
        Self { ifindex, address }
    }
    #[must_use]
    pub fn ifindex(&self) -> &Option<InterfaceIndex> {
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

/// A `FibGroup` is a set of [`FibEntry`]s that may be used to forward an IP packet.
/// A single entry may be used for each packet. In spite of this being a set, we implement it with a
/// vector for the following reasons:
///   * a `FibGroup` may contain typically a small number of `FibEntry`s
///   * a vector allows us to mutably iterate over the elements easily as compared to `BtreeSet` or a `HashSet`.
///   * we do not merge duplicates. This does not pose any functional issue and may be exploited
///     to weigh paths on the forwarding path.
#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FibGroup {
    entries: Vec<FibEntry>,
}

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
    #[must_use]
    pub(crate) fn drop_fibgroup() -> FibGroup {
        FibGroup::with_entry(FibEntry::drop_fibentry())
    }

    /// Add a [`FibEntry`] to a [`FibGroup`]
    pub fn add(&mut self, entry: FibEntry) {
        self.entries.push(entry);
    }
    /// Iterate over the [`FibEntry`]ies within a [`FibGroup`]
    pub fn iter(&self) -> impl Iterator<Item = &FibEntry> {
        self.entries.iter()
    }
    /// Mutably iterate over the [`FibEntry`]ies within a [`FibGroup`]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut FibEntry> {
        self.entries.iter_mut()
    }
    /// Extend a [`FibGroup`] with the  [`FibEntry`]ies of another one
    /// N.B. `extend()` uses `extend_from_slice` creating a copy. This is usually
    /// the required behavior. For consuming (moving) the entries in other
    /// we'd use append.
    pub fn extend(&mut self, other: &Self) {
        self.entries.extend_from_slice(&other.entries);
    }

    /// Tell how many entries a [`FibGroup`] has
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Tell if a [`FibGroup`] is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Provide a reference to the vector of [`FibEntry`]ies in a [`FibGroup`]
    #[must_use]
    pub fn entries(&self) -> &Vec<FibEntry> {
        &self.entries
    }

    /// Provide a mutable reference to the vector of [`FibEntry`]s in a [`FibGroup`]
    #[must_use]
    #[cfg(test)]
    pub(crate) fn entries_mut(&mut self) -> &mut Vec<FibEntry> {
        &mut self.entries
    }
}

#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(test, derive(Hash))]
/// A Fib entry is made of a sequence of [`PktInstruction`] s to be executed for an IP packet
/// in order to forward it.
pub struct FibEntry {
    pub(crate) instructions: Vec<PktInstruction>,
}

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
    #[must_use]
    pub fn drop_fibentry() -> Self {
        Self::with_inst(PktInstruction::Drop)
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

    /// Tell if a `FibEntry` is well-formed to process a packet.
    /// A single instruction entry can only be valid if it is a drop, a local delivery, or
    /// an egress with a known interface index. A multi-instruction one must end with
    /// an egress object and known interface index.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match self.instructions.len() {
            0 => false,
            1 => {
                let inst = &self.instructions[0];
                match inst {
                    PktInstruction::Drop | PktInstruction::Local(_) => true,
                    PktInstruction::Egress(e) => e.ifindex.is_some(),
                    PktInstruction::Encap(_) => false,
                }
            }
            _ => {
                let inst = self.instructions.last().unwrap_or_else(|| unreachable!());
                match inst {
                    PktInstruction::Egress(e) => e.ifindex().is_some(),
                    _ => false,
                }
            }
        }
    }

    /// Compress all of the `Egress` instructions of a `FibEntry` into a single
    /// one, provided that the interface index could be resolved
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
    #[must_use]
    pub fn is_iplocal(&self) -> bool {
        self.instructions.len() == 1 && matches!(self.instructions[0], PktInstruction::Local(_))
    }
    #[must_use]
    pub fn is_vxlan(&self) -> Option<Vni> {
        for inst in &self.instructions {
            if let PktInstruction::Encap(ResolvedEncapsulation::Vxlan(vxlan)) = inst {
                return Some(vxlan.vni);
            }
        }
        None
    }
    #[must_use]
    pub fn is_vxlan_with_vni(&self, vni: Vni) -> bool {
        for inst in &self.instructions {
            if let PktInstruction::Encap(ResolvedEncapsulation::Vxlan(vxlan)) = inst {
                return vxlan.vni == vni;
            }
        }
        false
    }
}

#[derive(Clone, Default, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(test, derive(Hash))]
#[allow(unused)]
/// A `PktInstruction` represents an action to be performed by the packet processor on a packet.
pub enum PktInstruction {
    #[default]
    Drop, /* drop the packet */
    Local(InterfaceIndex),        /* packet is destined to gw */
    Encap(ResolvedEncapsulation), /* encapsulate the packet */
    Egress(EgressObject),         /* send the packet over interface to some ip */
}

#[cfg(test)]
mod squash_properties {
    use super::*;
    use crate::rib::encapsulation::ResolvedVxlan;
    use bolero::{Driver, ValueGenerator};
    use net::eth::mac::Mac;
    use std::net::Ipv4Addr;
    use std::num::NonZero;
    use std::ops::Bound::Included;

    // A small alphabet makes conflicting fields common enough to exercise merge precedence.
    const ADDRESSES: [IpAddr; 3] = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
    ];

    fn index(raw: u8) -> InterfaceIndex {
        InterfaceIndex::new(NonZero::new(u32::from(raw)).unwrap_or_else(|| unreachable!()))
    }

    // Zero encodes `None` without conflating it with generator exhaustion.
    fn choose<T: Clone>(pick: u8, choices: &[T]) -> Option<T> {
        (pick > 0).then(|| choices[usize::from(pick - 1)].clone())
    }

    fn egress<D: Driver>(driver: &mut D) -> Option<EgressObject> {
        let ifindex = driver.gen_u8(Included(&0), Included(&3))?;
        let address = driver.gen_u8(Included(&0), Included(&3))?;
        Some(EgressObject::new(
            choose(ifindex, &[index(1), index(2), index(3)]),
            choose(address, &ADDRESSES),
        ))
    }

    fn instruction<D: Driver>(driver: &mut D) -> Option<PktInstruction> {
        Some(match driver.gen_u8(Included(&0), Included(&3))? {
            // Distinct indices make instruction order observable.
            0 => PktInstruction::Local(index(driver.gen_u8(Included(&1), Included(&3))?)),
            1 => PktInstruction::Drop,
            2 => PktInstruction::Encap(ResolvedEncapsulation::Vxlan(ResolvedVxlan {
                vni: Vni::new_checked(u32::from(driver.gen_u8(Included(&1), Included(&3))?))
                    .unwrap_or_else(|_| unreachable!()),
                remote: ADDRESSES[0],
                dmac: Mac::from([0x02, 0, 0, 0, 0, 1]),
            })),
            _ => PktInstruction::Egress(egress(driver)?),
        })
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub(super) struct Entry;

    impl ValueGenerator for Entry {
        type Output = FibEntry;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<FibEntry> {
            let count = driver.gen_u8(Included(&0), Included(&5))?;
            let mut entry = FibEntry::new();
            for _ in 0..count {
                entry.add(instruction(driver)?);
            }
            Some(entry)
        }
    }

    fn egresses(entry: &FibEntry) -> Vec<&EgressObject> {
        entry
            .iter()
            .filter_map(|inst| match inst {
                PktInstruction::Egress(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    fn others(entry: &FibEntry) -> Vec<&PktInstruction> {
        entry
            .iter()
            .filter(|inst| !matches!(inst, PktInstruction::Egress(_)))
            .collect()
    }

    #[test]
    fn squash_preserves_the_other_instructions_in_order() {
        bolero::check!()
            .with_generator(Entry)
            .cloned()
            .for_each(|entry: FibEntry| {
                let before: Vec<PktInstruction> = others(&entry).into_iter().cloned().collect();
                let mut squashed = entry.clone();
                squashed.squash();
                if entry.len() == 1 {
                    assert_eq!(squashed, entry);
                    return;
                }
                let after: Vec<PktInstruction> = others(&squashed).into_iter().cloned().collect();
                assert_eq!(after, before, "for {entry:?}");
            });
    }

    #[test]
    fn squash_leaves_at_most_one_egress_and_puts_it_last() {
        bolero::check!()
            .with_generator(Entry)
            .cloned()
            .for_each(|entry: FibEntry| {
                if entry.len() == 1 {
                    return;
                }
                let mut squashed = entry.clone();
                squashed.squash();

                assert!(egresses(&squashed).len() <= 1, "for {entry:?}");
                if let Some(position) = squashed
                    .iter()
                    .position(|inst| matches!(inst, PktInstruction::Egress(_)))
                {
                    assert_eq!(position, squashed.len() - 1, "for {entry:?}");
                }
            });
    }

    /// Merge precedence is checked directly from the inputs, without calling `merge` in the oracle.
    #[test]
    fn squash_merges_first_interface_last_address_first_name() {
        bolero::check!()
            .with_generator(Entry)
            .cloned()
            .for_each(|entry: FibEntry| {
                if entry.len() == 1 {
                    return;
                }
                let inputs = egresses(&entry);
                let ifindex = inputs.iter().find_map(|e| *e.ifindex());
                let address = inputs.iter().rev().find_map(|e| *e.address());

                let mut squashed = entry.clone();
                squashed.squash();

                match egresses(&squashed).first() {
                    Some(merged) => {
                        assert_eq!(*merged.ifindex(), ifindex, "interface, for {entry:?}");
                        assert_eq!(*merged.address(), address, "address, for {entry:?}");
                    }
                    // An egress without an interface is unusable and removed.
                    None => assert!(ifindex.is_none(), "for {entry:?}"),
                }
            });
    }

    #[test]
    fn squash_is_idempotent() {
        bolero::check!()
            .with_generator(Entry)
            .cloned()
            .for_each(|entry: FibEntry| {
                let mut once = entry.clone();
                once.squash();
                let mut twice = once.clone();
                twice.squash();
                assert_eq!(twice, once, "for {entry:?}");
            });
    }
}

/// The two questions the forwarding path asks a `FibEntry` about itself.
///
/// Split from `squash_properties` because they are about classification rather than about merging,
/// but they draw entries from the same generator: an entry with no instruction, several, or a
/// repeated one is exactly where a predicate written for the common shape goes wrong.
#[cfg(test)]
mod classification_properties {
    use super::squash_properties::Entry;
    use super::*;

    /// An entry is "IP local" when delivering to this box is the whole of what it says.
    ///
    /// The `&&` is load-bearing in both directions and the two halves fail differently. Dropping
    /// the count admits an entry that is local *and* something else -- delivered locally and
    /// forwarded, a duplicate. Dropping the match admits any single-instruction entry, including
    /// `Drop`, which would deliver a discarded packet to the control plane.
    #[test]
    fn an_entry_is_ip_local_exactly_when_delivering_locally_is_all_it_does() {
        bolero::check!()
            .with_generator(Entry)
            .cloned()
            .for_each(|entry: FibEntry| {
                let locals = entry
                    .iter()
                    .filter(|inst| matches!(inst, PktInstruction::Local(_)))
                    .count();
                assert_eq!(
                    entry.is_iplocal(),
                    locals == 1 && entry.iter().count() == 1,
                    "for {entry:?}"
                );
            });
    }

    /// Asking whether an entry encapsulates into a given VNI agrees with asking which VNI it uses.
    ///
    /// Stated against `is_vxlan` rather than against the instruction list, because the pair are two
    /// readings of the same fact and the interesting failure is them disagreeing: `is_vxlan` picks
    /// the first VXLAN encapsulation, and a predicate that scanned for *any* matching one would
    /// answer yes about a VNI the packet will not be sent to.
    #[test]
    fn asking_about_one_vni_agrees_with_asking_which_vni() {
        bolero::check!()
            .with_generator(Entry)
            .cloned()
            .for_each(|entry: FibEntry| {
                for raw in 1..=4u32 {
                    let vni = Vni::new_checked(raw).unwrap_or_else(|_| unreachable!());
                    assert_eq!(
                        entry.is_vxlan_with_vni(vni),
                        entry.is_vxlan() == Some(vni),
                        "vni {raw} for {entry:?}"
                    );
                }
            });
    }
}
