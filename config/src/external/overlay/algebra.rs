// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configurations built by folding operations over a blank one.
//!
//! The [design note](../../../../../development/code/config-algebra-testing.md) argues the case at
//! length; the short version is that generating configuration *values* spends a fuzzer's budget on
//! the validator's rejection paths, and teaching a generator to avoid them means keeping a second
//! copy of the validator's rules. Drawing an **operation sequence** instead makes preconditions
//! unrepresentable rather than checked, so every configuration this module produces is valid by
//! construction and the generator never learns a validation rule.
//!
//! # What is and is not a shadow model
//!
//! [`Draft`] is a small description of a configuration, and an [`Overlay`] is built from it. That
//! is not the shadow model the design note warns against: a shadow model *predicts* what the code
//! under test will produce and is compared against it, so it drifts. This is the **source** the
//! configuration is built from, and nothing compares it to anything. What it buys is a place to
//! express removal, which the configuration types themselves have no vocabulary for -- `VpcTable`
//! and `VpcPeeringTable` can only be added to, which is faithful to a declarative config that
//! arrives whole from k8s and useless for saying "and then the operator deleted it".
//!
//! # The vocabulary so far
//!
//! Vpcs, peerings, and exposes that either forward or masquerade. Port forwarding, static NAT and
//! peering ACLs are not yet drawn. A partially modelled algebra gives partial coverage on purpose:
//! what grows is this list, rather than a collection of single-purpose generators.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::ops::Bound::Included;

use bolero::{Driver, ValueGenerator};
use lpm::prefix::{IpPrefix, Ipv4Prefix, Prefix};

use crate::ConfigError;
use crate::external::overlay::Overlay;
use crate::external::overlay::vpc::{Vpc, VpcTable};
use crate::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};

/// A stable name for a vpc, which outlives the vpc itself.
///
/// Handles are allocated by whoever draws the sequence rather than by [`Op::apply`], and that is
/// what makes commutation meaningful: two `AddVpc`s that allocated their handles on application
/// would produce different configurations when swapped, purely because the counter advanced in a
/// different order, and would have to be called non-commuting for a reason that has nothing to do
/// with the configuration.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct VpcHandle(pub u8);

/// A stable name for a peering. As [`VpcHandle`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct PeeringHandle(pub u8);

/// Which manifest of a peering an operation is about.
///
/// A peering is symmetric in the configuration model -- `get_peering_manifests` hands back
/// whichever side matches the vpc asking -- so left and right name positions rather than roles.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Side {
    Left,
    Right,
}

impl Side {
    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Side::Left => Side::Right,
            Side::Right => Side::Left,
        }
    }

    fn index(self) -> usize {
        match self {
            Side::Left => 0,
            Side::Right => 1,
        }
    }
}

/// What an expose asks to have done to the traffic it carries.
///
/// Only the two the algebra can currently draw. `Static` and `PortForwarding` exist in the
/// configuration model and are the next entries.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Flavour {
    /// No translation: the private prefix is also the public one.
    Forward,
    /// Stateful source NAT from the private prefix into the public one.
    Masquerade,
}

/// The most exposes one side of one peering may carry.
///
/// Four rather than a larger number because each expose costs a distinct address block and the
/// interesting cases -- a manifest holding more than one, a removal that is not the last -- are all
/// reachable at two.
pub const MAX_EXPOSES: u8 = 4;

/// The most vpcs one drawn sequence builds.
///
/// A cap and not just a bias, because `AddVpc` is where every draw that finds nothing to work on
/// ends up: uncapped, a sequence spent most of its operations creating vpcs and had one or two
/// peerings between a dozen of them, which is the least interesting configuration it could have
/// built. Six leaves fifteen possible peerings, which is more than a sequence can draw.
pub const MAX_VPCS: u8 = 6;

/// Address blocks reserved per peering: [`MAX_EXPOSES`] for each of the two sides.
const SLOTS_PER_PEERING: u32 = 2 * MAX_EXPOSES as u32;

impl VpcHandle {
    fn name(self) -> String {
        format!("VPC-{:03}", self.0)
    }

    // Five characters, which is what `VpcId::try_from` requires.
    fn id(self) -> String {
        format!("V{:04}", self.0)
    }

    fn vni(self) -> u32 {
        1000 + u32::from(self.0)
    }
}

impl PeeringHandle {
    fn name(self) -> String {
        format!("PEERING-{:03}", self.0)
    }

    /// The address block index reserved for one expose slot on one side of this peering.
    ///
    /// Every expose in a configuration gets a block of its own, which is what keeps the generator
    /// from having to know any of the overlap rules: a manifest refuses two exposes whose private
    /// prefixes overlap, and a vpc refuses two routes to *different* peers whose destinations
    /// overlap, and both are satisfied by construction if no two blocks are ever equal.
    fn block(self, side: Side, slot: u8) -> u32 {
        u32::from(self.0) * SLOTS_PER_PEERING
            + u32::try_from(side.index()).unwrap_or_else(|_| unreachable!())
                * u32::from(MAX_EXPOSES)
            + u32::from(slot)
    }
}

/// The private prefix of block `index`, a `/24` inside `10.0.0.0/8`.
fn private_prefix(index: u32) -> Prefix {
    prefix_v4(0x0A00_0000 | (index << 8), 24)
}

/// The public prefix of block `index`, a `/24` inside `172.16.0.0/12`.
///
/// A separate range from the private one so that a masquerade expose's two sides cannot collide,
/// and so that a forward expose in one peering cannot collide with a masquerade expose's public
/// side in another.
fn public_prefix(index: u32) -> Prefix {
    prefix_v4(0xAC10_0000 | (index << 8), 24)
}

fn prefix_v4(bits: u32, len: u8) -> Prefix {
    Prefix::from(
        Ipv4Prefix::new(Ipv4Addr::from_bits(bits), len)
            .unwrap_or_else(|_| unreachable!("a well-formed prefix")),
    )
}

/// One expose, named by the slot whose address block it holds.
///
/// The slot rather than the position in the list, because a removal must not move the blocks of
/// the exposes it leaves behind: an expose that changed address when a neighbour was deleted would
/// make every claim about traffic conditional on the deletion history.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExposeSpec {
    slot: u8,
    flavour: Flavour,
}

impl ExposeSpec {
    /// What this expose translates, if anything.
    #[must_use]
    pub fn flavour(self) -> Flavour {
        self.flavour
    }

    /// The private prefix this expose covers, on `side` of `peering`.
    #[must_use]
    pub fn private(self, peering: PeeringHandle, side: Side) -> Prefix {
        private_prefix(peering.block(side, self.slot))
    }

    /// The prefix this expose is reachable at from its peer.
    ///
    /// The same as [`ExposeSpec::private`] for [`Flavour::Forward`], which is what "no translation"
    /// means, and the masquerade pool otherwise.
    #[must_use]
    pub fn public(self, peering: PeeringHandle, side: Side) -> Prefix {
        match self.flavour {
            Flavour::Forward => self.private(peering, side),
            Flavour::Masquerade => public_prefix(peering.block(side, self.slot)),
        }
    }

    fn expose(self, peering: PeeringHandle, side: Side) -> VpcExpose {
        let private = self.private(peering, side);
        match self.flavour {
            Flavour::Forward => VpcExpose::empty().ip(private.into()),
            Flavour::Masquerade => VpcExpose::empty()
                .make_masquerade(None)
                .unwrap_or_else(|_| unreachable!("an empty expose accepts masquerade"))
                .ip(private.into())
                .as_range(self.public(peering, side).into())
                .unwrap_or_else(|_| unreachable!("a masquerade expose accepts a public range")),
        }
    }
}

/// One peering and both its manifests.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeeringSpec {
    left: VpcHandle,
    right: VpcHandle,
    exposes: [Vec<ExposeSpec>; 2],
}

impl PeeringSpec {
    /// The vpc on `side` of this peering.
    #[must_use]
    pub fn vpc(&self, side: Side) -> VpcHandle {
        match side {
            Side::Left => self.left,
            Side::Right => self.right,
        }
    }

    /// The exposes on `side`, in the order the manifest will carry them.
    #[must_use]
    pub fn exposes(&self, side: Side) -> &[ExposeSpec] {
        &self.exposes[side.index()]
    }

    fn exposes_mut(&mut self, side: Side) -> &mut Vec<ExposeSpec> {
        &mut self.exposes[side.index()]
    }

    fn touches(&self, vpc: VpcHandle) -> bool {
        self.left == vpc || self.right == vpc
    }

    fn side_of(&self, vpc: VpcHandle) -> Option<Side> {
        if self.left == vpc {
            Some(Side::Left)
        } else if self.right == vpc {
            Some(Side::Right)
        } else {
            None
        }
    }

    fn has_stateful(&self, side: Side) -> bool {
        self.exposes(side)
            .iter()
            .any(|expose| expose.flavour == Flavour::Masquerade)
    }

    fn manifest(&self, peering: PeeringHandle, side: Side) -> VpcManifest {
        self.exposes(side).iter().fold(
            VpcManifest::new(&self.vpc(side).name()),
            |manifest, spec| manifest.exposing(spec.expose(peering, side)),
        )
    }
}

/// A configuration in progress: what the operations fold over.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Draft {
    vpcs: BTreeSet<VpcHandle>,
    peerings: BTreeMap<PeeringHandle, PeeringSpec>,
}

impl Draft {
    /// The blank configuration, which is the identity the sequences fold over.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The vpcs present, in handle order.
    #[must_use]
    pub fn vpcs(&self) -> impl ExactSizeIterator<Item = VpcHandle> + '_ {
        self.vpcs.iter().copied()
    }

    /// The peerings present, in handle order.
    #[must_use]
    pub fn peerings(&self) -> impl ExactSizeIterator<Item = (PeeringHandle, &PeeringSpec)> {
        self.peerings.iter().map(|(handle, spec)| (*handle, spec))
    }

    /// The peering between `left` and `right`, in either order, if there is one.
    ///
    /// A vpc may peer with another at most once, so there is never more than one.
    #[must_use]
    pub fn peering_between(&self, left: VpcHandle, right: VpcHandle) -> Option<PeeringHandle> {
        self.peerings
            .iter()
            .find(|(_, spec)| spec.touches(left) && spec.touches(right))
            .map(|(handle, _)| *handle)
    }

    /// The connected components of the peering graph, each sorted, the whole sorted.
    ///
    /// Non-interference is a property of components rather than of edges: peerings `A-B` and `B-C`
    /// give `A` no path to `C`, but a configuration change inside `{A, B, C}` can still be observed
    /// from `A`, so the component and not the neighbourhood is the footprint tenant isolation is
    /// stated over. A vpc with no peerings is a component of its own.
    #[must_use]
    pub fn components(&self) -> Vec<Vec<VpcHandle>> {
        let mut unvisited: BTreeSet<VpcHandle> = self.vpcs.clone();
        let mut components = Vec::new();
        while let Some(&seed) = unvisited.iter().next() {
            let mut component = Vec::new();
            let mut frontier = vec![seed];
            unvisited.remove(&seed);
            while let Some(vpc) = frontier.pop() {
                component.push(vpc);
                for spec in self.peerings.values() {
                    let Some(side) = spec.side_of(vpc) else {
                        continue;
                    };
                    let peer = spec.vpc(side.other());
                    if unvisited.remove(&peer) {
                        frontier.push(peer);
                    }
                }
            }
            component.sort_unstable();
            components.push(component);
        }
        components.sort_unstable();
        components
    }

    /// Build the configuration this draft describes.
    ///
    /// # Errors
    ///
    /// Returns whatever assembling the tables returns. A draft reached by applying operations
    /// cannot produce one -- duplicate names, ids and vnis are all excluded by handles being
    /// distinct -- so a caller folding a generated sequence may treat an error as a defect here.
    pub fn overlay(&self) -> Result<Overlay, ConfigError> {
        let mut vpc_table = VpcTable::new();
        for vpc in self.vpcs() {
            vpc_table.add(Vpc::new(&vpc.name(), &vpc.id(), vpc.vni())?)?;
        }

        let mut peerings = VpcPeeringTable::new();
        for (handle, spec) in self.peerings() {
            peerings.add(VpcPeering::with_default_group(
                &handle.name(),
                spec.manifest(handle, Side::Left),
                spec.manifest(handle, Side::Right),
            ))?;
        }

        Ok(Overlay::new(vpc_table, peerings))
    }
}

/// What an operation touches, as a set of handles.
///
/// Commutation is derived from these rather than declared per pair, because it is not a property
/// of a pair: `peer(A, B)` commutes with `add_vpc(C)` and cannot be swapped with `add_vpc(A)` at
/// all. Read and write sets give the answer at any position in a sequence, cost one footprint per
/// operation rather than a table of pairs, and make a precondition an ordinary read of something
/// an earlier operation wrote.
///
/// A vpc handle in a footprint stands for the vpc *and its set of peers*. That is what makes
/// "peering `A` with `B` requires that they are not already peered" a read of `A` and `B` rather
/// than a read of every peering in the configuration.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Footprint {
    vpcs: BTreeSet<VpcHandle>,
    peerings: BTreeSet<PeeringHandle>,
}

impl Footprint {
    fn of(
        vpcs: impl IntoIterator<Item = VpcHandle>,
        peerings: impl IntoIterator<Item = PeeringHandle>,
    ) -> Self {
        Self {
            vpcs: vpcs.into_iter().collect(),
            peerings: peerings.into_iter().collect(),
        }
    }

    /// Whether the two footprints name anything in common.
    #[must_use]
    pub fn intersects(&self, other: &Self) -> bool {
        self.vpcs.intersection(&other.vpcs).next().is_some()
            || self.peerings.intersection(&other.peerings).next().is_some()
    }

    /// Whether this footprint is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vpcs.is_empty() && self.peerings.is_empty()
    }
}

/// One step of a configuration change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    /// Create a vpc with no peerings.
    AddVpc(VpcHandle),
    /// Delete a vpc, and with it every peering that named it.
    RemoveVpc(VpcHandle),
    /// Peer two vpcs, each exposing one forwarded prefix.
    AddPeering {
        handle: PeeringHandle,
        left: VpcHandle,
        right: VpcHandle,
    },
    /// Delete a peering, leaving both vpcs in place.
    RemovePeering(PeeringHandle),
    /// Add an expose to one side of a peering.
    AddExpose {
        peering: PeeringHandle,
        side: Side,
        slot: u8,
        flavour: Flavour,
    },
    /// Delete an expose from one side of a peering, which must not be its last.
    RemoveExpose {
        peering: PeeringHandle,
        side: Side,
        slot: u8,
    },
    /// Change what an expose does to the traffic it carries, leaving its private prefix alone.
    SetFlavour {
        peering: PeeringHandle,
        side: Side,
        slot: u8,
        flavour: Flavour,
    },
}

/// How to put back what an [`Op`] changed.
///
/// An undo log rather than an inverse element, because the reverse of an operation is a function of
/// the operation **and the state it was applied to**: the reverse of `SetFlavour` needs the previous
/// flavour, and the reverse of `RemoveVpc` needs every peering that was removed along with it. There
/// is no `Op` that expresses either, which is the concrete form of "this is not a group".
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Undo {
    RemoveVpc(VpcHandle),
    RestoreVpc {
        handle: VpcHandle,
        peerings: Vec<(PeeringHandle, PeeringSpec)>,
    },
    RemovePeering(PeeringHandle),
    RestorePeering(PeeringHandle, PeeringSpec),
    RemoveExpose {
        peering: PeeringHandle,
        side: Side,
        slot: u8,
    },
    RestoreExpose {
        peering: PeeringHandle,
        side: Side,
        index: usize,
        spec: ExposeSpec,
    },
    SetFlavour {
        peering: PeeringHandle,
        side: Side,
        slot: u8,
        flavour: Flavour,
    },
}

impl Op {
    /// The state this operation needs, which is the same thing as its precondition.
    ///
    /// Takes no draft, unlike [`Op::writes`], because every read set in the vocabulary so far is
    /// determined by the operation's own arguments. That is not a law -- `RemoveVpc`'s *write* set
    /// is state-dependent, and a read set could be -- so add the argument back rather than
    /// contorting an operation to fit.
    #[must_use]
    pub fn reads(&self) -> Footprint {
        match self {
            // Nothing: a fresh handle is nobody else's, and removal reads nothing it does not also
            // write.
            Op::AddVpc(_) | Op::RemoveVpc(_) | Op::RemovePeering(_) => Footprint::default(),
            // Both endpoints, because whether they may be peered is a fact about their peer sets.
            Op::AddPeering { left, right, .. } => Footprint::of([*left, *right], []),
            Op::AddExpose { peering, .. }
            | Op::RemoveExpose { peering, .. }
            | Op::SetFlavour { peering, .. } => Footprint::of([], [*peering]),
        }
    }

    /// Everything outside which this operation leaves alone, which is the frame.
    #[must_use]
    pub fn writes(&self, draft: &Draft) -> Footprint {
        match self {
            Op::AddVpc(handle) => Footprint::of([*handle], []),
            // A deletion's footprint is everything that referred to the deleted thing: the peerings
            // that named it, and the vpcs at the far end of those, whose peer sets shrink.
            Op::RemoveVpc(handle) => {
                let mut vpcs = BTreeSet::from([*handle]);
                let mut peerings = BTreeSet::new();
                for (peering, spec) in draft.peerings() {
                    if spec.touches(*handle) {
                        peerings.insert(peering);
                        vpcs.insert(spec.left);
                        vpcs.insert(spec.right);
                    }
                }
                Footprint { vpcs, peerings }
            }
            Op::AddPeering {
                handle,
                left,
                right,
            } => Footprint::of([*left, *right], [*handle]),
            Op::RemovePeering(handle) => {
                let mut vpcs = BTreeSet::new();
                if let Some(spec) = draft.peerings.get(handle) {
                    vpcs.insert(spec.left);
                    vpcs.insert(spec.right);
                }
                Footprint {
                    vpcs,
                    peerings: BTreeSet::from([*handle]),
                }
            }
            Op::AddExpose { peering, .. }
            | Op::RemoveExpose { peering, .. }
            | Op::SetFlavour { peering, .. } => Footprint::of([], [*peering]),
        }
    }

    /// Whether this operation's preconditions hold in `draft`.
    #[must_use]
    pub fn applicable(&self, draft: &Draft) -> bool {
        let mut trial = draft.clone();
        self.apply(&mut trial).is_some()
    }

    /// Apply this operation, returning how to reverse it.
    ///
    /// Returns `None`, leaving `draft` untouched, if the preconditions do not hold. A sequence from
    /// [`Sequence`] never produces one -- that is what "preconditions are unrepresentable" means
    /// here -- so this is the safety net rather than the mechanism, and
    /// `the_generator_only_draws_applicable_operations` asserts as much.
    pub fn apply(&self, draft: &mut Draft) -> Option<Undo> {
        match *self {
            Op::AddVpc(handle) => {
                if !draft.vpcs.insert(handle) {
                    return None;
                }
                Some(Undo::RemoveVpc(handle))
            }

            Op::RemoveVpc(handle) => remove_vpc(draft, handle),

            Op::AddPeering {
                handle,
                left,
                right,
            } => {
                if left == right
                    || draft.peerings.contains_key(&handle)
                    || !draft.vpcs.contains(&left)
                    || !draft.vpcs.contains(&right)
                    || draft.peering_between(left, right).is_some()
                {
                    return None;
                }
                // One expose per side: a manifest with none is refused, so a peering that could be
                // created empty would be a peering the algebra could not materialise.
                let first = |slot| ExposeSpec {
                    slot,
                    flavour: Flavour::Forward,
                };
                draft.peerings.insert(
                    handle,
                    PeeringSpec {
                        left,
                        right,
                        exposes: [vec![first(0)], vec![first(0)]],
                    },
                );
                Some(Undo::RemovePeering(handle))
            }

            Op::RemovePeering(handle) => {
                let spec = draft.peerings.remove(&handle)?;
                Some(Undo::RestorePeering(handle, spec))
            }

            Op::AddExpose {
                peering,
                side,
                slot,
                flavour,
            } => add_expose(draft, peering, side, slot, flavour),

            Op::RemoveExpose {
                peering,
                side,
                slot,
            } => {
                let spec = draft.peerings.get_mut(&peering)?;
                if spec.exposes(side).len() <= 1 {
                    return None;
                }
                let index = spec.exposes(side).iter().position(|e| e.slot == slot)?;
                let removed = spec.exposes_mut(side).remove(index);
                Some(Undo::RestoreExpose {
                    peering,
                    side,
                    index,
                    spec: removed,
                })
            }

            Op::SetFlavour {
                peering,
                side,
                slot,
                flavour,
            } => set_flavour(draft, peering, side, slot, flavour),
        }
    }
}

/// Delete a vpc and every peering that named it.
fn remove_vpc(draft: &mut Draft, handle: VpcHandle) -> Option<Undo> {
    if !draft.vpcs.remove(&handle) {
        return None;
    }
    let doomed: Vec<PeeringHandle> = draft
        .peerings
        .iter()
        .filter(|(_, spec)| spec.touches(handle))
        .map(|(peering, _)| *peering)
        .collect();
    let peerings = doomed
        .into_iter()
        .map(|peering| {
            let spec = draft
                .peerings
                .remove(&peering)
                .unwrap_or_else(|| unreachable!("just found it"));
            (peering, spec)
        })
        .collect();
    Some(Undo::RestoreVpc { handle, peerings })
}

/// Add an expose in a free slot on one side of a peering.
fn add_expose(
    draft: &mut Draft,
    peering: PeeringHandle,
    side: Side,
    slot: u8,
    flavour: Flavour,
) -> Option<Undo> {
    if slot >= MAX_EXPOSES {
        return None;
    }
    let spec = draft.peerings.get(&peering)?;
    if spec.exposes(side).iter().any(|e| e.slot == slot) {
        return None;
    }
    if flavour == Flavour::Masquerade && spec.has_stateful(side.other()) {
        return None;
    }
    draft
        .peerings
        .get_mut(&peering)
        .unwrap_or_else(|| unreachable!("just found it"))
        .exposes_mut(side)
        .push(ExposeSpec { slot, flavour });
    Some(Undo::RemoveExpose {
        peering,
        side,
        slot,
    })
}

/// Change what one expose does, leaving its private prefix alone.
fn set_flavour(
    draft: &mut Draft,
    peering: PeeringHandle,
    side: Side,
    slot: u8,
    flavour: Flavour,
) -> Option<Undo> {
    let spec = draft.peerings.get(&peering)?;
    if flavour == Flavour::Masquerade && spec.has_stateful(side.other()) {
        return None;
    }
    let index = spec.exposes(side).iter().position(|e| e.slot == slot)?;
    let exposes = draft
        .peerings
        .get_mut(&peering)
        .unwrap_or_else(|| unreachable!("just found it"))
        .exposes_mut(side);
    let previous = exposes[index].flavour;
    exposes[index].flavour = flavour;
    Some(Undo::SetFlavour {
        peering,
        side,
        slot,
        flavour: previous,
    })
}

impl Undo {
    /// Put back what the operation that produced this changed.
    ///
    /// # Panics
    ///
    /// If `draft` is not the state the operation left behind. An undo is only meaningful against
    /// that state, and applying one to any other is a caller error rather than a case to handle.
    pub fn apply(&self, draft: &mut Draft) {
        match self {
            Undo::RemoveVpc(handle) => {
                assert!(draft.vpcs.remove(handle), "no vpc {handle:?} to remove");
            }
            Undo::RestoreVpc { handle, peerings } => {
                assert!(draft.vpcs.insert(*handle), "vpc {handle:?} is still there");
                for (peering, spec) in peerings {
                    assert!(
                        draft.peerings.insert(*peering, spec.clone()).is_none(),
                        "peering {peering:?} is still there"
                    );
                }
            }
            Undo::RemovePeering(handle) => {
                assert!(
                    draft.peerings.remove(handle).is_some(),
                    "no peering {handle:?} to remove"
                );
            }
            Undo::RestorePeering(handle, spec) => {
                assert!(
                    draft.peerings.insert(*handle, spec.clone()).is_none(),
                    "peering {handle:?} is still there"
                );
            }
            Undo::RemoveExpose {
                peering,
                side,
                slot,
            } => {
                let spec = draft
                    .peerings
                    .get_mut(peering)
                    .unwrap_or_else(|| unreachable!("no peering {peering:?}"));
                let index = spec
                    .exposes(*side)
                    .iter()
                    .position(|e| e.slot == *slot)
                    .unwrap_or_else(|| unreachable!("no expose in slot {slot}"));
                spec.exposes_mut(*side).remove(index);
            }
            Undo::RestoreExpose {
                peering,
                side,
                index,
                spec,
            } => {
                draft
                    .peerings
                    .get_mut(peering)
                    .unwrap_or_else(|| unreachable!("no peering {peering:?}"))
                    .exposes_mut(*side)
                    .insert(*index, *spec);
            }
            Undo::SetFlavour {
                peering,
                side,
                slot,
                flavour,
            } => {
                let spec = draft
                    .peerings
                    .get_mut(peering)
                    .unwrap_or_else(|| unreachable!("no peering {peering:?}"));
                let index = spec
                    .exposes(*side)
                    .iter()
                    .position(|e| e.slot == *slot)
                    .unwrap_or_else(|| unreachable!("no expose in slot {slot}"));
                spec.exposes_mut(*side)[index].flavour = *flavour;
            }
        }
    }
}

/// The most operations one drawn sequence holds.
///
/// Bounded so that handles stay inside a `u8` -- a sequence cannot allocate more than one vpc and
/// one peering per operation -- and because the point of a sequence is a *species* of update rather
/// than a long history. The general property is recovered by composition, not by length.
pub const MAX_SEQUENCE: u8 = 32;

/// Draws sequences of operations, every one of which applies where it lands.
///
/// Each operation is chosen from what the draft built so far will accept, so the sequence is legal
/// by construction and the generator holds none of the validator's rules. Arguments are selected by
/// index modulo what exists rather than by handle, so that removing an earlier operation degrades
/// the rest of the sequence instead of scrambling it -- which is what makes sequence-level shrinking
/// worth attempting.
#[derive(Clone, Copy, Debug)]
pub struct Sequence {
    /// The most operations to draw. The generator draws between zero and this.
    pub len: u8,
}

impl Default for Sequence {
    fn default() -> Self {
        Self { len: 24 }
    }
}

impl Sequence {
    /// Sequences of up to `len` operations, clamped to [`MAX_SEQUENCE`].
    #[must_use]
    pub fn of(len: u8) -> Self {
        Self {
            len: len.min(MAX_SEQUENCE),
        }
    }

    /// Fold a sequence over the blank configuration.
    ///
    /// # Panics
    ///
    /// If any operation does not apply. A sequence from this generator never contains one; one
    /// assembled by hand may, and silently skipping it would leave the caller with a draft that is
    /// not what the sequence says.
    #[must_use]
    pub fn fold(ops: &[Op]) -> Draft {
        let mut draft = Draft::new();
        for (index, op) in ops.iter().enumerate() {
            assert!(
                op.apply(&mut draft).is_some(),
                "operation {index} ({op:?}) does not apply"
            );
        }
        draft
    }
}

impl ValueGenerator for Sequence {
    type Output = Vec<Op>;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<Op>> {
        let count = driver.gen_u8(Included(&0), Included(&self.len.min(MAX_SEQUENCE)))?;
        // How many peered components this sequence aims to end up with. Drawn once, because it is
        // a property of the configuration being built rather than of any one operation, and drawn
        // at all because a sequence that always aims at one would never state anything about
        // isolation while a sequence that never aims at one would skip the fully connected case.
        let target = usize::from(driver.gen_u8(Included(&1), Included(&4))?);
        let mut draft = Draft::new();
        let mut next_vpc = 0u8;
        let mut next_peering = 0u8;
        let mut ops = Vec::with_capacity(usize::from(count));

        for _ in 0..count {
            // A draw that finds nothing applicable ends the sequence rather than discarding it:
            // the ops so far are a perfectly good sequence, and throwing them away would spend the
            // draw for nothing.
            let Some(op) = draw(driver, &draft, &mut next_vpc, &mut next_peering, target) else {
                break;
            };
            // The draw is responsible for producing something applicable; if it did not, the
            // sequence is not the one the generator claims to have drawn.
            op.apply(&mut draft)?;
            ops.push(op);
        }

        Some(ops)
    }
}

/// The kinds of operation, and how often each is worth drawing relative to the others.
///
/// Weighted towards the operations that build structure, because a sequence's value is in the
/// configuration it arrives at rather than in its length, and towards removal enough that a quarter
/// of every sequence is deletion -- which the design note names as where the bugs live.
const MENU: [(Kind, u8); 7] = [
    (Kind::AddVpc, 4),
    (Kind::RemoveVpc, 1),
    (Kind::AddPeering, 4),
    (Kind::RemovePeering, 1),
    (Kind::AddExpose, 2),
    (Kind::RemoveExpose, 1),
    (Kind::SetFlavour, 2),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    AddVpc,
    RemoveVpc,
    AddPeering,
    RemovePeering,
    AddExpose,
    RemoveExpose,
    SetFlavour,
}

impl Kind {
    /// Whether this kind has anything to work on, cheaply and without drawing.
    ///
    /// An approximation is fine in one direction only: a kind wrongly called applicable is caught
    /// when its draw returns nothing and is struck off the menu, whereas a kind wrongly called
    /// inapplicable is silently never drawn. So each of these errs towards saying yes.
    fn applicable(self, draft: &Draft, next_vpc: u8, next_peering: u8) -> bool {
        let sides = || {
            draft
                .peerings()
                .flat_map(|(_, spec)| [Side::Left, Side::Right].map(move |side| spec.exposes(side)))
        };
        match self {
            Kind::AddVpc => next_vpc < u8::MAX && draft.vpcs.len() < usize::from(MAX_VPCS),
            Kind::RemoveVpc => !draft.vpcs.is_empty(),
            Kind::AddPeering => {
                let vpcs = draft.vpcs.len();
                next_peering < u8::MAX && vpcs >= 2 && draft.peerings.len() < vpcs * (vpcs - 1) / 2
            }
            Kind::RemovePeering | Kind::SetFlavour => !draft.peerings.is_empty(),
            Kind::AddExpose => sides().any(|exposes| exposes.len() < usize::from(MAX_EXPOSES)),
            Kind::RemoveExpose => sides().any(|exposes| exposes.len() > 1),
        }
    }
}

/// One operation that applies to `draft`.
///
/// The applicable kinds are collected first and the draw is made among those, rather than drawing a
/// kind and falling through to the next when it has nothing to work on. Falling through sounds
/// harmless and is not: whichever kind sits after a blocked one becomes its sink, so the drawn
/// distribution has nothing to do with the weights. Two versions of this were wrong that way.
/// `AddVpc` as the last resort made `RemoveVpc` take every draw once one vpc existed, so the draft
/// ping-ponged between zero and one and no peering was ever drawn at all. Capping the vpcs then
/// moved the same pathology one place along -- `AddVpc` blocked at the cap, so its draws fell into
/// `RemoveVpc`, which spent a third of every sequence tearing down what the rest had built. Both
/// were found by the counters in the tests below, not by reading this.
fn draw<D: Driver>(
    driver: &mut D,
    draft: &Draft,
    next_vpc: &mut u8,
    next_peering: &mut u8,
    target: usize,
) -> Option<Op> {
    let mut menu: Vec<Kind> = MENU
        .iter()
        .filter(|(kind, _)| kind.applicable(draft, *next_vpc, *next_peering))
        .flat_map(|(kind, weight)| std::iter::repeat_n(*kind, usize::from(*weight)))
        .collect();

    while !menu.is_empty() {
        let kind = pick(driver, &menu)?;
        let built = match kind {
            Kind::AddVpc => Some(Op::AddVpc(VpcHandle(*next_vpc))),
            Kind::RemoveVpc => draw_remove_vpc(driver, draft),
            Kind::AddPeering => draw_add_peering(driver, draft, *next_peering, target),
            Kind::RemovePeering => draw_remove_peering(driver, draft),
            Kind::AddExpose => draw_add_expose(driver, draft),
            Kind::RemoveExpose => draw_remove_expose(driver, draft),
            Kind::SetFlavour => draw_set_flavour(driver, draft),
        };

        let Some(op) = built else {
            menu.retain(|other| *other != kind);
            continue;
        };
        match op {
            Op::AddVpc(_) => *next_vpc = next_vpc.checked_add(1)?,
            Op::AddPeering { .. } => *next_peering = next_peering.checked_add(1)?,
            _ => {}
        }
        return Some(op);
    }

    None
}

fn draw_remove_vpc<D: Driver>(driver: &mut D, draft: &Draft) -> Option<Op> {
    let vpcs: Vec<VpcHandle> = draft.vpcs().collect();
    Some(Op::RemoveVpc(pick(driver, &vpcs)?))
}

/// A peering between two vpcs that are not already peered.
///
/// The second endpoint is drawn from the first's own component when the draw says so, and that
/// bias is the whole reason this is not two independent picks. Peering random pairs joins
/// everything into one component at around one edge per vpc, and in a connected configuration
/// every claim about tenant isolation is vacuously true.
/// A peering between two vpcs that are not already peered.
///
/// The partner is not just a second pick, because a random edge process percolates: at around one
/// edge per vpc everything is one component, and in a connected configuration every claim about
/// tenant isolation is vacuously true. Two brakes, and both had to be got right before the
/// `sequences_produce_disjoint_peering_components` counter moved at all:
///
/// * a draw may ask to stay **inside** the left vpc's own component, which strengthens a component
///   without joining two; and
/// * joining two *established* components is refused once the configuration already has as many as
///   this sequence asked for. Absorbing an unpeered vpc is always allowed, since that grows a
///   component rather than merging two.
///
/// A draw that asks for one of those and finds nobody falls back to the other rather than refusing.
/// Refusing outright looks tidier and cost most of the peerings: an isolated vpc is its own whole
/// component, so every inside draw on one found nobody, and half of all peering draws were thrown
/// away before the brakes did any work.
fn draw_add_peering<D: Driver>(
    driver: &mut D,
    draft: &Draft,
    next: u8,
    target: usize,
) -> Option<Op> {
    let vpcs: Vec<VpcHandle> = draft.vpcs().collect();
    let left = pick(driver, &vpcs)?;
    let within = driver.produce::<bool>()?;

    let free = |candidates: Vec<VpcHandle>| -> Vec<VpcHandle> {
        candidates
            .into_iter()
            .filter(|right| *right != left && draft.peering_between(left, *right).is_none())
            .collect()
    };

    let components = draft.components();
    let component_of = |vpc: VpcHandle| -> &[VpcHandle] {
        components
            .iter()
            .find(|component| component.contains(&vpc))
            .map_or(&[][..], Vec::as_slice)
    };
    let component = component_of(left).to_vec();

    // Only *peered* components count. An earlier version counted isolated vpcs too, so the count
    // was always well above the target and the brake never engaged once.
    let peered = components
        .iter()
        .filter(|component| component.len() > 1)
        .count();
    let left_alone = component.len() <= 1;
    let want_more = peered < target;

    // Which partners keep the configuration heading towards the number of components this sequence
    // asked for. Two unpeered vpcs may always pair off: that starts a component rather than joining
    // any. Absorbing a lone vpc into an existing component is refused only while more components
    // are still wanted -- which is the case that had been missing, and was the whole leak, since
    // with a handful of vpcs almost every lone vpc found a partner already in the one component and
    // was swallowed by it.
    let allowed = |right: VpcHandle| {
        let right_alone = component_of(right).len() <= 1;
        match (left_alone, right_alone) {
            (true, true) => true,
            (true, false) | (false, true) => !want_more,
            (false, false) => peered > target,
        }
    };

    let inside = free(component.clone());
    let outside: Vec<VpcHandle> = free(vpcs)
        .into_iter()
        .filter(|right| !component.contains(right))
        .filter(|right| allowed(*right))
        .collect();

    // A draw that asks to stay inside and finds nobody takes what is outside, and vice versa;
    // only an operation with nowhere at all to go refuses.
    let candidates = if (within && !inside.is_empty()) || outside.is_empty() {
        inside
    } else {
        outside
    };

    Some(Op::AddPeering {
        handle: PeeringHandle(next),
        left,
        right: pick(driver, &candidates)?,
    })
}

fn draw_remove_peering<D: Driver>(driver: &mut D, draft: &Draft) -> Option<Op> {
    let peerings: Vec<PeeringHandle> = draft.peerings().map(|(handle, _)| handle).collect();
    Some(Op::RemovePeering(pick(driver, &peerings)?))
}

fn draw_add_expose<D: Driver>(driver: &mut D, draft: &Draft) -> Option<Op> {
    let room: Vec<(PeeringHandle, Side)> = draft
        .peerings()
        .flat_map(|(handle, spec)| {
            [Side::Left, Side::Right]
                .into_iter()
                .filter(move |side| spec.exposes(*side).len() < usize::from(MAX_EXPOSES))
                .map(move |side| (handle, side))
        })
        .collect();
    let (peering, side) = pick(driver, &room)?;
    let spec = draft.peerings.get(&peering)?;
    let slot = (0..MAX_EXPOSES).find(|slot| spec.exposes(side).iter().all(|e| e.slot != *slot))?;

    Some(Op::AddExpose {
        peering,
        side,
        slot,
        flavour: draw_flavour(driver, spec, side)?,
    })
}

fn draw_remove_expose<D: Driver>(driver: &mut D, draft: &Draft) -> Option<Op> {
    let removable: Vec<(PeeringHandle, Side, u8)> = draft
        .peerings()
        .flat_map(|(handle, spec)| {
            [Side::Left, Side::Right]
                .into_iter()
                .filter(move |side| spec.exposes(*side).len() > 1)
                .flat_map(move |side| {
                    spec.exposes(side)
                        .iter()
                        .map(move |expose| (handle, side, expose.slot))
                })
        })
        .collect();
    let (peering, side, slot) = pick(driver, &removable)?;

    Some(Op::RemoveExpose {
        peering,
        side,
        slot,
    })
}

fn draw_set_flavour<D: Driver>(driver: &mut D, draft: &Draft) -> Option<Op> {
    let exposes: Vec<(PeeringHandle, Side, u8)> = draft
        .peerings()
        .flat_map(|(handle, spec)| {
            [Side::Left, Side::Right].into_iter().flat_map(move |side| {
                spec.exposes(side)
                    .iter()
                    .map(move |expose| (handle, side, expose.slot))
            })
        })
        .collect();
    let (peering, side, slot) = pick(driver, &exposes)?;
    let spec = draft.peerings.get(&peering)?;

    Some(Op::SetFlavour {
        peering,
        side,
        slot,
        flavour: draw_flavour(driver, spec, side)?,
    })
}

/// A flavour this side of this peering will accept.
///
/// Masquerade is refused when the far side already has it -- `validate_nat_combinations` allows at
/// most one stateful side per peering -- so a draw asking for it there gets forwarding instead. That
/// is the precondition made unrepresentable rather than checked: the sequence never contains the
/// illegal operation, so nothing downstream has to know the rule.
///
/// [`Op::apply`] refuses the same thing, and the two are genuinely redundant: breaking either one
/// alone leaves every property here green, and only removing both produces a configuration the
/// validator rejects. Worth knowing rather than tidying away. This one keeps a draw from being
/// spent on an operation that will be refused; the one in `apply` is what makes the rule hold for a
/// sequence a caller assembled by hand.
fn draw_flavour<D: Driver>(driver: &mut D, spec: &PeeringSpec, side: Side) -> Option<Flavour> {
    if driver.produce::<bool>()? && !spec.has_stateful(side.other()) {
        Some(Flavour::Masquerade)
    } else {
        Some(Flavour::Forward)
    }
}

/// One of `items`, chosen by index modulo how many there are.
///
/// A raw byte taken modulo the length rather than a bounded draw, so that the same byte keeps
/// naming a sensible element after an earlier operation is removed from the sequence. That is what
/// makes sequence-level shrinking degrade a sequence rather than scramble it.
fn pick<T: Copy, D: Driver>(driver: &mut D, items: &[T]) -> Option<T> {
    if items.is_empty() {
        return None;
    }
    let index = usize::from(driver.produce::<u8>()?) % items.len();
    items.get(index).copied()
}

impl Draft {
    /// This draft with everything `footprint` names dropped.
    ///
    /// The frame of an operation is what it leaves alone, so an operation's frame condition is that
    /// the draft restricted to the complement of its write set is unchanged. Written here rather
    /// than in the test because it is also how a caller states "compare these two configurations
    /// everywhere the change was not supposed to reach".
    #[must_use]
    pub fn restricted(&self, footprint: &Footprint) -> Self {
        Self {
            vpcs: self
                .vpcs
                .iter()
                .copied()
                .filter(|vpc| !footprint.vpcs.contains(vpc))
                .collect(),
            peerings: self
                .peerings
                .iter()
                .filter(|(peering, _)| !footprint.peerings.contains(peering))
                .map(|(peering, spec)| (*peering, spec.clone()))
                .collect(),
        }
    }

    /// Whether every peering names two vpcs that are present.
    ///
    /// The invariant a deletion is most likely to break: a peering left behind by a removed vpc is
    /// a dangling reference, and `Overlay::validate` would reject it -- so this says the same thing
    /// as the validity property, but attributes it to the operation that broke it rather than to
    /// the whole sequence.
    #[must_use]
    pub fn references_resolve(&self) -> bool {
        self.peerings
            .values()
            .all(|spec| self.vpcs.contains(&spec.left) && self.vpcs.contains(&spec.right))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bolero::check;
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    /// How many sequences reached each kind of operation.
    ///
    /// The draw falls through to the next kind when one has nothing to work on, and falls all the
    /// way back to `AddVpc` when none of them does, so an operation being *in* the vocabulary is no
    /// evidence at all that it is ever drawn. Without these a change that made removals
    /// unreachable -- the exact thing the design note warns the algebra will drift towards -- would
    /// leave every property here green.
    static DRAWN: [AtomicUsize; 7] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    const KINDS: [&str; 7] = [
        "AddVpc",
        "RemoveVpc",
        "AddPeering",
        "RemovePeering",
        "AddExpose",
        "RemoveExpose",
        "SetFlavour",
    ];

    fn record(op: Op) {
        let index = match op {
            Op::AddVpc(_) => 0,
            Op::RemoveVpc(_) => 1,
            Op::AddPeering { .. } => 2,
            Op::RemovePeering(_) => 3,
            Op::AddExpose { .. } => 4,
            Op::RemoveExpose { .. } => 5,
            Op::SetFlavour { .. } => 6,
        };
        DRAWN[index].fetch_add(1, Relaxed);
    }

    fn assert_every_kind_drawn() {
        for (kind, count) in KINDS.iter().zip(&DRAWN) {
            assert!(
                count.load(Relaxed) > 0,
                "no {kind} was ever drawn, so nothing here tested it"
            );
        }
    }

    /// The headline claim: the generator never needs to know a validation rule.
    ///
    /// Every draft a sequence folds to must materialise and validate. A failure is either a
    /// missing precondition in the algebra -- an operation that can build something the validator
    /// refuses -- or a validator refusing something it should accept, and the two are told apart by
    /// reading the sequence, which is short.
    ///
    /// The dangling-reference invariant is checked after every step rather than at the end, so a
    /// deletion that orphans a peering is attributed to the deletion.
    #[test]
    fn every_sequence_builds_a_valid_configuration() {
        let masquerading = AtomicUsize::new(0);
        let forwarding = AtomicUsize::new(0);

        check!()
            .with_generator(Sequence::default())
            .for_each(|ops| {
                let mut draft = Draft::new();
                for (index, op) in ops.iter().enumerate() {
                    record(*op);
                    assert!(
                        op.apply(&mut draft).is_some(),
                        "the generator drew {op:?} at {index}, which does not apply"
                    );
                    assert!(
                        draft.references_resolve(),
                        "{op:?} at {index} left a peering naming an absent vpc: {draft:?}"
                    );
                }

                for (_, spec) in draft.peerings() {
                    for side in [Side::Left, Side::Right] {
                        for expose in spec.exposes(side) {
                            match expose.flavour() {
                                Flavour::Masquerade => &masquerading,
                                Flavour::Forward => &forwarding,
                            }
                            .fetch_add(1, Relaxed);
                        }
                    }
                }

                let overlay = draft
                    .overlay()
                    .unwrap_or_else(|e| panic!("{ops:?} does not assemble: {e}"));
                if let Err(e) = overlay.validate() {
                    panic!("{ops:?} builds a configuration the validator refuses: {e}");
                }
            });

        assert_every_kind_drawn();
        assert!(
            masquerading.load(Relaxed) > 0 && forwarding.load(Relaxed) > 0,
            "only one flavour of expose was ever built (masquerade {}, forward {}), so the \
             combination rules were not exercised",
            masquerading.load(Relaxed),
            forwarding.load(Relaxed)
        );
    }

    /// `undo(apply(A, X)) == X`, for every operation of a drawn sequence at the state it met.
    ///
    /// This is the piece that makes the algebra a groupoid rather than a group, and the one most
    /// likely to be written wrong: `RemoveVpc` has to put back every peering it cascaded through,
    /// and `RemoveExpose` has to put its expose back where it was rather than at the end.
    ///
    /// It is also the sharpest state-leak probe available once there is a pipeline underneath,
    /// because the configuration after `undo . A` is provably the configuration before -- so any
    /// difference in behaviour is attributable to runtime state and to nothing else.
    #[test]
    fn undo_restores_the_configuration() {
        let checked = AtomicUsize::new(0);

        check!()
            .with_generator(Sequence::default())
            .for_each(|ops| {
                let mut draft = Draft::new();
                for op in ops {
                    let before = draft.clone();
                    let undo = op
                        .apply(&mut draft)
                        .unwrap_or_else(|| panic!("{op:?} does not apply"));
                    let after = draft.clone();

                    let mut reversed = after;
                    undo.apply(&mut reversed);
                    assert_eq!(
                        reversed, before,
                        "{op:?} then {undo:?} is not the configuration it started from"
                    );
                    checked.fetch_add(1, Relaxed);
                }
            });

        assert!(
            checked.load(Relaxed) > 0,
            "no operation was ever undone: every drawn sequence was empty"
        );
    }

    /// An operation changes nothing outside its write set.
    ///
    /// This is what keeps [`Op::writes`] honest, and that matters more than it looks: commutation
    /// is *derived* from the write sets, so a write set that under-reports would silently license
    /// swaps that change the configuration. Under-report and this fires; over-report and the
    /// commutation counter below falls instead. The pair pins the footprint from both sides.
    #[test]
    fn an_operation_leaves_its_complement_alone() {
        check!()
            .with_generator(Sequence::default())
            .for_each(|ops| {
                let mut draft = Draft::new();
                for op in ops {
                    let writes = op.writes(&draft);
                    let before = draft.restricted(&writes);
                    op.apply(&mut draft)
                        .unwrap_or_else(|| panic!("{op:?} does not apply"));
                    assert_eq!(
                        draft.restricted(&writes),
                        before,
                        "{op:?} claims to write {writes:?} and changed something outside it"
                    );
                }
            });
    }

    /// Two adjacent operations whose footprints are disjoint may be swapped.
    ///
    /// The conflict test is the database scheduler's: write-write and read-write conflict,
    /// read-read does not. Nothing here declares that any particular pair commutes -- the pairs are
    /// whatever the sequence happens to contain -- which is the point, since commutation depends on
    /// position and a table of commuting pairs is wrong as soon as it leaves the position it was
    /// written for.
    ///
    /// Only the configuration-level claim. Behavioural commutation is strictly stronger and can
    /// fail while the configurations agree, legitimately -- two orders allocate NAT ports in
    /// different sequences -- so it belongs over an observable projection and not here.
    #[test]
    fn independent_operations_commute() {
        let swapped = AtomicUsize::new(0);
        let considered = AtomicUsize::new(0);

        check!()
            .with_generator(Sequence::default())
            .for_each(|ops| {
                for index in 0..ops.len().saturating_sub(1) {
                    let mut draft = Sequence::fold(&ops[..index]);
                    let (first, second) = (ops[index], ops[index + 1]);

                    considered.fetch_add(1, Relaxed);
                    if conflict(&draft, first, second) {
                        continue;
                    }

                    let mut straight = draft.clone();
                    first.apply(&mut straight);
                    second.apply(&mut straight);

                    assert!(
                        second.apply(&mut draft).is_some(),
                        "{second:?} does not conflict with {first:?} but only applies after it"
                    );
                    assert!(
                        first.apply(&mut draft).is_some(),
                        "{first:?} does not conflict with {second:?} but only applies before it"
                    );

                    assert_eq!(
                        draft, straight,
                        "{first:?} and {second:?} have disjoint footprints and do not commute"
                    );
                    swapped.fetch_add(1, Relaxed);
                }
            });

        assert!(
            swapped.load(Relaxed) > 0,
            "no adjacent pair was ever found independent out of {} considered, so this asserted \
             nothing",
            considered.load(Relaxed)
        );
    }

    fn conflict(draft: &Draft, first: Op, second: Op) -> bool {
        let (rw1, ww1) = (first.reads(), first.writes(draft));
        let (rw2, ww2) = (second.reads(), second.writes(draft));
        ww1.intersects(&ww2) || ww1.intersects(&rw2) || rw1.intersects(&ww2)
    }

    /// The generator has to be pushed into producing more than one peering component.
    ///
    /// Peering random pairs joins everything at around one edge per vpc, and every claim about
    /// tenant isolation is vacuously true in a connected configuration. This does not assert
    /// isolation -- there is no traffic here -- it asserts that the *configurations* isolation will
    /// eventually be stated over are actually produced.
    #[test]
    fn sequences_produce_disjoint_peering_components() {
        let split = AtomicUsize::new(0);
        let joined = AtomicUsize::new(0);

        check!()
            .with_generator(Sequence::default())
            .for_each(|ops| {
                let draft = Sequence::fold(ops);
                // A component of isolated vpcs says nothing: two vpcs neither of which peers with
                // anything are trivially disjoint. Count only configurations with two or more
                // components that each contain a peering.
                let peered = draft
                    .components()
                    .into_iter()
                    .filter(|component| {
                        draft
                            .peerings()
                            .any(|(_, spec)| component.contains(&spec.left))
                    })
                    .count();
                if peered >= 2 {
                    split.fetch_add(1, Relaxed);
                } else {
                    joined.fetch_add(1, Relaxed);
                }
            });

        assert!(
            split.load(Relaxed) > 0,
            "every sequence produced at most one peered component out of {} drawn, so nothing here \
             will ever be able to state isolation",
            joined.load(Relaxed)
        );
    }

    /// Removing a vpc removes every peering that named it, and nothing else.
    ///
    /// Stated on its own rather than left to the validity property because a deletion's footprint
    /// is the thing the design note calls out as where the bugs live, and a sequence-level failure
    /// would only say that *some* configuration was refused.
    #[test]
    fn removing_a_vpc_removes_exactly_what_referred_to_it() {
        let removed = AtomicUsize::new(0);
        let cascaded = AtomicUsize::new(0);

        check!()
            .with_generator(Sequence::default())
            .for_each(|ops| {
                let mut draft = Draft::new();
                for op in ops {
                    if let Op::RemoveVpc(handle) = *op {
                        let doomed: BTreeSet<PeeringHandle> = draft
                            .peerings()
                            .filter(|(_, spec)| spec.touches(handle))
                            .map(|(peering, _)| peering)
                            .collect();
                        let survivors: BTreeSet<PeeringHandle> = draft
                            .peerings()
                            .map(|(peering, _)| peering)
                            .filter(|peering| !doomed.contains(peering))
                            .collect();

                        op.apply(&mut draft);

                        let left: BTreeSet<PeeringHandle> =
                            draft.peerings().map(|(peering, _)| peering).collect();
                        assert_eq!(
                            left, survivors,
                            "removing {handle:?} should have taken {doomed:?} and nothing else"
                        );
                        removed.fetch_add(1, Relaxed);
                        cascaded.fetch_add(doomed.len(), Relaxed);
                    } else {
                        op.apply(&mut draft);
                    }
                }
            });

        assert!(removed.load(Relaxed) > 0, "no vpc was ever removed");
        assert!(
            cascaded.load(Relaxed) > 0,
            "every removed vpc was unpeered, so the cascade was never exercised across {} removals",
            removed.load(Relaxed)
        );
    }
}
