// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::ops::Bound::Included;
use std::time::Duration;

use bolero::{Driver, ValueGenerator};
use lpm::prefix::{
    IpPrefix, Ipv4Prefix, PortRange, Prefix, PrefixPortsSet, PrefixWithOptionalPorts,
};

use crate::ConfigError;
use crate::external::overlay::Overlay;
use crate::external::overlay::acl::{Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope};
use crate::external::overlay::vpc::{Vpc, VpcTable};
use crate::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct VpcHandle(pub u8);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct PeeringHandle(pub u8);

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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Flavour {
    Forward,
    Masquerade,
    StaticNat,
    PortForward,
}

impl Flavour {
    #[must_use]
    pub const fn is_directional(self) -> bool {
        matches!(self, Self::Masquerade | Self::PortForward)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub enum Guard {
    #[default]
    Open,
    Permit,
    PermitFlow,
    PermitExcept,
    PermitByProtocol,
    Deny,
}

impl Guard {
    fn acl(self, peering: PeeringHandle, spec: &PeeringSpec) -> Option<Acl> {
        let (default, action, scope) = match self {
            Guard::Open => return None,
            Guard::Permit | Guard::PermitExcept | Guard::PermitByProtocol => {
                (AclAction::Deny, AclAction::Allow, AclScope::Packet)
            }
            Guard::PermitFlow => (AclAction::Deny, AclAction::Allow, AclScope::Flow),
            Guard::Deny => (AclAction::Allow, AclAction::Deny, AclScope::Packet),
        };
        let (proto, any_ports) = if self == Guard::PermitByProtocol {
            (AclProtoMatch::Udp, vec![port_range(EVERY_PORT)])
        } else {
            (AclProtoMatch::Any, Vec::new())
        };
        let rule = |side: Side| {
            let (from, to) = (spec.vpc(side).name(), spec.vpc(side.other()).name());
            AclRule {
                name: format!("{from}-to-{to}"),
                from,
                to,
                action,
                pattern: AclPattern {
                    src: PrefixPortsSet::new(),
                    dst: PrefixPortsSet::new(),
                    src_any_ports: any_ports.clone(),
                    dst_any_ports: any_ports.clone(),
                    proto,
                },
                scope,
                log: action == AclAction::Deny,
            }
        };
        let rules = match self {
            Guard::PermitFlow => {
                vec![rule(self.opening_side(spec).unwrap_or_else(|| {
                    unreachable!("`legal_on` refused a guard with no side")
                }))]
            }
            Guard::PermitExcept | Guard::PermitByProtocol => {
                let (side, which, prefix) = spec
                    .exception(peering)
                    .unwrap_or_else(|| unreachable!("`legal_on` refused a guard with no expose"));
                let denied_from = match which {
                    Narrowing::Source => side,
                    Narrowing::Destination => side.other(),
                };
                let mut denial = rule(denied_from);
                denial.name = format!("{}-except", denial.name);
                denial.action = AclAction::Deny;
                let named = PrefixPortsSet::from([PrefixWithOptionalPorts::from(prefix)]);
                match which {
                    Narrowing::Source => denial.pattern.src = named,
                    Narrowing::Destination => denial.pattern.dst = named,
                }
                if self == Guard::PermitByProtocol {
                    denial.pattern.proto = AclProtoMatch::Tcp;
                }
                vec![denial, rule(denied_from), rule(denied_from.other())]
            }
            Guard::Open | Guard::Permit | Guard::Deny => {
                vec![rule(Side::Left), rule(Side::Right)]
            }
        };
        Some(Acl::new(default, rules))
    }

    fn opening_side(self, spec: &PeeringSpec) -> Option<Side> {
        match self {
            Guard::PermitFlow => Some(
                spec.sole_opener()
                    .unwrap_or_else(|| unreachable!("`legal_on` refused a guard with no side")),
            ),
            Guard::Open
            | Guard::Permit
            | Guard::PermitExcept
            | Guard::PermitByProtocol
            | Guard::Deny => None,
        }
    }

    fn legal_on(self, spec: &PeeringSpec) -> bool {
        match self {
            Guard::Open | Guard::Permit | Guard::Deny => true,
            Guard::PermitFlow => spec.sole_opener().is_some(),
            Guard::PermitExcept | Guard::PermitByProtocol => spec.exception_slot().is_some(),
        }
    }

    fn silences(self, spec: &PeeringSpec, side: Side, nth: usize) -> bool {
        match self {
            Guard::Open | Guard::Permit | Guard::PermitFlow | Guard::PermitByProtocol => false,
            Guard::Deny => true,
            Guard::PermitExcept => spec
                .exception_slot()
                .is_some_and(|(at, which, _)| (at, which) == (side, nth)),
        }
    }
}

pub const MAX_EXPOSES: u8 = 4;

pub const MAX_VPCS: u8 = 6;

const SLOTS_PER_PEERING: u32 = 2 * MAX_EXPOSES as u32;

impl VpcHandle {
    fn name(self) -> String {
        format!("VPC-{:03}", self.0)
    }

    fn id(self) -> String {
        format!("V{:04}", self.0)
    }

    fn vni(self) -> u32 {
        1000 + u32::from(self.0)
    }
}

const LONG_IDLE_TIMEOUT: Duration = Duration::from_hours(1);

impl PeeringHandle {
    fn name(self) -> String {
        format!("PEERING-{:03}", self.0)
    }

    fn group(self) -> String {
        format!("group-{}", self.0 % 3)
    }

    fn block(self, side: Side, slot: u8) -> u32 {
        u32::from(self.0) * SLOTS_PER_PEERING
            + u32::try_from(side.index()).unwrap_or_else(|_| unreachable!())
                * u32::from(MAX_EXPOSES)
            + u32::from(slot)
    }
}

pub(crate) const FORWARDED_PRIVATE_PORTS: (u16, u16) = (1000, 1004);

pub(crate) const FORWARDED_PUBLIC_PORTS: (u16, u16) = (2000, 2004);

const EVERY_PORT: (u16, u16) = (1, u16::MAX);

fn port_range((start, end): (u16, u16)) -> PortRange {
    PortRange::new(start, end).unwrap_or_else(|_| unreachable!("a well-formed port range"))
}

fn private_prefix(index: u32) -> Prefix {
    prefix_v4(0x0A00_0000 | (index << 8), 24)
}

fn public_prefix(index: u32) -> Prefix {
    prefix_v4(0xAC10_0000 | (index << 8), 24)
}

fn prefix_v4(bits: u32, len: u8) -> Prefix {
    Prefix::from(
        Ipv4Prefix::new(Ipv4Addr::from_bits(bits), len)
            .unwrap_or_else(|_| unreachable!("a well-formed prefix")),
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExposeSpec {
    slot: u8,
    flavour: Flavour,
}

impl ExposeSpec {
    #[must_use]
    pub fn flavour(self) -> Flavour {
        self.flavour
    }

    fn idle_timeout(self) -> Option<Duration> {
        (self.slot % 2 == 1).then_some(LONG_IDLE_TIMEOUT)
    }

    #[must_use]
    pub fn private(self, peering: PeeringHandle, side: Side) -> Prefix {
        private_prefix(peering.block(side, self.slot))
    }

    #[must_use]
    pub fn public(self, peering: PeeringHandle, side: Side) -> Prefix {
        match self.flavour {
            Flavour::Forward => self.private(peering, side),
            Flavour::Masquerade | Flavour::StaticNat | Flavour::PortForward => {
                public_prefix(peering.block(side, self.slot))
            }
        }
    }

    fn expose(self, peering: PeeringHandle, side: Side) -> VpcExpose {
        let private = self.private(peering, side);
        match self.flavour {
            Flavour::Forward => VpcExpose::empty().ip(private.into()),
            Flavour::Masquerade => VpcExpose::empty()
                .make_masquerade(self.idle_timeout())
                .unwrap_or_else(|_| unreachable!("an empty expose accepts masquerade"))
                .ip(private.into())
                .as_range(self.public(peering, side).into())
                .unwrap_or_else(|_| unreachable!("a masquerade expose accepts a public range")),
            Flavour::StaticNat => VpcExpose::empty()
                .make_static_nat()
                .unwrap_or_else(|_| unreachable!("an empty expose accepts static nat"))
                .ip(private.into())
                .as_range(self.public(peering, side).into())
                .unwrap_or_else(|_| unreachable!("a static nat expose accepts a public range")),
            Flavour::PortForward => VpcExpose::empty()
                .make_port_forwarding(self.idle_timeout(), None)
                .unwrap_or_else(|_| unreachable!("an empty expose accepts port forwarding"))
                .ip(PrefixWithOptionalPorts::new(
                    private,
                    Some(port_range(FORWARDED_PRIVATE_PORTS)),
                ))
                .as_range(PrefixWithOptionalPorts::new(
                    self.public(peering, side),
                    Some(port_range(FORWARDED_PUBLIC_PORTS)),
                ))
                .unwrap_or_else(|_| {
                    unreachable!("a port forwarding expose accepts a public range")
                }),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Narrowing {
    Source,
    Destination,
}

impl Narrowing {
    fn of(flavour: Flavour) -> Option<Self> {
        match flavour {
            Flavour::Masquerade => Some(Self::Source),
            Flavour::PortForward => Some(Self::Destination),
            Flavour::Forward | Flavour::StaticNat => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeeringSpec {
    left: VpcHandle,
    right: VpcHandle,
    exposes: [Vec<ExposeSpec>; 2],
    guard: Guard,
}

impl PeeringSpec {
    #[must_use]
    pub fn vpc(&self, side: Side) -> VpcHandle {
        match side {
            Side::Left => self.left,
            Side::Right => self.right,
        }
    }

    #[must_use]
    pub fn guard(&self) -> Guard {
        self.guard
    }

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

    fn sole_opener(&self) -> Option<Side> {
        [Side::Left, Side::Right].into_iter().find_map(|side| {
            let exposes = self.exposes(side);
            if exposes.is_empty() {
                return None;
            }
            let all = |flavour| exposes.iter().all(|expose| expose.flavour == flavour);
            if all(Flavour::Masquerade) {
                Some(side)
            } else if all(Flavour::PortForward) {
                Some(side.other())
            } else {
                None
            }
        })
    }

    fn exception_slot(&self) -> Option<(Side, usize, Narrowing)> {
        [Side::Left, Side::Right].into_iter().find_map(|side| {
            self.exposes(side)
                .iter()
                .enumerate()
                .find_map(|(nth, expose)| Some((side, nth, Narrowing::of(expose.flavour)?)))
        })
    }

    fn exception(&self, peering: PeeringHandle) -> Option<(Side, Narrowing, Prefix)> {
        let (side, nth, which) = self.exception_slot()?;
        let expose = self.exposes(side)[nth];
        let prefix = match which {
            Narrowing::Source => expose.private(peering, side),
            Narrowing::Destination => expose.public(peering, side),
        };
        Some((side, which, prefix))
    }

    fn has_directional(&self, side: Side) -> bool {
        self.exposes(side)
            .iter()
            .any(|expose| expose.flavour.is_directional())
    }

    fn manifest(&self, peering: PeeringHandle, side: Side) -> VpcManifest {
        self.exposes(side).iter().fold(
            VpcManifest::new(&self.vpc(side).name()),
            |manifest, spec| manifest.exposing(spec.expose(peering, side)),
        )
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Draft {
    vpcs: BTreeSet<VpcHandle>,
    peerings: BTreeMap<PeeringHandle, PeeringSpec>,
}

impl Draft {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn vpcs(&self) -> impl ExactSizeIterator<Item = VpcHandle> + '_ {
        self.vpcs.iter().copied()
    }

    #[must_use]
    pub fn peerings(&self) -> impl ExactSizeIterator<Item = (PeeringHandle, &PeeringSpec)> {
        self.peerings.iter().map(|(handle, spec)| (*handle, spec))
    }

    #[must_use]
    pub fn peering_between(&self, left: VpcHandle, right: VpcHandle) -> Option<PeeringHandle> {
        self.peerings
            .iter()
            .find(|(_, spec)| spec.touches(left) && spec.touches(right))
            .map(|(handle, _)| *handle)
    }

    #[must_use]
    pub fn carries(&self, peering: &str, local: &str, nth: usize) -> bool {
        let Some((_, spec)) = self
            .peerings
            .iter()
            .find(|(handle, _)| handle.name() == peering)
        else {
            return true;
        };
        let Some(side) = [Side::Left, Side::Right]
            .into_iter()
            .find(|side| spec.vpc(*side).name() == local)
        else {
            return true;
        };
        !spec.guard.silences(spec, side, nth)
    }

    #[must_use]
    pub fn guard_named(&self, name: &str) -> Option<Guard> {
        self.peerings
            .iter()
            .find(|(handle, _)| handle.name() == name)
            .map(|(_, spec)| spec.guard)
    }

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

    pub fn overlay(&self) -> Result<Overlay, ConfigError> {
        let mut vpc_table = VpcTable::new();
        for vpc in self.vpcs() {
            vpc_table.add(Vpc::new(&vpc.name(), &vpc.id(), vpc.vni())?)?;
        }

        let mut peerings = VpcPeeringTable::new();
        for (handle, spec) in self.peerings() {
            let mut peering = VpcPeering::new(
                &handle.name(),
                spec.manifest(handle, Side::Left),
                spec.manifest(handle, Side::Right),
                handle.group(),
            );
            peering.acl = spec.guard.acl(handle, spec);
            peerings.add(peering)?;
        }

        Ok(Overlay::new(vpc_table, peerings))
    }
}

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

    #[must_use]
    pub fn intersects(&self, other: &Self) -> bool {
        self.vpcs.intersection(&other.vpcs).next().is_some()
            || self.peerings.intersection(&other.peerings).next().is_some()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vpcs.is_empty() && self.peerings.is_empty()
    }

    #[must_use]
    pub fn touches_vpc_named(&self, name: &str) -> bool {
        self.vpcs.iter().any(|vpc| vpc.name() == name)
    }

    #[must_use]
    pub fn touches_peering_named(&self, name: &str) -> bool {
        self.peerings.iter().any(|peering| peering.name() == name)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    AddVpc(VpcHandle),
    RemoveVpc(VpcHandle),
    AddPeering {
        handle: PeeringHandle,
        left: VpcHandle,
        right: VpcHandle,
    },
    RemovePeering(PeeringHandle),
    AddExpose {
        peering: PeeringHandle,
        side: Side,
        slot: u8,
        flavour: Flavour,
    },
    RemoveExpose {
        peering: PeeringHandle,
        side: Side,
        slot: u8,
    },
    SetFlavour {
        peering: PeeringHandle,
        side: Side,
        slot: u8,
        flavour: Flavour,
    },
    SetGuard {
        peering: PeeringHandle,
        guard: Guard,
    },
}

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
    SetGuard {
        peering: PeeringHandle,
        guard: Guard,
    },
}

impl Op {
    #[must_use]
    pub fn reads(&self) -> Footprint {
        match self {
            Op::AddVpc(_) | Op::RemoveVpc(_) | Op::RemovePeering(_) => Footprint::default(),
            Op::AddPeering { left, right, .. } => Footprint::of([*left, *right], []),
            Op::AddExpose { peering, .. }
            | Op::RemoveExpose { peering, .. }
            | Op::SetFlavour { peering, .. }
            | Op::SetGuard { peering, .. } => Footprint::of([], [*peering]),
        }
    }

    #[must_use]
    pub fn writes(&self, draft: &Draft) -> Footprint {
        match self {
            Op::AddVpc(handle) => Footprint::of([*handle], []),
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
            | Op::SetFlavour { peering, .. }
            | Op::SetGuard { peering, .. } => Footprint::of([], [*peering]),
        }
    }

    #[must_use]
    pub fn applicable(&self, draft: &Draft) -> bool {
        let mut trial = draft.clone();
        self.apply(&mut trial).is_some()
    }

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
                        guard: Guard::Open,
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
                respecting_guard(
                    draft,
                    peering,
                    Undo::RestoreExpose {
                        peering,
                        side,
                        index,
                        spec: removed,
                    },
                )
            }

            Op::SetFlavour {
                peering,
                side,
                slot,
                flavour,
            } => set_flavour(draft, peering, side, slot, flavour),

            Op::SetGuard { peering, guard } => {
                let spec = draft.peerings.get_mut(&peering)?;
                if !guard.legal_on(spec) {
                    return None;
                }
                let previous = std::mem::replace(&mut spec.guard, guard);
                Some(Undo::SetGuard {
                    peering,
                    guard: previous,
                })
            }
        }
    }
}

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
    if flavour.is_directional() && spec.has_directional(side.other()) {
        return None;
    }
    draft
        .peerings
        .get_mut(&peering)
        .unwrap_or_else(|| unreachable!("just found it"))
        .exposes_mut(side)
        .push(ExposeSpec { slot, flavour });
    respecting_guard(
        draft,
        peering,
        Undo::RemoveExpose {
            peering,
            side,
            slot,
        },
    )
}

fn respecting_guard(draft: &mut Draft, peering: PeeringHandle, undo: Undo) -> Option<Undo> {
    let spec = draft.peerings.get(&peering)?;
    if spec.guard.legal_on(spec) {
        return Some(undo);
    }
    undo.apply(draft);
    None
}

fn set_flavour(
    draft: &mut Draft,
    peering: PeeringHandle,
    side: Side,
    slot: u8,
    flavour: Flavour,
) -> Option<Undo> {
    let spec = draft.peerings.get(&peering)?;
    if flavour.is_directional() && spec.has_directional(side.other()) {
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
    respecting_guard(
        draft,
        peering,
        Undo::SetFlavour {
            peering,
            side,
            slot,
            flavour: previous,
        },
    )
}

impl Undo {
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
            Undo::SetGuard { peering, guard } => {
                draft
                    .peerings
                    .get_mut(peering)
                    .unwrap_or_else(|| unreachable!("no peering {peering:?}"))
                    .guard = *guard;
            }
        }
    }
}

pub const MAX_SEQUENCE: u8 = 32;

#[derive(Clone, Copy, Debug)]
pub struct Sequence {
    pub len: u8,
}

impl Default for Sequence {
    fn default() -> Self {
        Self { len: 24 }
    }
}

impl Sequence {
    #[must_use]
    pub fn of(len: u8) -> Self {
        Self {
            len: len.min(MAX_SEQUENCE),
        }
    }

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
        let target = usize::from(driver.gen_u8(Included(&1), Included(&4))?);
        let mut draft = Draft::new();
        let mut next_vpc = 0u8;
        let mut next_peering = 0u8;
        let mut ops = Vec::with_capacity(usize::from(count));

        for _ in 0..count {
            let Some(op) = draw(driver, &draft, &mut next_vpc, &mut next_peering, target) else {
                break;
            };
            op.apply(&mut draft)?;
            ops.push(op);
        }

        Some(ops)
    }
}

const MENU: [(Kind, u8); 8] = [
    (Kind::AddVpc, 4),
    (Kind::RemoveVpc, 1),
    (Kind::AddPeering, 4),
    (Kind::RemovePeering, 1),
    (Kind::AddExpose, 2),
    (Kind::RemoveExpose, 1),
    (Kind::SetFlavour, 2),
    (Kind::SetGuard, 2),
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
    SetGuard,
}

impl Kind {
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
            Kind::RemovePeering | Kind::SetFlavour | Kind::SetGuard => !draft.peerings.is_empty(),
            Kind::AddExpose => sides().any(|exposes| exposes.len() < usize::from(MAX_EXPOSES)),
            Kind::RemoveExpose => sides().any(|exposes| exposes.len() > 1),
        }
    }
}

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
            Kind::SetGuard => draw_set_guard(driver, draft),
        };

        let Some(op) = built.filter(|op| op.applicable(draft)) else {
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

    let peered = components
        .iter()
        .filter(|component| component.len() > 1)
        .count();
    let left_alone = component.len() <= 1;
    let want_more = peered < target;

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

fn draw_set_guard<D: Driver>(driver: &mut D, draft: &Draft) -> Option<Op> {
    const ORDERED: [Guard; 6] = [
        Guard::Open,
        Guard::Permit,
        Guard::PermitExcept,
        Guard::PermitByProtocol,
        Guard::PermitFlow,
        Guard::Deny,
    ];

    let guard = pick(driver, &ORDERED)?;
    let willing: Vec<PeeringHandle> = draft
        .peerings()
        .filter(|(_, spec)| guard.legal_on(spec))
        .map(|(handle, _)| handle)
        .collect();

    Some(Op::SetGuard {
        peering: pick(driver, &willing)?,
        guard,
    })
}

fn draw_flavour<D: Driver>(driver: &mut D, spec: &PeeringSpec, side: Side) -> Option<Flavour> {
    const ORDERED: [Flavour; 4] = [
        Flavour::Forward,
        Flavour::StaticNat,
        Flavour::PortForward,
        Flavour::Masquerade,
    ];
    let legal: &[Flavour] = if spec.has_directional(side.other()) {
        &ORDERED[..2]
    } else {
        &ORDERED
    };
    pick(driver, legal)
}

fn pick<T: Copy, D: Driver>(driver: &mut D, items: &[T]) -> Option<T> {
    if items.is_empty() {
        return None;
    }
    let index = usize::from(driver.produce::<u8>()?) % items.len();
    items.get(index).copied()
}

impl Draft {
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
    use concurrency::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    #[test]
    fn writing_a_vpc_does_not_imply_writing_its_peerings() {
        static SEEN: AtomicUsize = AtomicUsize::new(0);

        check!()
            .with_generator(Sequence::default())
            .for_each(|ops: &Vec<Op>| {
                let mut draft = Draft::new();
                for op in ops {
                    let footprint = op.writes(&draft);
                    for vpc in &footprint.vpcs {
                        for (handle, spec) in draft.peerings() {
                            if spec.touches(*vpc) && !footprint.peerings.contains(&handle) {
                                SEEN.fetch_add(1, Relaxed);
                            }
                        }
                    }
                    op.apply(&mut draft).expect("a drawn operation applies");
                }
            });

        assert!(
            SEEN.load(Relaxed) > 0,
            "no drawn operation ever wrote a vpc while leaving one of its peerings unwritten. \
             Either the vocabulary changed and a peering-only frame filter is now sound -- in \
             which case say so where the filter is written -- or the generator stopped drawing \
             `AddPeering` against a vpc that already had one"
        );
    }

    static DRAWN: [AtomicUsize; 8] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    const KINDS: [&str; 8] = [
        "AddVpc",
        "RemoveVpc",
        "AddPeering",
        "RemovePeering",
        "AddExpose",
        "RemoveExpose",
        "SetFlavour",
        "SetGuard",
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
            Op::SetGuard { .. } => 7,
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

    #[test]
    fn every_sequence_builds_a_valid_configuration() {
        let flavours = [const { AtomicUsize::new(0) }; 4];
        let guards = [const { AtomicUsize::new(0) }; 6];

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
                            flavours[match expose.flavour() {
                                Flavour::Forward => 0,
                                Flavour::Masquerade => 1,
                                Flavour::StaticNat => 2,
                                Flavour::PortForward => 3,
                            }]
                            .fetch_add(1, Relaxed);
                        }
                    }
                }

                let overlay = draft
                    .overlay()
                    .unwrap_or_else(|e| panic!("{ops:?} does not assemble: {e}"));

                for (handle, spec) in draft.peerings() {
                    let acl = overlay
                        .peering_table
                        .values()
                        .find(|peering| peering.name == handle.name())
                        .and_then(|peering| peering.acl.as_ref());
                    let observed = acl.map_or(Guard::Open, |acl| {
                        let inert = acl
                            .rules()
                            .first()
                            .is_some_and(|rule| rule.pattern.proto == AclProtoMatch::Tcp);
                        match (acl.default_action(), acl.rules().len()) {
                            (AclAction::Deny, 1) => Guard::PermitFlow,
                            (AclAction::Deny, 3) if inert => Guard::PermitByProtocol,
                            (AclAction::Deny, 3) => Guard::PermitExcept,
                            (AclAction::Deny, _) => Guard::Permit,
                            (AclAction::Allow, _) => Guard::Deny,
                        }
                    });
                    assert_eq!(
                        observed,
                        spec.guard(),
                        "{:?} is guarded {:?} and assembled an acl reading {observed:?}",
                        handle,
                        spec.guard()
                    );
                    guards[match observed {
                        Guard::Open => 0,
                        Guard::Permit => 1,
                        Guard::PermitExcept => 2,
                        Guard::PermitByProtocol => 3,
                        Guard::PermitFlow => 4,
                        Guard::Deny => 5,
                    }]
                    .fetch_add(1, Relaxed);
                }

                if let Err(e) = overlay.validate() {
                    panic!("{ops:?} builds a configuration the validator refuses: {e}");
                }
            });

        assert_every_kind_drawn();
        assert_every_shape_built(&flavours, &guards);
    }

    const FLAVOURS: [&str; 4] = ["forward", "masquerade", "static-nat", "port-forward"];
    const GUARDS: [&str; 6] = [
        "open",
        "permit",
        "permit-except-one",
        "permit-by-protocol",
        "permit-by-flow",
        "deny",
    ];

    fn assert_every_shape_built(flavours: &[AtomicUsize; 4], guards: &[AtomicUsize; 6]) {
        let show = |names: &[&str], counts: &[AtomicUsize]| {
            names
                .iter()
                .zip(counts)
                .map(|(name, count)| format!("{name}={}", count.load(Relaxed)))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let (built, set) = (show(&FLAVOURS, flavours), show(&GUARDS, guards));
        eprintln!("exposes: {built}\nguards:  {set}");

        for (name, count) in FLAVOURS.iter().zip(flavours) {
            assert!(
                count.load(Relaxed) > 0,
                "no expose was ever {name} ({built}), so the nat combination rules were not \
                 exercised"
            );
        }
        for (name, count) in GUARDS.iter().zip(guards) {
            assert!(
                count.load(Relaxed) > 0,
                "no peering was ever left {name} ({set}), so the acl vocabulary was not exercised"
            );
        }
    }

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

    #[test]
    fn sequences_produce_disjoint_peering_components() {
        let split = AtomicUsize::new(0);
        let joined = AtomicUsize::new(0);

        check!()
            .with_generator(Sequence::default())
            .for_each(|ops| {
                let draft = Sequence::fold(ops);
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
