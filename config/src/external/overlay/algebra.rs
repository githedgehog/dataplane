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
//! Vpcs, peerings, exposes in every flavour the configuration model has, and a peering-scoped ACL
//! that either permits or denies everything the peering carries. A partially modelled algebra
//! gives partial coverage on purpose: what grows is the vocabulary, rather than a collection of
//! single-purpose generators.
//!
//! What is *not* drawn is recorded in [`completeness`](super::completeness) rather than here, and
//! that is the only place it can be kept honest: that record is checked against what drawn
//! configurations actually exhibit, and a paragraph is not.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::ops::Bound::Included;
use std::time::Duration;

use bolero::{Driver, ValueGenerator};
use lpm::prefix::with_ports::L4Protocol;
use lpm::prefix::{
    IpPrefix, Ipv4Prefix, PortRange, Prefix, PrefixPortsSet, PrefixWithOptionalPorts,
};

use crate::ConfigError;
use crate::external::overlay::Overlay;
use crate::external::overlay::acl::{Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope};
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
/// Every flavour the configuration model has. The one degree of freedom left inside them is the
/// protocol: an expose narrowed to tcp or udp is not drawn, so `VpcExposeNat.proto` stays fixed in
/// `completeness`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Flavour {
    /// No translation: the private prefix is also the public one.
    Forward,
    /// Stateful source NAT from the private prefix into the public one.
    Masquerade,
    /// Stateless one-to-one translation between the private prefix and the public one.
    ///
    /// The two blocks of the address plan are both `/24`s, which is what a static
    /// mapping needs: every private address has exactly one public address and the
    /// translation carries no state at all.  That is the whole reason it is worth
    /// having in the vocabulary next to [`Masquerade`](Self::Masquerade) -- the two
    /// answer the same question about a configuration change with and without a flow
    /// table underneath.
    StaticNat,
    /// A forwarded service: the far side opens the connection, on named ports.
    ///
    /// The only flavour whose traffic runs *inwards*, which is why it is worth having separately
    /// from [`StaticNat`](Self::StaticNat) even though both translate an address one to one. It is
    /// also the only one that puts ports in the configuration at all --
    /// [`FORWARDED_PRIVATE_PORTS`] and [`FORWARDED_PUBLIC_PORTS`] -- so it is what makes a
    /// generated prefix set something other than whole addresses.
    ///
    /// The protocol is left at `Any`, deliberately. Narrowing an expose to tcp or udp is a separate
    /// degree of freedom, and opening the flavour and narrowing the protocol at once would leave
    /// neither measured on its own -- an `Any` expose is also the one every derived load can reach.
    PortForward,
    /// Everything: a `default` expose, which names no prefix and stands for all destinations.
    ///
    /// The only flavour with no address block of its own, and the only one whose expose carries
    /// neither `ips` nor `nat` -- `VpcExpose::validate` refuses a default expose that has either.
    ///
    /// Legal only on a peering whose two vpcs have no *other* peering, which is a stronger
    /// condition than the configuration model imposes and is chosen to keep the algebra's
    /// preconditions local. A default expose produces a route that overlaps every other route the
    /// vpc sees, and two overlapping routes must agree about their gateway group and must not both
    /// be default. Both are conditions on a vpc's whole neighbourhood rather than on one peering,
    /// and a neighbourhood is exactly what a later `AddPeering` can change underneath a rule. An
    /// isolated pair has neither question to answer.
    ///
    /// No traffic is derived across such a peering: a default expose advertises no prefix, so
    /// there is no address for the far side to aim at. What it reaches is the configuration paths
    /// -- `is_default_only`, the root-prefix ACL coverage set, the default route -- rather than a
    /// packet.
    Everything,
}

impl Flavour {
    /// Whether this flavour is one a peering may carry on only one of its two sides.
    ///
    /// `VpcPeering::validate` allows no-nat and static nat opposite anything, and refuses
    /// masquerade or port forwarding opposite either of themselves. Both are directional -- one
    /// decides which way a connection may be opened -- and a peering that named both directions
    /// would not say which translation a packet is owed.
    ///
    /// Named here rather than spelled out at each guard so that the algebra's rule and the
    /// validator's rule are one sentence apiece and can be compared.
    #[must_use]
    pub const fn is_directional(self) -> bool {
        matches!(self, Self::Masquerade | Self::PortForward)
    }

    /// Whether an expose of this flavour advertises an address block at all.
    ///
    /// False only for [`Everything`](Self::Everything), which is what makes it the one flavour
    /// whose slot names no prefix.
    const fn has_prefixes(self) -> bool {
        !matches!(self, Self::Everything)
    }
}

/// What a peering's ACL does to the traffic the peering carries.
///
/// Two shapes and their absence, rather than a generated rule set, and the restraint is the whole
/// design. An ACL a property has to *evaluate* in order to know what should have happened is a
/// second copy of a decision procedure, which is the thing an oracle must not be. `acl_filter`'s
/// own generator is the rich one, and lookup and ordering are its to check. Here a rule set covers
/// the whole peering in both directions, so what the ACL does is knowable without matching
/// anything: either everything the peering carries is permitted, or none of it is.
///
/// In every shape the default action is the **opposite** of what the rules say. That is what makes
/// the rules load-bearing in either direction rather than only one: a rule table that lowered to
/// nothing would leave [`Permit`](Self::Permit) carrying nothing and [`Deny`](Self::Deny) carrying
/// everything, and each is a failure of a property rather than only the first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub enum Guard {
    /// No ACL at all. `AclFilter` finds no default action for the peering and lets traffic past.
    #[default]
    Open,
    /// Every direction named and allowed, over a default of deny.
    Permit,
    /// One direction named and allowed, authorising the other by flow membership.
    ///
    /// The only shape whose replies are not permitted by a rule of their own. `AclFilter::lookup`
    /// misses on a reply, reverses it through the flow -- undoing whatever NAT did to it, in
    /// `reverse_summary` -- and looks the *request* up instead, honouring the answer only if the
    /// rule it finds is an `Allow` at flow scope. Nothing else in the vocabulary reaches that path,
    /// and it is the one place in `acl_filter` where an ACL verdict depends on NAT.
    ///
    /// Legal only on a peering only one side of which may open a connection, which is
    /// [`PeeringSpec::sole_opener`]. Two separate things follow from that one condition and they
    /// have to agree, or this shape would be untestable: `validate_scope` accepts flow scope
    /// because such a peering's flows all reach the flow table, and every load the derivation
    /// produces opens from that one side, so a single rule covers all of them.
    PermitFlow,
    /// Everything permitted except one expose's own outgoing traffic, which a earlier rule denies.
    ///
    /// The only shape whose rules **overlap**: a packet from the named expose matches the deny and
    /// the permit both, and what happens to it is decided by which one the lookup returns. Nothing
    /// else in the vocabulary can say anything about rule order, because with at most one rule per
    /// direction no packet ever matches two.
    ///
    /// The expose it names is a masquerading one, and that is what makes the effect predictable
    /// rather than a matter of evaluating the ACL. A masquerading expose is source nat and nothing
    /// else -- `can_receive_connection` is false for one -- so no load is ever *aimed* at its
    /// addresses and no reply ever carries one as a source. Its prefix therefore appears in exactly
    /// one place in the traffic the configuration implies: as the source of its own requests.
    /// Narrow a rule to it and precisely those requests change verdict.
    PermitExcept,
    /// As [`PermitExcept`](Self::PermitExcept), except that nothing is excepted after all.
    ///
    /// The denial names a protocol the configuration's own traffic never carries, so it cannot
    /// fire; the permits that follow it name the protocol the traffic does carry, and name it by
    /// port range rather than by address. Everything is carried.
    ///
    /// The value is that the correctness here is a **negative**: a rule that must *not* fire. If
    /// the protocol were dropped on the way into the table, or lowered as a wildcard, this
    /// configuration would silence an expose and `a_generated_configuration_carries_its_own_traffic`
    /// would say so. Every other shape in this vocabulary is checked by a rule doing something.
    ///
    /// It leans on one fact about the traffic a configuration implies rather than about the
    /// configuration: every load the derivation builds is UDP. That is worth stating here because
    /// it is the whole reason `Tcp` is the protocol that cannot fire, and a load kind carrying
    /// anything else would need this rewritten rather than merely extended.
    PermitByProtocol,
    /// Every direction named and denied, over a default of allow.
    Deny,
}

impl Guard {
    /// The ACL this guard puts on a peering, or `None` for [`Guard::Open`].
    ///
    /// The rules carry empty patterns, which `AclRule::validate` fills in from the two manifests: a
    /// rule's source becomes everything its `from` side holds, and its destination everything its
    /// `to` side advertises. So the coverage follows the exposes instead of being written down
    /// here, and an expose added to a peering is inside the ACL by construction rather than by
    /// anything remembering to widen it.
    ///
    /// Packet scope, and that is what keeps this free of a legality condition. `validate_scope`
    /// refuses a flow-scoped rule on a peering carrying any expose that is neither masquerade nor
    /// port forwarding, because such a peering carries flows the flow table never sees. Flow scope
    /// is a degree of freedom of its own and drawing it means drawing that condition too.
    fn acl(self, peering: PeeringHandle, spec: &PeeringSpec) -> Option<Acl> {
        let (default, action, scope) = match self {
            Guard::Open => return None,
            Guard::Permit | Guard::PermitExcept | Guard::PermitByProtocol => {
                (AclAction::Deny, AclAction::Allow, AclScope::Packet)
            }
            Guard::PermitFlow => (AclAction::Deny, AclAction::Allow, AclScope::Flow),
            Guard::Deny => (AclAction::Allow, AclAction::Deny, AclScope::Packet),
        };
        // One rule per direction. A rule is directional -- `PeeringAclRuleSet` files it under its
        // `from` side's vni -- so a single rule would leave the reply direction to the default,
        // which is the opposite action, and neither shape would mean what it says.
        // A rule that names its protocol also names its ports, because that is the only shape in
        // which ports may be named at all: `AclPattern::validate_ports` refuses port matching on
        // any protocol but tcp and udp. The range is every port there is, so what it selects is
        // "udp, on any port" -- the `match` shape that names ports and no address, which the k8s
        // converter produces and `expand_any_ports` materialises against the manifests.
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
                // A denial is the verdict an operator wants in the log, and a permit is not. That
                // makes the field vary with the rule rather than with a draw, and it is the shape
                // a real ACL is written in.
                log: action == AclAction::Deny,
            }
        };
        let rules = match self {
            // One rule, from the side connections may be opened from. A second rule would permit
            // the reply directly and the reverse lookup would never run, which is the whole of what
            // this shape is for.
            Guard::PermitFlow => {
                vec![rule(self.opening_side(spec).unwrap_or_else(|| {
                    unreachable!("`legal_on` refused a guard with no side")
                }))]
            }
            // The denial goes **first**, and that is the whole of the shape: it names a subset of
            // what the rule after it names, so a packet from the excepted expose matches both and
            // only the order decides which answer it gets.
            Guard::PermitExcept | Guard::PermitByProtocol => {
                let (side, which, prefix) = spec
                    .exception(peering)
                    .unwrap_or_else(|| unreachable!("`legal_on` refused a guard with no expose"));
                // A source narrowing rides the rule *from* the excepted expose's side; a
                // destination narrowing rides the rule *to* it, which is the rule from the other
                // side. See `Narrowing`.
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
                    // A protocol the traffic never carries, so the denial cannot fire. See
                    // `Guard::PermitByProtocol`; the whole shape is that this rule does nothing.
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

    /// The side this guard names, for a shape that names one.
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

    /// Whether this guard may sit on this peering.
    ///
    /// The condition runs the opposite way to [`Flavour::is_directional`] -- a guard constrains the
    /// exposes rather than the other way about -- and that is faithful rather than awkward:
    /// `validate_scope` is literally a rule about which NAT modes a peering may carry given a rule's
    /// scope. So the expose operations consult this too, and an expose that would leave a peering's
    /// own ACL invalid does not apply.
    fn legal_on(self, spec: &PeeringSpec) -> bool {
        match self {
            Guard::Open | Guard::Permit | Guard::Deny => true,
            Guard::PermitFlow => spec.sole_opener().is_some(),
            Guard::PermitExcept | Guard::PermitByProtocol => spec.exception_slot().is_some(),
        }
    }

    /// Whether this guard stops `nth` expose of `side` carrying what it otherwise would.
    ///
    /// The whole of what a guard means to whoever derives traffic, and it lives here so that
    /// nobody downstream has to read an ACL to find out. Stated per expose rather than per peering
    /// because [`Guard::PermitExcept`] is: it is the one shape under which two exposes of one
    /// peering get different answers.
    fn silences(self, spec: &PeeringSpec, side: Side, nth: usize) -> bool {
        match self {
            // `PermitByProtocol` sits here rather than beside the `PermitExcept` it is otherwise
            // shaped like: its denial names a protocol the traffic does not carry, so the rule
            // cannot fire and the expose it names is carried after all.
            Guard::Open | Guard::Permit | Guard::PermitFlow | Guard::PermitByProtocol => false,
            Guard::Deny => true,
            Guard::PermitExcept => spec
                .exception_slot()
                .is_some_and(|(at, which, _)| (at, which) == (side, nth)),
        }
    }
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

/// How long an expose that names an idle timeout asks its flows to live.
///
/// Far longer than any property here runs, deliberately. Nothing in this harness advances a clock,
/// so a timeout short enough to fire would fire at a moment decided by how fast the machine is --
/// which is a flaky test, not a test of expiry. What a configuration carrying a timeout is under
/// test for *here* is that it lowers, and that it carries its traffic exactly as one without does.
/// Expiry itself wants the paused clock, and `nat::masquerade::expiry` is where that lives.
const LONG_IDLE_TIMEOUT: Duration = Duration::from_hours(1);

impl PeeringHandle {
    fn name(self) -> String {
        format!("PEERING-{:03}", self.0)
    }

    /// The gateway group this peering is served by.
    ///
    /// Three groups over however many peerings, so that some peerings share one and some do not.
    /// A group constrains only *overlapping* exposes -- `VpcRouteSet::validate` refuses two
    /// overlapping routes in different groups -- and the address plan gives every expose a block
    /// of its own, so nothing generated can reach that rule. Which is worth saying plainly: this
    /// makes the field vary, and the rule that gives it meaning stays out of reach.
    fn group(self) -> String {
        format!("group-{}", self.0 % 3)
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

/// The private ports a forwarded service listens on.
///
/// A range rather than one port, so the mapping has an offset to preserve -- which is what a
/// derived load reads it as.
pub(crate) const FORWARDED_PRIVATE_PORTS: (u16, u16) = (1000, 1004);

/// The public ports a forwarded service is reached at.
///
/// The **same width** as [`FORWARDED_PRIVATE_PORTS`], and deliberately not the same numbers. Equal
/// width is a requirement rather than a tidiness: the two sides of a translation are one flat list
/// of (address, port) pairs, so unequal widths would stop the mapping being offset-preserving in
/// the address, and a load that reads the mapping off the two prefixes would then be wrong with
/// nothing saying so. Different numbers are what makes a test that confuses the two sides fail
/// rather than pass.
pub(crate) const FORWARDED_PUBLIC_PORTS: (u16, u16) = (2000, 2004);

/// Every port a load could send from or to.
///
/// One rather than zero at the bottom: a load's ports come from `Vary`, which floors them at one,
/// and a range that reached zero would claim coverage of a port no generated traffic uses.
const EVERY_PORT: (u16, u16) = (1, u16::MAX);

fn port_range((start, end): (u16, u16)) -> PortRange {
    PortRange::new(start, end).unwrap_or_else(|_| unreachable!("a well-formed port range"))
}

/// The base of the private range, `10.0.0.0/8`.
const PRIVATE_BASE: u32 = 0x0A00_0000;

/// The base of the public range, `172.16.0.0/12`.
const PUBLIC_BASE: u32 = 0xAC10_0000;

/// The private prefix of block `index`, a `/24` inside `10.0.0.0/8`.
fn private_prefix(index: u32) -> Prefix {
    prefix_v4(PRIVATE_BASE | (index << 8), 24)
}

/// The public prefix of block `index`, a `/24` inside `172.16.0.0/12`.
///
/// A separate range from the private one so that a masquerade expose's two sides cannot collide,
/// and so that a forward expose in one peering cannot collide with a masquerade expose's public
/// side in another.
fn public_prefix(index: u32) -> Prefix {
    prefix_v4(PUBLIC_BASE | (index << 8), 24)
}

/// The slice an expose carves out of the middle of a block.
///
/// A **middle** slice rather than a half, because what an exclusion is for is making a prefix set
/// non-contiguous: `10.0.b.0/24` less `10.0.b.64/26` is two prefixes, `10.0.b.0/26` and
/// `10.0.b.128/25`, and two prefixes is what a matcher, an lpm table and `RangeBuilder` each have
/// to handle and might not. Taking a half would leave one prefix and prove nothing.
///
/// Nothing generated is *aimed* at an excluded address: the derivation reads its addresses off the
/// effective set, so it stays inside the first of the two prefixes. That is a real limit and the
/// census row says so -- a matcher that ignored exclusions entirely would still carry every load.
/// What is under test here is the shape of the set, not the hole in it.
fn excluded_slice(index: u32, base: u32) -> Prefix {
    prefix_v4(base | (index << 8) | 0x40, 26)
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

    /// Whether this expose names an idle timeout for the flows it opens.
    ///
    /// By slot rather than drawn, so a manifest with more than one expose has both answers in it
    /// at once -- which is the shape that would catch a lowering that read one expose's timeout
    /// and applied it to its neighbours. See [`LONG_IDLE_TIMEOUT`] for why the value is inert.
    fn idle_timeout(self) -> Option<Duration> {
        (self.slot % 2 == 1).then_some(LONG_IDLE_TIMEOUT)
    }

    /// Which transport protocol this expose's translation applies to.
    ///
    /// Only port forwarding can say -- `make_port_forwarding` is the one constructor that takes a
    /// protocol -- so only port forwarding varies here.
    ///
    /// By slot, and cycling through all three, so that a manifest holding several port-forwarded
    /// exposes holds several answers. That is the shape worth having rather than a nicety: the
    /// port forwarding table is keyed in part by protocol, and exposes that agree on it are the
    /// ones whose keys can collide.
    fn nat_proto(self) -> Option<L4Protocol> {
        match self.flavour {
            Flavour::PortForward => Some(match self.slot % 3 {
                0 => L4Protocol::Any,
                1 => L4Protocol::Udp,
                _ => L4Protocol::Tcp,
            }),
            Flavour::Forward | Flavour::Masquerade | Flavour::StaticNat | Flavour::Everything => {
                None
            }
        }
    }

    /// Whether this expose carves a slice out of the ranges it advertises.
    ///
    /// By slot, and on the low slots, so a manifest holding several exposes holds both answers.
    /// Never for port forwarding: `VpcExpose::validate` refuses exclusions on a forwarded expose
    /// outright, which is a rule worth having the algebra respect rather than discover.
    ///
    /// The slot rule is chosen to be independent of [`ExposeSpec::idle_timeout`]'s, so that all
    /// four combinations of the two appear across the four slots rather than only two.
    fn excludes(self) -> bool {
        self.slot < 2
            && matches!(
                self.flavour,
                Flavour::Forward | Flavour::Masquerade | Flavour::StaticNat
            )
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
            Flavour::Forward | Flavour::Everything => self.private(peering, side),
            Flavour::Masquerade | Flavour::StaticNat | Flavour::PortForward => {
                public_prefix(peering.block(side, self.slot))
            }
        }
    }

    /// Carve this expose's slice out of both of its ranges, if it has one.
    ///
    /// Both ranges and by the same shape, which static NAT requires and everything else merely
    /// tolerates: `VpcExpose::validate` refuses a static mapping whose two sides hold different
    /// numbers of addresses, and cutting one side alone would build exactly that.
    fn carve(self, expose: VpcExpose, peering: PeeringHandle, side: Side) -> VpcExpose {
        if !self.excludes() {
            return expose;
        }
        let block = peering.block(side, self.slot);
        let expose = expose.not(excluded_slice(block, PRIVATE_BASE).into());
        if expose.nat.is_none() {
            return expose;
        }
        expose
            .not_as(excluded_slice(block, PUBLIC_BASE).into())
            .unwrap_or_else(|_| unreachable!("a translating expose accepts an excluded range"))
    }

    fn expose(self, peering: PeeringHandle, side: Side) -> VpcExpose {
        let private = self.private(peering, side);
        match self.flavour {
            Flavour::Everything => VpcExpose::empty().set_default(),
            Flavour::Forward => self.carve(VpcExpose::empty().ip(private.into()), peering, side),
            Flavour::Masquerade => self.carve(
                VpcExpose::empty()
                    .make_masquerade(self.idle_timeout())
                    .unwrap_or_else(|_| unreachable!("an empty expose accepts masquerade"))
                    .ip(private.into())
                    .as_range(self.public(peering, side).into())
                    .unwrap_or_else(|_| unreachable!("a masquerade expose accepts a public range")),
                peering,
                side,
            ),
            Flavour::StaticNat => self.carve(
                VpcExpose::empty()
                    .make_static_nat()
                    .unwrap_or_else(|_| unreachable!("an empty expose accepts static nat"))
                    .ip(private.into())
                    .as_range(self.public(peering, side).into())
                    .unwrap_or_else(|_| unreachable!("a static nat expose accepts a public range")),
                peering,
                side,
            ),
            Flavour::PortForward => VpcExpose::empty()
                // `None` protocol leaves the expose at `Any`; see `Flavour::PortForward`.
                .make_port_forwarding(self.idle_timeout(), self.nat_proto())
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

/// Which end of a rule a narrowed exception names, and therefore which rule carries it.
///
/// Both are the same trick from opposite ends: name a prefix that appears in the traffic the
/// configuration implies in exactly *one* place, so that narrowing a rule to it changes exactly one
/// thing and no evaluation is needed to say which.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Narrowing {
    /// The private prefix of a masquerading expose, on the rule *from* its side.
    ///
    /// Nothing is ever aimed at a masquerading expose -- `can_receive_connection` is false for one
    /// -- so its private prefix is the source of its own requests and of nothing else.
    Source,
    /// The public prefix of a port-forwarding expose, on the rule *to* its side.
    ///
    /// The mirror image: a port-forwarding expose is reached and never reaches, so its public
    /// prefix is the destination of the traffic aimed at it and of nothing else.
    Destination,
}

impl Narrowing {
    fn of(flavour: Flavour) -> Option<Self> {
        match flavour {
            Flavour::Masquerade => Some(Self::Source),
            Flavour::PortForward => Some(Self::Destination),
            Flavour::Forward | Flavour::StaticNat | Flavour::Everything => None,
        }
    }
}

/// One peering and both its manifests.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeeringSpec {
    left: VpcHandle,
    right: VpcHandle,
    exposes: [Vec<ExposeSpec>; 2],
    guard: Guard,
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

    /// What this peering's ACL does to its traffic.
    ///
    /// Read by whoever derives traffic from the configuration, because a guard decides whether
    /// there is any to derive. The assembled configuration says the same thing, but only by
    /// evaluating an ACL against the manifests -- which is the reading this exists to avoid.
    #[must_use]
    pub fn guard(&self) -> Guard {
        self.guard
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

    /// The one side connections may be opened from, where only one side may open them.
    ///
    /// A side whose exposes are *all* masquerade opens everything the peering carries: masquerade
    /// is source nat and nothing else, `can_receive_connection` is false for one, and so nothing
    /// aims traffic at it. A side whose exposes are all port forwarding is the mirror image -- it
    /// is reached and never reaches -- so its peer is the opener. Any other side leaves both
    /// directions open and has no answer here: one with both flavours at once, or with anything
    /// that neither translates nor is reached on named ports.
    ///
    /// At most one side ever answers, because [`Flavour::is_directional`] keeps both flavours off
    /// both sides of a peering at once. See [`Guard::PermitFlow`] for what it is asked for.
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

    /// The expose a rule may be narrowed to, where it lives, and which end of a rule names it.
    ///
    /// The *first* directional expose of whichever side has one, by position in the manifest --
    /// which is the order [`PeeringSpec::manifest`] folds them in and the order a validated
    /// manifest keeps them in, so "the first" means the same thing to whoever reads the assembled
    /// configuration. Slot order would not: a slot freed by a removal is refilled by the next
    /// addition, which lands at the end.
    ///
    /// At most one side has a directional expose at all -- [`Flavour::is_directional`] -- so there
    /// is nothing to choose between.
    fn exception_slot(&self) -> Option<(Side, usize, Narrowing)> {
        [Side::Left, Side::Right].into_iter().find_map(|side| {
            self.exposes(side)
                .iter()
                .enumerate()
                .find_map(|(nth, expose)| Some((side, nth, Narrowing::of(expose.flavour)?)))
        })
    }

    /// [`PeeringSpec::exception_slot`], resolved to the prefix a rule would name.
    fn exception(&self, peering: PeeringHandle) -> Option<(Side, Narrowing, Prefix)> {
        let (side, nth, which) = self.exception_slot()?;
        let expose = self.exposes(side)[nth];
        let prefix = match which {
            Narrowing::Source => expose.private(peering, side),
            Narrowing::Destination => expose.public(peering, side),
        };
        Some((side, which, prefix))
    }

    /// Whether `side` already exposes everything.
    fn has_everything(&self, side: Side) -> bool {
        self.exposes(side)
            .iter()
            .any(|expose| expose.flavour == Flavour::Everything)
    }

    /// Whether `side` carries a flavour that forbids one on the other side.
    ///
    /// See [`Flavour::is_directional`] for which, and why.
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

    /// The guard on the peering that [`Draft::overlay`] calls `name`.
    ///
    /// By name rather than by handle, for the reason [`Footprint::touches_vpc_named`] gives:
    /// handles do not leave this module, and a caller deriving traffic from an assembled
    /// configuration knows only names. `None` for a name no peering has.
    ///
    /// Asked at all because a guard decides whether a peering carries anything, and a derivation
    /// that read that off the assembled ACL would be evaluating one -- which is what
    /// [`Guard`] exists to keep nobody having to do.
    /// Whether the peering [`Draft::overlay`] calls `peering` carries what the `nth` expose of the
    /// side named `local` would otherwise carry.
    ///
    /// The one question a caller deriving traffic has to ask about a guard, answered here so that
    /// nobody downstream reads an ACL to answer it -- reading one means matching its rules against
    /// the manifests, and a second copy of a decision procedure is what an oracle must not be.
    ///
    /// Per expose, because [`Guard::PermitExcept`] is the one shape under which two exposes of one
    /// peering get different answers. By name and position for the reason [`Draft::guard_named`]
    /// gives.
    ///
    /// Only the ACL. An expose narrowed to a transport protocol the traffic does not carry is a
    /// different thing and not this one: it still *routes* its prefix, and only declines to
    /// translate, so the configuration carries that traffic in the sense this question asks about.
    /// Whoever derives traffic skips such an expose because there is no outcome it can state, not
    /// because the configuration refuses it.
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

    /// How many peerings name `vpc`.
    fn peerings_of(&self, vpc: VpcHandle) -> usize {
        self.peerings
            .values()
            .filter(|spec| spec.touches(vpc))
            .count()
    }

    /// Whether `vpc` already takes part in a peering that exposes everything.
    ///
    /// Asked by `AddPeering`, because [`Flavour::Everything`]'s precondition is about a vpc's whole
    /// neighbourhood: a peering added beside a default expose would break a rule that held when
    /// the expose was drawn. The other direction -- refusing the expose when the neighbourhood is
    /// already busy -- is [`PeeringSpec::may_expose_everything`].
    fn beside_everything(&self, vpc: VpcHandle) -> bool {
        self.peerings.values().any(|spec| {
            spec.touches(vpc)
                && [Side::Left, Side::Right]
                    .into_iter()
                    .any(|side| spec.has_everything(side))
        })
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

    /// Whether this footprint names the vpc that [`Draft::overlay`] calls `name`.
    ///
    /// Handles do not leave this module, and this is why they do not have to. A frame condition is
    /// checked against traffic, traffic is derived from an assembled configuration, and an
    /// assembled configuration knows only names -- so the projection a caller needs is "is this
    /// name inside the footprint", not the handle itself.
    #[must_use]
    pub fn touches_vpc_named(&self, name: &str) -> bool {
        self.vpcs.iter().any(|vpc| vpc.name() == name)
    }

    /// Whether this footprint names the peering that [`Draft::overlay`] calls `name`.
    ///
    /// See [`Footprint::touches_vpc_named`]. Both are needed and neither implies the other:
    /// `AddExpose` writes a peering and no vpc at all, so filtering on vpcs alone would admit
    /// traffic on the very peering that changed.
    #[must_use]
    pub fn touches_peering_named(&self, name: &str) -> bool {
        self.peerings.iter().any(|peering| peering.name() == name)
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
    /// Put a peering-scoped ACL on a peering, replace the one it has, or take it away.
    SetGuard {
        peering: PeeringHandle,
        guard: Guard,
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
    SetGuard {
        peering: PeeringHandle,
        guard: Guard,
    },
}

impl Op {
    /// The state this operation needs, which is the same thing as its precondition.
    ///
    /// Takes a draft, and used not to. The note that stood here said every read set in the
    /// vocabulary was determined by the operation's own arguments, that this was not a law, and
    /// that the argument should be added back rather than contorting an operation to fit.
    /// [`Flavour::Everything`] is what made it not a law: a vpc already in a peering that exposes
    /// everything takes no others, so whether two vpcs may be peered is a fact about the *exposes*
    /// of the peerings they are already in, and not only about their peer sets.
    ///
    /// `independent_operations_commute` is what found this, by reporting an `AddPeering` and a
    /// `SetFlavour` as independent when swapping them changed whether the peering could be made at
    /// all. Widening the write set of every expose operation instead would have said something
    /// false -- changing an expose does not change any vpc's peer set -- and would have cost every
    /// swap those operations take part in.
    #[must_use]
    pub fn reads(&self, draft: &Draft) -> Footprint {
        match self {
            // Nothing: a fresh handle is nobody else's, and removal reads nothing it does not also
            // write.
            Op::AddVpc(_) | Op::RemoveVpc(_) | Op::RemovePeering(_) => Footprint::default(),
            // Both endpoints, because whether they may be peered is a fact about their peer sets --
            // and every peering those endpoints are already in, because it is also a fact about
            // what those peerings expose.
            Op::AddPeering { left, right, .. } => Footprint::of(
                [*left, *right],
                draft
                    .peerings()
                    .filter(|(_, spec)| spec.touches(*left) || spec.touches(*right))
                    .map(|(handle, _)| handle),
            ),
            Op::RemoveExpose { peering, .. } | Op::SetGuard { peering, .. } => {
                Footprint::of([], [*peering])
            }
            // The peering, and -- for an expose that would stand for everything -- the two vpcs
            // as well, because whether one is allowed is a fact about their whole neighbourhoods.
            // See `Flavour::Everything`.
            Op::AddExpose {
                peering, flavour, ..
            }
            | Op::SetFlavour {
                peering, flavour, ..
            } => {
                let mut footprint = Footprint::of([], [*peering]);
                if *flavour == Flavour::Everything
                    && let Some(spec) = draft.peerings.get(peering)
                {
                    footprint.vpcs.insert(spec.left);
                    footprint.vpcs.insert(spec.right);
                }
                footprint
            }
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
            | Op::SetFlavour { peering, .. }
            | Op::SetGuard { peering, .. } => Footprint::of([], [*peering]),
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
                    // A vpc in a peering that exposes everything takes no others; see
                    // `Flavour::Everything`.
                    || draft.beside_everything(left)
                    || draft.beside_everything(right)
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
                        // Peerings arrive unguarded, so that putting an ACL on one is an operation
                        // whose effect a property can observe rather than a fact of the fixture.
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
    if flavour.is_directional() && spec.has_directional(side.other()) {
        return None;
    }
    if flavour == Flavour::Everything && !may_expose_everything(draft, peering, side) {
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

/// Keep a change to a peering's exposes only if the peering's own guard survives it.
///
/// Applied and rolled back rather than tested first, because "would this leave the guard legal"
/// takes the same work as doing it: the condition is over the resulting exposes. Rolling back
/// through the undo the operation was about to return is also the one way to be sure the two agree
/// -- a separately written revert is a second thing to keep correct.
fn respecting_guard(draft: &mut Draft, peering: PeeringHandle, undo: Undo) -> Option<Undo> {
    let spec = draft.peerings.get(&peering)?;
    if spec.guard.legal_on(spec) {
        return Some(undo);
    }
    undo.apply(draft);
    None
}

/// Whether `side` of `peering` may take on a [`Flavour::Everything`] expose.
///
/// Three conditions, all local reads of the draft, and all three are the configuration model's
/// rules restated where they can be made unrepresentable rather than checked. A manifest holds at
/// most one default expose; a peering may not have one on both sides; and the two vpcs must have
/// no other peering, for the reason [`Flavour::Everything`] gives.
fn may_expose_everything(draft: &Draft, peering: PeeringHandle, side: Side) -> bool {
    let Some(spec) = draft.peerings.get(&peering) else {
        return false;
    };
    !spec.has_everything(side)
        && !spec.has_everything(side.other())
        && [Side::Left, Side::Right]
            .into_iter()
            .all(|which| draft.peerings_of(spec.vpc(which)) == 1)
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
    if flavour.is_directional() && spec.has_directional(side.other()) {
        return None;
    }
    let index = spec.exposes(side).iter().position(|e| e.slot == slot)?;
    if flavour == Flavour::Everything
        && spec.exposes(side)[index].flavour != Flavour::Everything
        && !may_expose_everything(draft, peering, side)
    {
        return None;
    }
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
            Kind::RemovePeering | Kind::SetFlavour | Kind::SetGuard => !draft.peerings.is_empty(),
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
            Kind::SetGuard => draw_set_guard(driver, draft),
        };

        // Filtered rather than trusted. Each `draw_*` avoids the preconditions it knows about, so
        // this is usually redundant -- but `Sequence::generate` discards the *whole* sequence when
        // an op does not apply, so a precondition one of them has not learned about is expensive
        // and silent. A guard constrains the exposes (see `Guard::legal_on`), which is a condition
        // no draw over exposes can see from its own arguments.
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
        flavour: draw_flavour(
            driver,
            spec,
            side,
            may_expose_everything(draft, peering, side),
        )?,
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

    // Already being everything is not a reason to refuse becoming it again, and
    // `may_expose_everything` counts the expose itself; the same latitude `Op::SetFlavour` has
    // elsewhere.
    let already = spec
        .exposes(side)
        .iter()
        .any(|expose| expose.slot == slot && expose.flavour == Flavour::Everything);
    Some(Op::SetFlavour {
        peering,
        side,
        slot,
        flavour: draw_flavour(
            driver,
            spec,
            side,
            already || may_expose_everything(draft, peering, side),
        )?,
    })
}

/// A guard, and a peering that will accept it.
///
/// The guard is drawn *first*, and that order is the whole of what makes the flow-scoped shape
/// reachable. `Guard::PermitFlow` is legal on about one peering in twenty -- it needs a side only
/// one end of which may open a connection -- so drawing the peering first spends nineteen
/// twentieths of the draws that ask for it on peerings that refuse it, and the reverse lookup in
/// `AclFilter::lookup`, which nothing else in the vocabulary reaches, would rest on a handful of
/// cases per run. Measured over one run of `every_sequence_builds_a_valid_configuration`: 53
/// flow-scoped peerings drawing the peering first, 124 biasing that pick towards peerings that
/// accept every guard, 188 this way.
///
/// A guard no peering will accept refuses the draw rather than falling back to one they will.
/// Falling back is what the note on [`draw`] warns about: whichever guard it fell back to would
/// absorb the refused draws and the drawn distribution would stop being the one written here.
fn draw_set_guard<D: Driver>(driver: &mut D, draft: &Draft) -> Option<Op> {
    // Ordered least-constraining first, so that the byte `pick` reduces towards the peering that
    // carries its traffic with nothing in the way.
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
fn draw_flavour<D: Driver>(
    driver: &mut D,
    spec: &PeeringSpec,
    side: Side,
    everything: bool,
) -> Option<Flavour> {
    // Ordered simplest-first, so that the byte `pick` reduces towards the least translating expose
    // -- and with the flavours that carry a legality condition last, so that they are what falls
    // off the end when the condition fails.
    const ORDERED: [Flavour; 5] = [
        Flavour::Forward,
        Flavour::StaticNat,
        Flavour::PortForward,
        Flavour::Masquerade,
        Flavour::Everything,
    ];
    let end = if everything { 5 } else { 4 };
    let legal = if spec.has_directional(side.other()) {
        &ORDERED[..2]
    } else {
        &ORDERED[..end]
    };
    pick(driver, legal)
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
    use concurrency::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    /// An operation can write a vpc without writing every peering that vpc takes part in.
    ///
    /// Asserted as a *positive* -- that such an operation is drawn -- because it is the reason a
    /// frame condition over traffic has to be filtered three ways, by both endpoint vpcs and by
    /// the peering, rather than by the peering alone.
    ///
    /// `AddPeering(P, A, B)` is the case. Its write set has `A` and `B`, because each one's peer
    /// set changes, and the single peering `P`. Any peering `A` already had is therefore *inside*
    /// the write set through `A` and outside it by peering name, so a filter that consulted only
    /// peering names would assert the frame over traffic the footprint says the operation may
    /// change.
    ///
    /// Whether it *does* change it is a sharper question and a better property -- "adding a
    /// peering for one vpc changed nothing observable for another" is the design note's isolation
    /// claim -- but it is not this one, and conflating them would turn a legitimate behaviour
    /// change into a reported defect.
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

    /// How many sequences reached each kind of operation.
    ///
    /// The draw falls through to the next kind when one has nothing to work on, and falls all the
    /// way back to `AddVpc` when none of them does, so an operation being *in* the vocabulary is no
    /// evidence at all that it is ever drawn. Without these a change that made removals
    /// unreachable -- the exact thing the design note warns the algebra will drift towards -- would
    /// leave every property here green.
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
        let flavours = [const { AtomicUsize::new(0) }; 5];
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
                                Flavour::Everything => 4,
                            }]
                            .fetch_add(1, Relaxed);
                        }
                    }
                }

                let overlay = draft
                    .overlay()
                    .unwrap_or_else(|e| panic!("{ops:?} does not assemble: {e}"));

                // Counted off the assembled configuration rather than off the draft, and the
                // difference is the whole value of the counter: a `Guard::acl` that had stopped
                // building an ACL would leave a draft-side count untouched and green. What is
                // asserted is the mapping -- each guard produces the acl it claims to -- and what
                // is counted is what the configuration ended up with.
                for (handle, spec) in draft.peerings() {
                    let acl = overlay
                        .peering_table
                        .values()
                        .find(|peering| peering.name == handle.name())
                        .and_then(|peering| peering.acl.as_ref());
                    // The default is the opposite of what the rules say; the rule count and the
                    // first rule's protocol tell the permitting shapes apart. See `Guard`.
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

    /// The names of the two vocabularies above, in the order they are counted in.
    const FLAVOURS: [&str; 5] = [
        "forward",
        "masquerade",
        "static-nat",
        "port-forward",
        "everything",
    ];
    const GUARDS: [&str; 6] = [
        "open",
        "permit",
        "permit-except-one",
        "permit-by-protocol",
        "permit-by-flow",
        "deny",
    ];

    /// Report what shapes a run built, and fail if it built any of them not at all.
    ///
    /// Printed as well as asserted, because the counts are how a reader tells "reached" from
    /// "reached often enough to be worth anything": `permit-by-flow` needs a peering only one end
    /// of which may open a connection, and runs at a fraction of its neighbours' rate for that
    /// reason -- see [`draw_set_guard`].
    ///
    /// The two vocabularies fail for different reasons and so are asserted separately. An expose
    /// flavour never built means the nat combination rules were never exercised; a guard never set
    /// means a validator rule was not -- the one filling an empty ACL pattern in from the
    /// manifests.
    fn assert_every_shape_built(flavours: &[AtomicUsize; 5], guards: &[AtomicUsize; 6]) {
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
        let (rw1, ww1) = (first.reads(draft), first.writes(draft));
        let (rw2, ww2) = (second.reads(draft), second.writes(draft));
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
