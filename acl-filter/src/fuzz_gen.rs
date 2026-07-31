// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fuzz generators for the ACL property tests: valid-by-construction overlays carrying generated
//! ACLs, and packet summaries biased to land inside the generated prefixes.
//!
//! bolero generates a compact [`OverlaySpec`] (so shrinking operates on structure, not on whole
//! configs); [`OverlaySpec::build`] normalizes it into a configuration that satisfies every
//! validation rule and then runs the *real* validation. A rejection is itself a finding: either the
//! generator's model of the rules or the config rules themselves drifted.
//!
//! This deliberately duplicates the skeleton of `flow-filter`'s `fuzz_gen` rather than sharing it.
//! The two want opposite things from their prefixes: the flow-filter needs a pool of *disjoint*
//! blocks so that expose overlaps only ever arise where it injects them, while ACL rules are all
//! about *overlapping* matches, since that is what first-match ordering has to resolve. Sharing
//! would force one of them into the other's prefix discipline.
//!
//! What the entropy goes into, therefore, is the ACL: rule count, order, direction, action, scope,
//! protocol, and overlapping address/port patterns. The peering skeleton stays deliberately plain
//! (one expose per side, plain or masquerade) because peering shape is what the flow-filter suite
//! varies, and the ACL lowering only reads a manifest for coverage validation.
//!
//! Deliberately out of scope: rules whose prefixes disagree in IP version with their peering.
//! Those cannot survive validation -- `validate_patterns_coverage` intersects every pattern with
//! the manifest's own (single-version) coverage set and rejects an empty result -- so the
//! `filter_map` in `lower_rules` that would silently drop them is unreachable from a validated
//! config.

#![cfg(test)]

use crate::PacketSummary;
use bolero::TypeGenerator;
use config::external::overlay::acl::{
    Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope,
};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use lpm::prefix::{PortRange, Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use net::vxlan::Vni;
use std::net::IpAddr;

/// The three VPCs every generated overlay contains.
pub(crate) const VNIS: [u32; 3] = [100, 200, 300];
/// A VNI no generated VPC uses; probes drawing it must find no rule and no default.
const BOGUS_VNI: u32 = 999;

/// Peering slot `i`, when present, connects this fixed VPC pair. Distinct pairs by construction, so
/// the one-peering-per-VPC-pair rule always holds. Three slots over three VPCs means a generated
/// overlay can carry every directed pair, which is what exercises the per-(src, dst) default-action
/// map and the directional rule split.
const PEERING_PAIRS: [(usize, usize); 3] = [(0, 1), (0, 2), (1, 2)];

pub(crate) fn vni(id: u32) -> Vni {
    Vni::new_checked(id).unwrap_or_else(|e| unreachable!("{id} is a valid VNI: {e:?}"))
}

// -------------------------------------------------------------------------------------------------
// Prefix pool.
//
// Block `n` owns the private/public prefixes below, and one block is allocated per (peering, side),
// so no two manifests in an overlay ever advertise the same range. Within a block, rule patterns
// deliberately overlap: that is the whole point of the ACL suite.

fn private_block(n: u8, v6: bool) -> String {
    if v6 {
        format!("2001:db8:0:{n:x}::/120")
    } else {
        format!("10.{n}.0.0/24")
    }
}

fn public_block(n: u8, v6: bool) -> String {
    if v6 {
        format!("2001:db9:0:{n:x}::/120")
    } else {
        format!("20.{n}.0.0/24")
    }
}

/// An address inside block `n` (hosts beyond a block's populated range are still useful probes:
/// they land in the block's prefix but nowhere near a host rule).
pub(crate) fn block_addr(n: u8, host: u8, public: bool, v6: bool) -> IpAddr {
    if v6 {
        let net = if public { "db9" } else { "db8" };
        format!("2001:{net}:0:{n:x}::{host:x}")
            .parse()
            .unwrap_or_else(|e| unreachable!("generated v6 address must parse: {e}"))
    } else {
        let net = if public { 20 } else { 10 };
        format!("{net}.{n}.0.{host}")
            .parse()
            .unwrap_or_else(|e| unreachable!("generated v4 address must parse: {e}"))
    }
}

// -------------------------------------------------------------------------------------------------
// Rule pattern selectors.

/// Which part of a block one pattern entry covers. Every variant intersects the block, so pattern
/// coverage validation always passes; the variants overlap each other, which is what makes rule
/// order observable.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum PrefixSel {
    /// The whole block.
    Block,
    /// The block's lower half (`/25`, or `/121` for v6).
    LowerHalf,
    /// The block's upper half.
    UpperHalf,
    /// A single host inside the block.
    Host(u8),
}

impl PrefixSel {
    /// The prefix this selector names inside block `n`.
    fn resolve(self, n: u8, public: bool, v6: bool) -> Prefix {
        let block = if public {
            public_block(n, v6)
        } else {
            private_block(n, v6)
        };
        let text = match (self, v6) {
            (PrefixSel::Block, _) => block,
            (PrefixSel::LowerHalf, false) => block.replace("/24", "/25"),
            (PrefixSel::UpperHalf, false) => block.replace(".0.0/24", ".0.128/25"),
            (PrefixSel::LowerHalf, true) => block.replace("/120", "/121"),
            (PrefixSel::UpperHalf, true) => block.replace("::/120", "::80/121"),
            (PrefixSel::Host(h), false) => block.replace(".0.0/24", &format!(".0.{h}/32")),
            (PrefixSel::Host(h), true) => block.replace("::/120", &format!("::{h:x}/128")),
        };
        Prefix::from(text.as_str())
    }
}

/// One side of a rule's pattern.
///
/// [`SideSel::Two`] is the reason this is not just a `PrefixSel`: the lowering expands a rule into
/// one table rule per (source entry x destination entry) pair, and with single-entry patterns that
/// expansion is the identity -- a lowering that dropped every entry but the first would pass
/// unnoticed. Two entries per side make the cross product observable.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum SideSel {
    /// No prefixes at all: validation substitutes the manifest's whole coverage set.
    All,
    One(PrefixSel),
    Two(PrefixSel, PrefixSel),
}

impl SideSel {
    fn resolve(self, n: u8, public: bool, v6: bool) -> Vec<Prefix> {
        match self {
            SideSel::All => Vec::new(),
            SideSel::One(a) => vec![a.resolve(n, public, v6)],
            SideSel::Two(a, b) => {
                vec![a.resolve(n, public, v6), b.resolve(n, public, v6)]
            }
        }
    }
}

/// A rule's port constraint. Only TCP and UDP rules may carry one (config rejects port matching on
/// any other protocol), so this is forced to `None` during normalization for the rest.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum PortSel {
    None,
    /// The well-known range.
    Low,
    /// The ephemeral range.
    High,
    /// A single port in the middle of the well-known range, so it nests inside `Low`.
    Single(u8),
}

impl PortSel {
    fn resolve(self) -> Option<PortRange> {
        let range = |lo: u16, hi: u16| {
            PortRange::new(lo, hi).unwrap_or_else(|e| unreachable!("valid port range: {e:?}"))
        };
        match self {
            PortSel::None => None,
            PortSel::Low => Some(range(1, 1023)),
            PortSel::High => Some(range(1024, u16::MAX)),
            PortSel::Single(k) => {
                let port = 500 + u16::from(k);
                Some(range(port, port))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum ProtoSel {
    Any,
    Tcp,
    Udp,
    /// A protocol named by number. `Other(6)` / `Other(17)` deliberately alias TCP / UDP: two
    /// spellings of the same match must lower identically.
    Other(u8),
}

impl ProtoSel {
    fn to_config(self) -> AclProtoMatch {
        match self {
            ProtoSel::Any => AclProtoMatch::Any,
            ProtoSel::Tcp => AclProtoMatch::Tcp,
            ProtoSel::Udp => AclProtoMatch::Udp,
            ProtoSel::Other(p) => AclProtoMatch::Other(p),
        }
    }

    /// Whether config permits a port constraint alongside this protocol.
    fn allows_ports(self) -> bool {
        matches!(self, ProtoSel::Tcp | ProtoSel::Udp)
    }
}

// -------------------------------------------------------------------------------------------------
// Specs.

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct RuleSpec {
    /// Apply the rule to the reverse direction (remote -> local) rather than local -> remote. The
    /// lowering keeps a rule only on the visit from its `from` VPC, so both must be generated.
    reverse: bool,
    allow: bool,
    /// `scope: flow` (as opposed to `scope: packet`). Config only permits it when one whole side of
    /// the peering is masquerade or port forwarding, which normalization arranges.
    flow_scope: bool,
    log: bool,
    proto: ProtoSel,
    src: SideSel,
    dst: SideSel,
    src_ports: PortSel,
    dst_ports: PortSel,
}

/// The rule an ACL falls back to when the spec generated none (an ACL with no rules is rejected by
/// config validation).
const FALLBACK_RULE: RuleSpec = RuleSpec {
    reverse: false,
    allow: true,
    flow_scope: false,
    log: false,
    proto: ProtoSel::Any,
    src: SideSel::All,
    dst: SideSel::All,
    src_ports: PortSel::None,
    dst_ports: PortSel::None,
};

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct AclSpec {
    default_allow: bool,
    /// Up to four rules, in order. Order is precedence, so this is the axis the suite cares about
    /// most.
    rules: [Option<RuleSpec>; 4],
}

impl AclSpec {
    fn rule_specs(&self) -> impl Iterator<Item = RuleSpec> + '_ {
        self.rules.iter().flatten().copied()
    }
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct PeeringSpec {
    /// IP version of the whole peering (both manifests are kept single-version).
    v6: bool,
    /// Masquerade the local side (rather than exposing it plainly). A masquerade side's public
    /// prefixes differ from its private ones, which is what makes the source/destination coverage
    /// sets differ.
    local_masq: bool,
    remote_masq: bool,
    /// `None` means no ACL at all on this peering, which must allow everything.
    acl: Option<AclSpec>,
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct OverlaySpec {
    peerings: [Option<PeeringSpec>; 3],
}

/// One direction of one generated peering: the VNI pair a packet must carry, and the blocks its
/// addresses must fall in, for an ACL rule to have any chance of matching it.
///
/// Probes are anchored to these rather than drawn freely. Free draws are overwhelmingly misses --
/// the source and destination VNIs must name a peered pair *and* the two addresses must land in
/// that peering's two blocks -- so an unanchored generator spends its whole budget confirming that
/// unrelated traffic matches nothing. [`Stray`] puts the miss paths back deliberately.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Anchor {
    src_vni: u32,
    dst_vni: u32,
    /// The `from` side's private block: what a rule's source pattern is validated against.
    src_block: u8,
    /// The `to` side's public block, and whether that is its public space (it masquerades) or its
    /// private one (it does not): what a rule's destination pattern is validated against.
    dst_block: u8,
    dst_public: bool,
    v6: bool,
}

/// A materialized overlay, the number of allocated prefix blocks (stray probes map their block
/// selectors into that range), and one anchor per peering direction.
pub(crate) struct BuiltOverlay {
    pub(crate) overlay: ValidatedOverlay,
    pub(crate) blocks: u8,
    pub(crate) anchors: Vec<Anchor>,
}

impl OverlaySpec {
    /// Normalize the raw spec into a valid configuration and build it. Panics if the result fails
    /// real config validation (generator/config drift).
    pub(crate) fn build(&self) -> BuiltOverlay {
        let mut spec = *self;

        // At least one peering, or there is nothing to look up.
        if spec.peerings.iter().all(Option::is_none) {
            spec.peerings[0] = Some(PeeringSpec {
                v6: false,
                local_masq: false,
                remote_masq: false,
                acl: Some(AclSpec {
                    default_allow: false,
                    rules: [Some(FALLBACK_RULE), None, None, None],
                }),
            });
        }
        for peering in spec.peerings.iter_mut().flatten() {
            if let Some(acl) = peering.acl.as_mut()
                && acl.rules.iter().all(Option::is_none)
            {
                // An ACL list must contain at least one rule.
                acl.rules[0] = Some(FALLBACK_RULE);
            }
            // `scope: flow` requires that one whole side of the peering use masquerade or port
            // forwarding for every expose. Each side here has exactly one expose, so masquerading
            // the local side satisfies it -- and stateful NAT on one side forbids NAT on the other,
            // so the remote side must then be plain.
            let wants_flow_scope = peering
                .acl
                .iter()
                .flat_map(AclSpec::rule_specs)
                .any(|rule| rule.flow_scope);
            if wants_flow_scope {
                peering.local_masq = true;
            }
            if peering.local_masq {
                peering.remote_masq = false;
            }
        }

        // Materialize.
        let mut vpc_table = VpcTable::new();
        for (i, id) in VNIS.iter().enumerate() {
            vpc_table
                .add(
                    Vpc::new(&vpc_name(i), &format!("VPC{:02}", i + 1), *id)
                        .unwrap_or_else(|e| unreachable!("valid VPC: {e}")),
                )
                .unwrap_or_else(|e| unreachable!("distinct VPCs: {e}"));
        }
        let mut peering_table = VpcPeeringTable::new();
        let mut blocks: u8 = 0;
        let mut anchors = Vec::new();
        for (slot, peering) in spec.peerings.iter().enumerate() {
            let Some(peering) = peering else { continue };
            let (a, b) = PEERING_PAIRS[slot];
            let local_block = blocks;
            let remote_block = blocks + 1;
            blocks += 2;

            // Both directions: a rule may be written either way round, and the lowering keeps each
            // on the visit from its own `from` VPC.
            anchors.push(Anchor {
                src_vni: VNIS[a],
                dst_vni: VNIS[b],
                src_block: local_block,
                dst_block: remote_block,
                dst_public: peering.remote_masq,
                v6: peering.v6,
            });
            anchors.push(Anchor {
                src_vni: VNIS[b],
                dst_vni: VNIS[a],
                src_block: remote_block,
                dst_block: local_block,
                dst_public: peering.local_masq,
                v6: peering.v6,
            });

            let local = manifest(&vpc_name(a), local_block, peering.local_masq, peering.v6);
            let remote = manifest(&vpc_name(b), remote_block, peering.remote_masq, peering.v6);
            let mut built = VpcPeering::with_default_group(
                &format!("{}-to-{}", vpc_name(a), vpc_name(b)),
                local,
                remote,
            );
            built.acl = peering.acl.map(|acl| {
                build_acl(
                    &acl,
                    (&vpc_name(a), local_block, peering.local_masq),
                    (&vpc_name(b), remote_block, peering.remote_masq),
                    peering.v6,
                )
            });
            peering_table
                .add(built)
                .unwrap_or_else(|e| unreachable!("distinct peerings: {e}"));
        }

        let overlay = Overlay::new(vpc_table, peering_table)
            .validate()
            .unwrap_or_else(|e| {
                panic!(
                    "generated overlay must validate (generator/config drift): {e}\nspec: {spec:?}"
                )
            });
        BuiltOverlay {
            overlay,
            blocks,
            anchors,
        }
    }
}

fn vpc_name(index: usize) -> String {
    format!("vpc{}", index + 1)
}

/// One manifest with a single expose over block `n`: masquerading behind the block's public range,
/// or advertising the private range plainly (in which case public and private coincide).
fn manifest(name: &str, n: u8, masquerade: bool, v6: bool) -> VpcManifest {
    let expose = if masquerade {
        VpcExpose::empty()
            .make_masquerade(None)
            .unwrap_or_else(|e| unreachable!("masquerade on an empty expose: {e}"))
            .ip(private_block(n, v6).as_str().into())
            .as_range(public_block(n, v6).as_str().into())
            .unwrap_or_else(|e| unreachable!("equal-size public range: {e}"))
    } else {
        VpcExpose::empty().ip(private_block(n, v6).as_str().into())
    };
    VpcManifest::with_exposes(name, vec![expose])
}

/// Build the ACL for one peering. `local` and `remote` each carry the VPC name, its prefix block,
/// and whether it masquerades (which decides whether its public space differs from its private).
fn build_acl(spec: &AclSpec, local: (&str, u8, bool), remote: (&str, u8, bool), v6: bool) -> Acl {
    let (local_name, local_block, local_masq) = local;
    let (remote_name, remote_block, remote_masq) = remote;

    let rules = spec
        .rule_specs()
        .enumerate()
        .map(|(i, rule)| {
            // A rule's source is matched against its `from` VPC's private space and its
            // destination against its `to` VPC's public space -- the same asymmetry config
            // validation checks the pattern's coverage against.
            let ((from, src_block), (to, dst_block, dst_masq)) = if rule.reverse {
                (
                    (remote_name, remote_block),
                    (local_name, local_block, local_masq),
                )
            } else {
                (
                    (local_name, local_block),
                    (remote_name, remote_block, remote_masq),
                )
            };

            // Ports are only legal on TCP and UDP rules.
            let (src_ports, dst_ports) = if rule.proto.allows_ports() {
                (rule.src_ports.resolve(), rule.dst_ports.resolve())
            } else {
                (None, None)
            };

            AclRule {
                // Names must be unique within an ACL; the index supplies that.
                name: format!("rule{i}"),
                from: from.to_owned(),
                to: to.to_owned(),
                action: if rule.allow {
                    AclAction::Allow
                } else {
                    AclAction::Deny
                },
                pattern: AclPattern {
                    src: prefix_set(rule.src.resolve(src_block, false, v6), src_ports),
                    dst: prefix_set(rule.dst.resolve(dst_block, dst_masq, v6), dst_ports),
                    src_any_ports: Vec::new(),
                    dst_any_ports: Vec::new(),
                    proto: rule.proto.to_config(),
                },
                scope: if rule.flow_scope {
                    AclScope::Flow
                } else {
                    AclScope::Packet
                },
                log: rule.log,
            }
        })
        .collect();

    Acl::new(
        if spec.default_allow {
            AclAction::Allow
        } else {
            AclAction::Deny
        },
        rules,
    )
}

/// A pattern set over the given prefixes, all sharing one port constraint. The empty set is what
/// [`SideSel::All`] lowers to, which validation substitutes with the manifest's own coverage.
fn prefix_set(prefixes: Vec<Prefix>, ports: Option<PortRange>) -> PrefixPortsSet {
    prefixes
        .into_iter()
        .map(|prefix| PrefixWithOptionalPorts::new(prefix, ports))
        .collect()
}

// -------------------------------------------------------------------------------------------------
// Probes.

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum ProbeProto {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl ProbeProto {
    fn next_header(self) -> NextHeader {
        match self {
            ProbeProto::Tcp => NextHeader::TCP,
            ProbeProto::Udp => NextHeader::UDP,
            ProbeProto::Icmp => NextHeader::ICMP,
            ProbeProto::Other(p) => NextHeader::new(p),
        }
    }

    /// Only TCP and UDP packets carry ports; everything else looks up with the wildcard value.
    fn has_ports(self) -> bool {
        matches!(self, ProbeProto::Tcp | ProbeProto::Udp)
    }
}

/// A probe's port, biased towards the edges of the ranges the rule generator emits.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum ProbePort {
    Exact(u16),
    /// In or just past the well-known range that `PortSel::Low` covers.
    WellKnown(u8),
    /// In or around the single-port range that `PortSel::Single` covers.
    Nested(u8),
}

impl ProbePort {
    fn resolve(self) -> u16 {
        match self {
            ProbePort::Exact(p) => p,
            ProbePort::WellKnown(k) => 1 + u16::from(k) * 4,
            ProbePort::Nested(k) => 499 + u16::from(k),
        }
    }
}

/// How a probe departs from its anchor. Each variant breaks exactly one of the things a match
/// needs, so every miss path is reached deliberately and stays shrinkable. Carried as an `Option`
/// so that half of all probes stay squarely inside their peering, where rules can actually match;
/// the ways to miss outnumber the ways to hit, and left unweighted they crowd out the hits.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum Stray {
    /// Claim a source VPC that does not exist.
    SrcVni,
    /// Claim a destination VPC that does not exist (so the pair is unpeered).
    DstVni,
    /// Swap the VNI pair without swapping the addresses: a real pair, wrong direction.
    SwapVnis,
    /// Take the source address from some other block.
    SrcBlock(u8),
    /// Take the destination address from some other block.
    DstBlock(u8),
    /// Take the source from the `from` side's public space rather than its private one.
    SrcPublic,
    /// Give the destination the opposite IP version of the source.
    CrossVersion,
}

/// One packet's ACL question, in spec form: an anchor (a peering direction), a deliberate departure
/// from it, and the host/protocol/port entropy that decides which of that peering's rules match.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct ProbeSpec {
    anchor_sel: u8,
    stray: Option<Stray>,
    src_host: u8,
    dst_host: u8,
    proto: ProbeProto,
    sport: ProbePort,
    dport: ProbePort,
}

impl ProbeSpec {
    pub(crate) fn resolve(&self, built: &BuiltOverlay) -> PacketSummary {
        // Every generated overlay has at least one peering, hence at least two anchors.
        let anchor = built.anchors[self.anchor_sel as usize % built.anchors.len()];
        let nblocks = built.blocks.max(1);

        let mut src_vni = anchor.src_vni;
        let mut dst_vni = anchor.dst_vni;
        let mut src_block = anchor.src_block;
        let mut dst_block = anchor.dst_block;
        let mut src_public = false;
        let mut dst_v6 = anchor.v6;
        match self.stray {
            None => {}
            Some(Stray::SrcVni) => src_vni = BOGUS_VNI,
            Some(Stray::DstVni) => dst_vni = BOGUS_VNI,
            Some(Stray::SwapVnis) => std::mem::swap(&mut src_vni, &mut dst_vni),
            Some(Stray::SrcBlock(b)) => src_block = b % nblocks,
            Some(Stray::DstBlock(b)) => dst_block = b % nblocks,
            Some(Stray::SrcPublic) => src_public = true,
            Some(Stray::CrossVersion) => dst_v6 = !anchor.v6,
        }

        PacketSummary {
            src_vni: vni(src_vni),
            dst_vni: vni(dst_vni),
            src_ip: block_addr(src_block, self.src_host, src_public, anchor.v6),
            dst_ip: block_addr(dst_block, self.dst_host, anchor.dst_public, dst_v6),
            proto: self.proto.next_header(),
            ports: self
                .proto
                .has_ports()
                .then(|| (self.sport.resolve(), self.dport.resolve())),
        }
    }
}
