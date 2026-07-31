// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generators for ACL property tests.
//!
//! [`OverlaySpec::build`] normalizes a compact spec and validates the resulting config. Probes are
//! biased toward generated peerings so short runs exercise rule matches as well as misses.
//!
//! This remains separate from `flow-filter`'s generator: flow-filter needs disjoint prefix blocks,
//! while ACL ordering requires overlapping patterns. Invalid cross-version rules are out of scope
//! because config validation rejects them before lowering.

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

pub(crate) const VNIS: [u32; 3] = [100, 200, 300];
/// A VNI outside [`VNIS`].
const BOGUS_VNI: u32 = 999;

/// The unique VPC pair assigned to each peering slot.
const PEERING_PAIRS: [(usize, usize); 3] = [(0, 1), (0, 2), (1, 2)];

pub(crate) fn vni(id: u32) -> Vni {
    Vni::new_checked(id).unwrap_or_else(|e| unreachable!("{id} is a valid VNI: {e:?}"))
}

// -------------------------------------------------------------------------------------------------
// Prefix pool.
//
// Each peering side owns a distinct block; rule patterns overlap within it.

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

/// An address inside block `n`.
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

/// An overlapping region within a generated block.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum PrefixSel {
    Block,
    LowerHalf,
    UpperHalf,
    Host(u8),
}

impl PrefixSel {
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

/// One side of a rule pattern. Two entries make lowering's cross-product observable.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum SideSel {
    /// Validation expands this to the manifest's coverage set.
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

/// A generated TCP or UDP port constraint.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum PortSel {
    None,
    Low,
    High,
    /// A port nested inside `Low`.
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
    /// A protocol number, including aliases for TCP and UDP.
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

    fn allows_ports(self) -> bool {
        matches!(self, ProtoSel::Tcp | ProtoSel::Udp)
    }
}

// -------------------------------------------------------------------------------------------------
// Specs.

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct RuleSpec {
    /// Apply the rule from remote to local.
    reverse: bool,
    allow: bool,
    /// Request flow scope; normalization adds the required NAT.
    flow_scope: bool,
    log: bool,
    proto: ProtoSel,
    src: SideSel,
    dst: SideSel,
    src_ports: PortSel,
    dst_ports: PortSel,
}

/// Ensures a generated ACL is non-empty.
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
    /// Up to four rules in precedence order.
    rules: [Option<RuleSpec>; 4],
}

impl AclSpec {
    fn rule_specs(&self) -> impl Iterator<Item = RuleSpec> + '_ {
        self.rules.iter().flatten().copied()
    }
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct PeeringSpec {
    /// IP version for both manifests.
    v6: bool,
    /// Masquerade changes a side's public prefix.
    local_masq: bool,
    remote_masq: bool,
    /// `None` leaves the peering without an ACL.
    acl: Option<AclSpec>,
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct OverlaySpec {
    peerings: [Option<PeeringSpec>; 3],
}

/// One direction of a generated peering, used to bias probes toward matches.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Anchor {
    src_vni: u32,
    dst_vni: u32,
    /// The source side's private block.
    src_block: u8,
    /// The destination side's advertised block.
    dst_block: u8,
    dst_public: bool,
    v6: bool,
}

/// A validated overlay and its probe metadata.
pub(crate) struct BuiltOverlay {
    pub(crate) overlay: ValidatedOverlay,
    pub(crate) blocks: u8,
    pub(crate) anchors: Vec<Anchor>,
}

impl OverlaySpec {
    /// Normalize and validate the generated config.
    pub(crate) fn build(&self) -> BuiltOverlay {
        let mut spec = *self;

        // Keep at least one peering to probe.
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
                acl.rules[0] = Some(FALLBACK_RULE);
            }
            // Flow scope requires stateful NAT on one side. Stateful NAT cannot be on both sides.
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

            // Anchor both rule directions.
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

/// Build one plain or masqueraded expose over block `n`.
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

fn build_acl(spec: &AclSpec, local: (&str, u8, bool), remote: (&str, u8, bool), v6: bool) -> Acl {
    let (local_name, local_block, local_masq) = local;
    let (remote_name, remote_block, remote_masq) = remote;

    let rules = spec
        .rule_specs()
        .enumerate()
        .map(|(i, rule)| {
            // Rules match the source's private space and destination's public space.
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

            let (src_ports, dst_ports) = if rule.proto.allows_ports() {
                (rule.src_ports.resolve(), rule.dst_ports.resolve())
            } else {
                (None, None)
            };

            AclRule {
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

    fn has_ports(self) -> bool {
        matches!(self, ProbeProto::Tcp | ProbeProto::Udp)
    }
}

/// A port biased toward generated range boundaries.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum ProbePort {
    Exact(u16),
    WellKnown(u8),
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

/// One deliberate departure from a peering anchor.
/// `Option<Stray>` keeps half of probes on the match path.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum Stray {
    SrcVni,
    DstVni,
    /// Use the reverse VNI pair without reversing addresses.
    SwapVnis,
    SrcBlock(u8),
    DstBlock(u8),
    SrcPublic,
    CrossVersion,
}

/// A generated packet relative to a peering anchor.
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
