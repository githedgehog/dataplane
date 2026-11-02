// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The software ACL filter and rate limiter as the oracle for the NIC: generated ACLs, exposes and
//! rate limits are compiled and lowered onto mlx5 as they would be on a port, and every way the
//! [model](crate::model) says the NIC may treat a generated frame is held to the cascade contract
//! against what software does with the decapsulated packet:
//!
//! - the NIC denies a frame only if software drops it;
//! - the NIC charges a frame only to the meter the software charges it to;
//! - the NIC drops a frame only as red from such a meter, and only for a meter that drops red;
//! - every meter the NIC enforces is at least as permissive as the software component it stands
//!   for.
//!
//! Frames the software could not route (no peer exposes the destination) are dropped by it
//! anyway, so the NIC may do anything with them but change them. Transit VXLAN (to another VTEP)
//! the NIC neither drops nor charges.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU64, NonZeroUsize};

use acl::table::Backend;
use acl_filter::AclFilterContext;
use config::external::overlay::acl::{
    Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope, AclTcpFlagsMatch,
};
use config::external::overlay::ratelimit::{
    ColorAction, ColorActions, Meter, MeterProfile, RateLimitRule, RateLimitTables,
};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use dpdk::flow::template::{Color, MeterAlgorithm, MeterUnit, TemplateAction};
use dpdk::queue::rx::RxQueueIndex;
use flow_filter::{FlowFilter, FlowFilterContext, FlowFilterContextWriter};
use lpm::prefix::L4Protocol;
use lpm::prefix::with_ports::{PortRange, PrefixPortsSet};
use lpm::prefix::{Prefix as LpmPrefix, PrefixWithOptionalPorts};
use net::buffer::TestBuffer;
use net::packet::{Packet, VpcDiscriminant};
use net::tcp::TcpFlags;
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use policer::{Profile, Rate};
use rate_limit::{Classify, PeeringRules, RateLimitWriter, RateLimits, Unit};

use crate::mlx5::{Plan, Role, encoded_burst, encoded_rate, pmd_scale};
use crate::model::{Outcome, Verdict};
use crate::program::Program;

/// A VPC: its name, VNI and the one prefix it exposes.
struct VpcSpec {
    name: &'static str,
    id: &'static str,
    vni: u32,
    expose: IpAddr,
    len: u8,
}

const VPCS: [VpcSpec; 5] = [
    VpcSpec {
        name: "vpc-a",
        id: "AAAAA",
        vni: 100,
        expose: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        len: 16,
    },
    VpcSpec {
        name: "vpc-b",
        id: "BBBBB",
        vni: 200,
        expose: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
        len: 16,
    },
    VpcSpec {
        name: "vpc-c",
        id: "CCCCC",
        vni: 300,
        expose: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 0)),
        len: 16,
    },
    VpcSpec {
        name: "vpc-d",
        id: "DDDDD",
        vni: 400,
        expose: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0)),
        len: 64,
    },
    VpcSpec {
        name: "vpc-e",
        id: "EEEEE",
        vni: 500,
        expose: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 2, 0, 0, 0, 0)),
        len: 64,
    },
];

/// Peerings, by index into [`VPCS`].
const PEERINGS: [(usize, usize); 4] = [(0, 1), (0, 2), (1, 2), (3, 4)];

const PORTS: [u16; 7] = [53, 80, 443, 4789, 8080, 1, 65535];

/// The names of the generated meters; see [`meter`].
const METERS: [&str; 4] = ["bytes", "packets", "pass", "chain"];

fn peering_name(peering: usize) -> String {
    let (l, r) = PEERINGS[peering];
    format!("{}--{}", VPCS[l].name, VPCS[r].name)
}

/// The address `bits` picks within `vpc`'s exposed prefix, and that prefix with `len` more bits.
fn within(vpc: usize, bits: u128, extra: u8) -> (IpAddr, u8) {
    let spec = &VPCS[vpc];
    match spec.expose {
        IpAddr::V4(base) => {
            let len = spec.len + extra % (33 - spec.len);
            let host = u32::try_from(bits & 0xffff).unwrap_or(0);
            let addr = u32::from(base) | host;
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            (IpAddr::V4(Ipv4Addr::from(addr & mask)), len)
        }
        IpAddr::V6(base) => {
            let len = spec.len + extra % (129 - spec.len);
            let addr = u128::from(base) | (bits & u128::from(u64::MAX));
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            (IpAddr::V6(Ipv6Addr::from(addr & mask)), len)
        }
    }
}

#[derive(Debug, Clone, bolero::TypeGenerator)]
enum RawPorts {
    Exact(u8),
    Range(u8, u8),
}

impl RawPorts {
    fn range(&self) -> PortRange {
        let port = |i: u8| PORTS[usize::from(i) % PORTS.len()];
        let (a, b) = match *self {
            RawPorts::Exact(i) => (port(i), port(i)),
            RawPorts::Range(i, j) => (port(i), port(j)),
        };
        PortRange::new(a.min(b), a.max(b)).unwrap_or_else(|_| unreachable!())
    }
}

#[derive(Debug, Clone, bolero::TypeGenerator)]
struct RawSubnet {
    bits: u64,
    extra: u8,
    ports: Option<RawPorts>,
}

impl RawSubnet {
    fn subnet(&self, vpc: usize) -> PrefixWithOptionalPorts {
        let (addr, len) = within(vpc, u128::from(self.bits), self.extra);
        let prefix = LpmPrefix::try_from((addr, len)).unwrap_or_else(|_| unreachable!());
        PrefixWithOptionalPorts::new(prefix, self.ports.as_ref().map(RawPorts::range))
    }
}

#[derive(Debug, Copy, Clone, bolero::TypeGenerator)]
enum RawProto {
    Any,
    Udp,
    Tcp,
    /// TCP, with the flags in the mask (the second) required to take their values in the first.
    TcpFlags(u8, u8),
    Icmp,
    Other(u8),
}

impl RawProto {
    /// The flags a TCP rule requires: values and mask.
    fn tcp_flags(self) -> Option<(u8, u8)> {
        match self {
            RawProto::TcpFlags(value, mask) if mask != 0 => Some((value & mask, mask)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, bolero::TypeGenerator)]
pub(crate) struct RawRule {
    /// A peering, and which way.
    peering: u8,
    reverse: bool,
    src: Vec<RawSubnet>,
    dst: Vec<RawSubnet>,
    proto: RawProto,
    meter: u8,
}

impl RawRule {
    /// The index of the rule's peering.
    pub(crate) fn peering_index(&self) -> usize {
        self.direction().0
    }

    /// The VNIs of the rule's source and destination VPCs.
    pub(crate) fn vnis(&self) -> (u32, u32) {
        let (_, from, to) = self.direction();
        (VPCS[from].vni, VPCS[to].vni)
    }

    /// The peering, and the source and destination VPCs.
    fn direction(&self) -> (usize, usize, usize) {
        let peering = usize::from(self.peering) % PEERINGS.len();
        let (from, to) = PEERINGS[peering];
        if self.reverse {
            (peering, to, from)
        } else {
            (peering, from, to)
        }
    }

    fn rule(&self) -> RateLimitRule {
        let (peering, from, to) = self.direction();
        RateLimitRule {
            peering: peering_name(peering),
            from: VPCS[from].name.into(),
            to: VPCS[to].name.into(),
            meter: METERS[usize::from(self.meter) % METERS.len()].into(),
            pattern: self.pattern(),
        }
    }

    /// What the rule matches, as an ACL rule would.
    fn pattern(&self) -> AclPattern {
        let (_, from, to) = self.direction();
        // Only TCP and UDP rules may name ports.
        let ports = matches!(
            self.proto,
            RawProto::Udp | RawProto::Tcp | RawProto::TcpFlags(..)
        );
        let set = |subnets: &[RawSubnet], vpc| -> PrefixPortsSet {
            subnets
                .iter()
                .take(2)
                .map(|s| {
                    let subnet = s.subnet(vpc);
                    if ports {
                        subnet
                    } else {
                        PrefixWithOptionalPorts::new(subnet.prefix(), None)
                    }
                })
                .collect()
        };
        AclPattern {
            src: set(&self.src, from),
            dst: set(&self.dst, to),
            proto: match self.proto {
                RawProto::Any => AclProtoMatch::Any,
                RawProto::Udp => AclProtoMatch::Udp,
                RawProto::Tcp => AclProtoMatch::tcp(),
                RawProto::TcpFlags(value, mask) => {
                    let mut flags = AclTcpFlagsMatch::ANY;
                    for bit in (0..8).map(|i| 1u8 << i).filter(|bit| mask & bit != 0) {
                        let flag = TcpFlags::from_bits_truncate(bit);
                        flags = flags.require(flag, value & bit != 0);
                    }
                    AclProtoMatch::Tcp(flags)
                }
                RawProto::Icmp => AclProtoMatch::Other(1),
                RawProto::Other(p) => AclProtoMatch::Other(p),
            },
            ..AclPattern::default()
        }
    }
}

/// An ACL rule: what it matches (the rate-limit rule's fields, but for the meter), its verdict and
/// its scope.
#[derive(Debug, Clone, bolero::TypeGenerator)]
pub(crate) struct RawAclRule {
    pub(crate) rule: RawRule,
    pub(crate) deny: bool,
    flow: bool,
}

/// The peerings' ACLs: each peering with rules has an ACL, with the default action given (deny if
/// `Some(true)`, else allow).
#[derive(Debug, Clone, Default, bolero::TypeGenerator)]
pub(crate) struct RawAcls {
    pub(crate) defaults: [Option<bool>; 4],
    pub(crate) rules: Vec<RawAclRule>,
    /// What each side of each peering exposes, left then right.
    pub(crate) exposes: [[RawExpose; 2]; 4],
}

/// What a VPC exposes to a peer.
#[derive(Debug, Copy, Clone, Default, bolero::TypeGenerator)]
pub(crate) enum RawExpose {
    /// Its own prefix.
    #[default]
    Own,
    /// A default expose: every address no other expose of the source VPC's peers takes.
    Default,
    /// A prefix covering every VPC of its family (`10.0.0.0/8`, `fd00::/16`).
    Wide,
    /// Its own prefix and, in another expose, another VPC's of its family.
    Plus(u8),
    /// One address of its own prefix (`.5`), port-forwarded: TCP (else UDP) to one of [`PORTS`].
    PortForward { tcp: bool, port: u8 },
    /// Its own prefix, masquerading a private one: only replies reach it.
    Masquerade,
}

impl RawAcls {
    /// The rules, in first-match order, at most six.
    fn rules(&self) -> &[RawAclRule] {
        &self.rules[..self.rules.len().min(6)]
    }

    /// The ACL of `peering`, if it has one.
    fn acl(&self, peering: usize) -> Option<Acl> {
        let rules: Vec<AclRule> = self
            .rules()
            .iter()
            .filter(|r| r.rule.direction().0 == peering)
            .enumerate()
            .map(|(i, r)| {
                let (_, from, to) = r.rule.direction();
                AclRule {
                    name: format!("rule {i}"),
                    from: VPCS[from].name.into(),
                    to: VPCS[to].name.into(),
                    action: if r.deny {
                        AclAction::Deny
                    } else {
                        AclAction::Allow
                    },
                    pattern: r.rule.pattern(),
                    // The ACL filter allows TCP flag matches in packet scope only.
                    scope: if r.flow && r.rule.proto.tcp_flags().is_none() {
                        AclScope::Flow
                    } else {
                        AclScope::Packet
                    },
                    log: false,
                }
            })
            .collect();
        // An ACL needs a rule.
        if rules.is_empty() {
            return None;
        }
        let default = self.defaults[peering];
        let default = if default == Some(true) {
            AclAction::Deny
        } else {
            AclAction::Allow
        };
        Some(Acl::new(default, rules))
    }
}

/// What frames are aimed at: the rate-limit rules, then the ACL rules.
pub(crate) fn targets(rules: &[RawRule], acls: &RawAcls) -> Vec<RawRule> {
    rules
        .iter()
        .cloned()
        .chain(acls.rules().iter().map(|r| r.rule.clone()))
        .collect()
}

#[derive(Debug, bolero::TypeGenerator)]
pub(crate) struct RawMeter {
    rate: u32,
    committed_burst: u32,
    excess_burst: u32,
    excess_rate: Option<u32>,
}

impl RawMeter {
    fn profile(&self, red: ColorAction) -> Option<MeterProfile> {
        let rate =
            |r: u32| Rate::new(NonZeroU64::new(u64::from(r).max(1)).unwrap_or(NonZeroU64::MIN));
        let profile = Profile::new(
            rate(self.rate),
            u64::from(self.committed_burst).max(1500),
            self.excess_rate.map(rate),
            u64::from(self.excess_burst),
        )
        .ok()?;
        Some(MeterProfile {
            profile,
            actions: ColorActions {
                red,
                ..ColorActions::default()
            },
        })
    }
}

/// The meter named `METERS[index]`.
fn meter(index: usize, raw: &RawMeter) -> Option<Meter> {
    let drop = raw.profile(ColorAction::Drop)?;
    let pass = raw.profile(ColorAction::Pass)?;
    Some(match index {
        0 => Meter {
            bytes: Some(drop),
            packets: None,
        },
        1 => Meter {
            bytes: None,
            packets: Some(drop),
        },
        2 => Meter {
            bytes: Some(pass),
            packets: None,
        },
        _ => Meter {
            bytes: Some(pass),
            packets: Some(drop),
        },
    })
}

pub(crate) fn overlay(
    meters: &[RawMeter; 4],
    rules: &[RawRule],
    acls: &RawAcls,
) -> Option<ValidatedOverlay> {
    with_exposes(meters, rules, acls, &exposes(meters, rules, acls))
}

/// The generated exposes, side by side, as far as the overlay still validates with them; the
/// other sides expose their VPC's own prefix.
pub(crate) fn exposes(
    meters: &[RawMeter; 4],
    rules: &[RawRule],
    acls: &RawAcls,
) -> [[RawExpose; 2]; 4] {
    let mut exposes = [[RawExpose::Own; 2]; 4];
    for peering in 0..exposes.len() {
        for side in 0..2 {
            let mut tried = exposes;
            tried[peering][side] = acls.exposes[peering][side];
            if with_exposes(meters, rules, acls, &tried).is_some() {
                exposes = tried;
            }
        }
    }
    exposes
}

fn manifest(vpc: usize, raw: RawExpose) -> Option<VpcManifest> {
    let spec = &VPCS[vpc];
    let mut manifest = VpcManifest::new(spec.name);
    let own = LpmPrefix::try_from((spec.expose, spec.len)).ok()?;
    let v4 = spec.expose.is_ipv4();
    match raw {
        RawExpose::Own => manifest.add_expose(VpcExpose::empty().ip(own.into())),
        RawExpose::Default => manifest.add_expose(VpcExpose::empty().set_default()),
        RawExpose::Wide => {
            let wide = if v4 {
                LpmPrefix::try_from((IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8))
            } else {
                LpmPrefix::try_from((IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)), 16))
            };
            manifest.add_expose(VpcExpose::empty().ip(wide.ok()?.into()));
        }
        RawExpose::Plus(i) => {
            manifest.add_expose(VpcExpose::empty().ip(own.into()));
            let others: Vec<usize> = (0..VPCS.len())
                .filter(|&o| o != vpc && VPCS[o].expose.is_ipv4() == v4)
                .collect();
            if let Some(&other) = others.get(usize::from(i) % others.len().max(1)) {
                let spec = &VPCS[other];
                let prefix = LpmPrefix::try_from((spec.expose, spec.len)).ok()?;
                manifest.add_expose(VpcExpose::empty().ip(prefix.into()));
            }
        }
        RawExpose::PortForward { tcp, port } => {
            let host = |addr: IpAddr| {
                let len = if addr.is_ipv4() { 32 } else { 128 };
                let port = PORTS[usize::from(port) % PORTS.len()];
                let port = PortRange::new(port, port).ok()?;
                Some(PrefixWithOptionalPorts::new(
                    LpmPrefix::try_from((addr, len)).ok()?,
                    Some(port),
                ))
            };
            let public = offset(spec.expose, 5);
            let private = offset(private_base(vpc, v4), 5);
            let proto = if tcp {
                L4Protocol::Tcp
            } else {
                L4Protocol::Udp
            };
            manifest.add_expose(
                VpcExpose::empty()
                    .make_port_forwarding(None, Some(proto))
                    .ok()?
                    .ip(host(private)?)
                    .as_range(host(public)?)
                    .ok()?,
            );
        }
        RawExpose::Masquerade => {
            let private = LpmPrefix::try_from((private_base(vpc, v4), spec.len)).ok()?;
            manifest.add_expose(
                VpcExpose::empty()
                    .make_masquerade(None)
                    .ok()?
                    .ip(private.into())
                    .as_range(own.into())
                    .ok()?,
            );
        }
    }
    Some(manifest)
}

/// `addr` plus `n`.
fn offset(addr: IpAddr, n: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) + u32::from(n))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) + u128::from(n))),
    }
}

/// A private prefix of `vpc`'s, outside every VPC's public one.
fn private_base(vpc: usize, v4: bool) -> IpAddr {
    let vpc = u8::try_from(vpc).unwrap_or(u8::MAX);
    if v4 {
        IpAddr::V4(Ipv4Addr::new(192, 168, vpc, 0))
    } else {
        IpAddr::V6(Ipv6Addr::new(0xfd99, 0, 0, u16::from(vpc), 0, 0, 0, 0))
    }
}

fn with_exposes(
    meters: &[RawMeter; 4],
    rules: &[RawRule],
    acls: &RawAcls,
    exposes: &[[RawExpose; 2]; 4],
) -> Option<ValidatedOverlay> {
    let mut vpcs = VpcTable::new();
    for spec in &VPCS {
        vpcs.add(Vpc::new(spec.name, spec.id, spec.vni).ok()?)
            .ok()?;
    }
    let mut peerings = VpcPeeringTable::new();
    for (peering, &(l, r)) in PEERINGS.iter().enumerate() {
        let [left, right] = exposes[peering];
        let mut vpc_peering = VpcPeering::new(
            &peering_name(peering),
            manifest(l, left)?,
            manifest(r, right)?,
            "default".into(),
        );
        vpc_peering.acl = acls.acl(peering);
        peerings.add(vpc_peering).ok()?;
    }
    let meters = METERS
        .iter()
        .zip(meters)
        .enumerate()
        .map(|(i, (name, raw))| Some(((*name).to_string(), meter(i, raw)?)))
        .collect::<Option<_>>()?;
    Overlay::new(vpcs, peerings)
        .with_rate_limits(RateLimitTables {
            meters,
            rules: rules.iter().take(6).map(RawRule::rule).collect(),
        })
        .validate()
        .ok()
}

#[derive(Debug, Copy, Clone, bolero::TypeGenerator)]
enum RawL4 {
    Udp,
    Tcp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Copy, Clone, bolero::TypeGenerator)]
pub(crate) enum RawFragment {
    Whole,
    First,
    Later(u16),
}

#[derive(Debug, Clone, bolero::TypeGenerator)]
pub(crate) struct RawFrame {
    /// A rule the frame is aimed at: its peering, and an address in its first destination.
    pub(crate) aim: Option<u8>,
    src_vpc: u8,
    src_bits: u64,
    /// The VPC whose prefix holds the destination, or a random destination.
    dst_vpc: Option<u8>,
    dst_bits: u64,
    l4: RawL4,
    src_port: u8,
    dst_port: u8,
    pub(crate) fragment: RawFragment,
    /// IPv6 only: a hop-by-hop options header first.
    pub(crate) hop_by_hop: bool,
    pub(crate) vlan: Option<u16>,
    /// The flags of a TCP frame.
    tcp_flags: u8,
}

fn ones_complement(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}

/// The address `bits` picks inside `prefix`.
fn inside((base, len): (IpAddr, u8), bits: u64) -> IpAddr {
    // One in four is the host a port-forwarding expose publishes, if the subnet holds it.
    let bits = if bits.is_multiple_of(4) { 5 } else { bits };
    match base {
        IpAddr::V4(b) => {
            let host = u32::MAX.checked_shr(u32::from(len)).unwrap_or(0);
            let bits = u32::try_from(bits & 0xffff_ffff).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(b) | (bits & host)))
        }
        IpAddr::V6(b) => {
            let host = u128::MAX.checked_shr(u32::from(len)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(b) | (u128::from(bits) & host)))
        }
    }
}

/// A frame and what the software knows of it.
pub(crate) struct Frame {
    src_vni: u32,
    /// The VPC routing would deliver the inner packet to, if any.
    dst_vni: Option<u32>,
    inner: Vec<u8>,
}

impl RawFrame {
    /// The source VPC, and the inner source and destination addresses.
    fn addresses(&self, aimed: Option<&RawRule>) -> (usize, IpAddr, IpAddr) {
        let v6 = match aimed {
            Some(rule) => rule.direction().1 >= 3,
            None => usize::from(self.src_vpc) % VPCS.len() >= 3,
        };
        let family: Vec<usize> = (0..VPCS.len()).filter(|&i| (i >= 3) == v6).collect();
        let src_vpc = match aimed {
            Some(rule) => rule.direction().1,
            None => family[usize::from(self.src_vpc) % family.len()],
        };
        let src = match aimed.and_then(|rule| rule.src.first()) {
            Some(s) => inside(within(src_vpc, u128::from(s.bits), s.extra), self.src_bits),
            None => within(src_vpc, u128::from(self.src_bits), u8::MAX).0,
        };
        let dst = match aimed {
            Some(rule) => {
                let to = rule.direction().2;
                let subnet = rule
                    .dst
                    .first()
                    .map_or((VPCS[to].expose, VPCS[to].len), |s| {
                        within(to, u128::from(s.bits), s.extra)
                    });
                inside(subnet, self.dst_bits)
            }
            None => match self.dst_vpc {
                Some(i) => {
                    within(
                        family[usize::from(i) % family.len()],
                        u128::from(self.dst_bits),
                        u8::MAX,
                    )
                    .0
                }
                None if v6 => IpAddr::V6(Ipv6Addr::from(
                    u128::from(self.dst_bits) << 64 | u128::from(self.src_bits),
                )),
                None => IpAddr::V4(Ipv4Addr::from(
                    u32::try_from(self.dst_bits & 0xffff_ffff).unwrap_or(0),
                )),
            },
        };
        (src_vpc, src, dst)
    }

    /// The inner protocol number and the bytes after the IP header.
    fn payload(&self, aimed: Option<&RawRule>, v6: bool) -> (u8, Vec<u8>) {
        let port = |i: u8| PORTS[usize::from(i) % PORTS.len()];
        // An aimed frame takes the ports of the subnets it was aimed into, if they name any.
        let aimed_port = |subnets: Option<&Vec<RawSubnet>>, own: u8| {
            subnets
                .and_then(|s| s.first())
                .and_then(|s| s.ports.as_ref())
                .map_or_else(|| port(own), |p| p.range().start())
        };
        let (src_port, dst_port) = (
            aimed_port(aimed.map(|r| &r.src), self.src_port),
            aimed_port(aimed.map(|r| &r.dst), self.dst_port),
        );
        let l4 = match aimed.map(|rule| rule.proto) {
            Some(RawProto::Udp) => RawL4::Udp,
            Some(RawProto::Tcp | RawProto::TcpFlags(..)) => RawL4::Tcp,
            Some(RawProto::Icmp) => RawL4::Icmp,
            Some(RawProto::Other(p)) => RawL4::Other(p),
            Some(RawProto::Any) | None => self.l4,
        };
        let (proto, mut payload): (u8, Vec<u8>) = match l4 {
            RawL4::Udp => {
                let mut h = Vec::from(src_port.to_be_bytes());
                h.extend(dst_port.to_be_bytes());
                h.extend([0, 16, 0, 0]);
                (17, h)
            }
            RawL4::Tcp => {
                let mut h = Vec::from(src_port.to_be_bytes());
                h.extend(dst_port.to_be_bytes());
                // Aimed at a rule naming flags, the frame carries them, whatever its other flags.
                let flags = match aimed.and_then(|r| r.proto.tcp_flags()) {
                    Some((value, mask)) => (self.tcp_flags & !mask) | value,
                    None => self.tcp_flags,
                };
                h.extend([0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
                (6, h)
            }
            RawL4::Icmp => (if v6 { 58 } else { 1 }, vec![8, 0, 0, 0, 0, 1, 0, 1]),
            RawL4::Other(p) => (p, vec![0; 8]),
        };
        payload.extend([0xab; 8]);
        (proto, payload)
    }

    pub(crate) fn frame(&self, rules: &[RawRule]) -> Frame {
        let aimed = self
            .aim
            .filter(|_| !rules.is_empty())
            .map(|i| &rules[usize::from(i) % rules.len()]);
        let (src_vpc, src, dst) = self.addresses(aimed);
        // Routing: the peer of the source VPC that exposes the destination.
        let dst_vni = PEERINGS
            .iter()
            .filter_map(|&(l, r)| match src_vpc {
                s if s == l => Some(r),
                s if s == r => Some(l),
                _ => None,
            })
            .find(|&peer| {
                let spec = &VPCS[peer];
                LpmPrefix::try_from((spec.expose, spec.len)).is_ok_and(|p| p.covers_addr(&dst))
            })
            .map(|peer| VPCS[peer].vni);

        let (proto, payload) = self.payload(aimed, src.is_ipv6());
        let (offset, more) = match self.fragment {
            RawFragment::Whole => (0, false),
            RawFragment::First => (0, true),
            RawFragment::Later(o) => ((o % 0x1fff).max(1), false),
        };

        let mut inner = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1];
        if let Some(vid) = self.vlan {
            inner.extend([0x81, 0x00]);
            inner.extend((vid & 0x0fff).to_be_bytes());
        }
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                inner.extend([0x08, 0x00]);
                let total = u16::try_from(20 + payload.len()).unwrap_or(u16::MAX);
                let frag = offset | if more { 0x2000 } else { 0 };
                let mut h = vec![0x45, 0];
                h.extend(total.to_be_bytes());
                h.extend([0, 7]);
                h.extend(frag.to_be_bytes());
                h.extend([64, proto, 0, 0]);
                h.extend(s.octets());
                h.extend(d.octets());
                let sum = ones_complement(&h);
                h[10..12].copy_from_slice(&sum.to_be_bytes());
                inner.extend(h);
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                inner.extend([0x86, 0xdd]);
                let mut ext = Vec::new();
                let mut next = proto;
                if !matches!(self.fragment, RawFragment::Whole) {
                    let field = (offset << 3) | u16::from(more);
                    let mut h = vec![next, 0];
                    h.extend(field.to_be_bytes());
                    h.extend([0, 0, 0, 7]);
                    ext.splice(0..0, h);
                    next = 44;
                }
                if self.hop_by_hop {
                    ext.splice(0..0, [next, 0, 1, 4, 0, 0, 0, 0]);
                    next = 0;
                }
                let len = u16::try_from(ext.len() + payload.len()).unwrap_or(u16::MAX);
                inner.extend([0x60, 0, 0, 0]);
                inner.extend(len.to_be_bytes());
                inner.extend([next, 64]);
                inner.extend(s.octets());
                inner.extend(d.octets());
                inner.extend(ext);
            }
            _ => unreachable!("one family"),
        }
        inner.extend(payload);
        Frame {
            src_vni: VPCS[src_vpc].vni,
            dst_vni,
            inner,
        }
    }
}

/// The VTEP the generated VPCs' VXLAN is addressed to.
pub(crate) const VTEP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

/// [`VTEP`] for every VPC of `program`'s rules.
pub(crate) fn vteps(program: &Program) -> BTreeMap<Vni, Ipv4Addr> {
    program
        .denies
        .iter()
        .map(|d| d.matches.src_vni)
        .chain(program.rules.iter().map(|r| r.matches.src_vni))
        .map(|vni| (vni, VTEP))
        .collect()
}

impl Frame {
    /// The frame on the underlay wire: IPv4, UDP to the VXLAN port, VXLAN with the source VNI.
    fn wire(&self) -> Vec<u8> {
        self.wire_to([0x02, 0, 0, 0, 0, 4], 0)
    }

    /// The frame on the underlay wire to `dst`, with outer IP identification `id`, which no
    /// pattern matches: it tells frames apart on a real port.
    pub(crate) fn wire_to(&self, dst: [u8; 6], id: u16) -> Vec<u8> {
        self.encapsulated(dst, VTEP, id)
    }

    /// The frame passing through the gateway's underlay: VXLAN to another VTEP than the
    /// gateway's, which software routes without decapsulating it.
    fn transit(&self) -> Vec<u8> {
        self.transit_to([0x02, 0, 0, 0, 0, 4], 0)
    }

    /// [`Frame::transit`] to `dst`, with outer IP identification `id`, as [`Frame::wire_to`].
    pub(crate) fn transit_to(&self, dst: [u8; 6], id: u16) -> Vec<u8> {
        self.encapsulated(dst, Ipv4Addr::new(192, 0, 2, 9), id)
    }

    fn encapsulated(&self, dst: [u8; 6], vtep: Ipv4Addr, id: u16) -> Vec<u8> {
        let mut f = Vec::from(dst);
        f.extend([0x02, 0, 0, 0, 0, 3, 0x08, 0x00]);
        let udp_len = u16::try_from(16 + self.inner.len()).unwrap_or(u16::MAX);
        let total = udp_len.saturating_add(20);
        let mut ip = vec![0x45, 0];
        ip.extend(total.to_be_bytes());
        ip.extend(id.to_be_bytes());
        ip.extend([0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1]);
        ip.extend(vtep.octets());
        let sum = ones_complement(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        f.extend(ip);
        f.extend([0xc0, 0x00, 0x12, 0xb5]);
        f.extend(udp_len.to_be_bytes());
        f.extend([0, 0]);
        let v = self.src_vni.to_be_bytes();
        f.extend([0x08, 0, 0, 0, v[1], v[2], v[3], 0]);
        f.extend(&self.inner);
        f
    }

    /// What the software does with the decapsulated packet: the ACL filter, then the rate
    /// limiter.
    fn software(&self, acls: &AclFilterContext, limits: &RateLimits<PeeringRules>) -> Software {
        let Ok(mut packet) = Packet::new(TestBuffer::from_raw_data(&self.inner)) else {
            return Software::Unclassifiable;
        };
        let vni =
            |v: u32| VpcDiscriminant::VNI(Vni::new_checked(v).unwrap_or_else(|_| unreachable!()));
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(vni(self.src_vni));
        packet.meta_mut().dst_vpcd = self.dst_vni.map(vni);
        match acls.direct_match(&packet) {
            Err(_) => return Software::Unclassifiable,
            Ok(Some(AclAction::Deny)) => return Software::Denied,
            Ok(Some(AclAction::Allow)) => {}
            Ok(None) => {
                let (src, dst) = (vni(self.src_vni), self.dst_vni.map(vni));
                if let (VpcDiscriminant::VNI(src), Some(VpcDiscriminant::VNI(dst))) = (src, dst)
                    && acls.default_action(src, dst) == Some(AclAction::Deny)
                {
                    return Software::DefaultDenied;
                }
            }
        }
        Software::Charges(limits.classifier().classify(&packet).map(|rule| {
            let meter = limits.rules()[rule].meter();
            limits.meters()[meter].name().to_string()
        }))
    }
}

/// What the software does with a packet with no flow state.
#[derive(Debug, PartialEq, Eq)]
enum Software {
    /// The ACL filter passes it, and the rate limiter charges the named meter, or none.
    Charges(Option<String>),
    /// An ACL rule matching it directly denies it: whatever the flow state, it is dropped.
    Denied,
    /// No ACL rule matches it and its peering denies by default: dropped, unless it is the reply
    /// of a flow a flow-scoped rule allowed.
    DefaultDenied,
    /// The ACL filter cannot classify it (a truncated transport header, an IPv4 protocol number
    /// of an IPv6 extension header, a broken extension chain, ...) and drops it.
    Unclassifiable,
}

impl Software {
    /// Whether the software drops the packet, flow state or not.
    fn drops(&self) -> bool {
        matches!(self, Software::Denied | Software::Unclassifiable)
    }
}

/// How the NIC's outcomes for checked frames compared with the software.
#[derive(Debug, Default)]
struct Tally {
    /// Outcomes charging a meter.
    charged: usize,
    /// Outcomes charging a meter for a packet the ACL filter cannot classify: the tolerated
    /// deviation.
    charged_dropped: usize,
    /// Cases with some exposes other than their VPC's own prefix.
    exposed: usize,
    /// Cases checked.
    cases: usize,
}

/// The ways `outcome` breaks the cascade contract for a frame `software` treats so.
///
/// One deviation is tolerated, explicitly: the NIC may charge a meter for a packet the ACL filter
/// cannot classify, and drops before the rate limiter, which the software never charges. It is
/// counted in [`Tally::charged_dropped`]. Packets an ACL denies are not tolerated: a peering is
/// offloaded whole or not at all, so the NIC denies them first.
fn violation(
    program: &Program,
    outcome: &Outcome,
    software: &Software,
    tally: &mut Tally,
) -> Option<String> {
    let denied = outcome
        .path
        .iter()
        .any(|role| matches!(role, Role::Deny(_)));
    if denied && !software.drops() {
        return Some(format!(
            "the NIC denies what the software does not: {software:?}"
        ));
    }
    if !outcome.meters.is_empty() {
        tally.charged += 1;
    }
    for &m in &outcome.meters {
        let nic = program.meters[m].name.as_str();
        match software {
            Software::Charges(meter) if meter.as_deref() == Some(nic) => {}
            Software::Charges(meter) => {
                return Some(format!(
                    "the NIC charges meter {nic}, the software {meter:?}"
                ));
            }
            Software::Unclassifiable => tally.charged_dropped += 1,
            Software::Denied | Software::DefaultDenied => {
                return Some(format!(
                    "the NIC charges meter {nic} for a packet the software denies: {software:?}"
                ));
            }
        }
    }
    match outcome.verdict {
        Verdict::Delivered | Verdict::Untouched => None,
        Verdict::Dropped if denied => None,
        Verdict::Dropped if outcome.color == Some(Color::Red) && !outcome.meters.is_empty() => None,
        Verdict::Dropped => Some("the NIC drops without a deny or a red meter".to_string()),
        Verdict::Missed(group) => Some(format!("the NIC misses in group {group:?}")),
    }
}

/// The NIC meter must be at least as permissive as the software component it stands for.
fn check_profiles(limits: &RateLimits<PeeringRules>, program: &Program, plan: &Plan) {
    for (nic, lowered) in program
        .meters
        .iter()
        .zip(plan.meters.iter().map(|m| &m.key.profile))
    {
        let meter = limits
            .meters()
            .iter()
            .find(|m| m.name() == nic.name)
            .unwrap_or_else(|| unreachable!());
        let software = meter
            .component(nic.unit)
            .unwrap_or_else(|| unreachable!())
            .profile();
        let unit = match nic.unit {
            Unit::Bytes => MeterUnit::Bytes,
            Unit::Packets => MeterUnit::Packets,
        };
        assert_eq!(lowered.unit, unit, "meter {}", nic.name);
        let (cir, eir, cbs, ebs) = match lowered.algorithm {
            MeterAlgorithm::Srtcm { cir, cbs, ebs } => (cir, None, cbs, ebs),
            MeterAlgorithm::Rfc4115 { cir, eir, cbs, ebs } => (cir, Some(eir), cbs, ebs),
            MeterAlgorithm::Trtcm { .. } => unreachable!("the software has no RFC 2698 meters"),
        };
        // As mlx5 encodes them, in its scaled units.
        let shift = pmd_scale(unit);
        let rate = |r: u64| encoded_rate(r << shift);
        let burst = |b: u64| encoded_burst(b << shift);
        let software_cir = software.committed_rate().per_second().get();
        assert!(
            rate(cir) >= software_cir << shift,
            "meter {}: CIR {cir} encodes below the software's {software_cir}",
            nic.name
        );
        if let Some(software_eir) = software.excess_rate() {
            let coupled = software_eir.per_second().get() + software_cir;
            assert!(
                eir.is_some_and(|eir| rate(eir) >= coupled << shift),
                "meter {}: EIR {eir:?} encodes below the software's coupled {coupled}",
                nic.name
            );
        }
        let [committed_slack, excess_slack] = nic.lease_slack;
        assert!(
            burst(cbs) >= (software.committed_burst() + committed_slack) << shift
                && (software.excess_burst() == 0
                    || burst(ebs) >= (software.excess_burst() + excess_slack) << shift),
            "meter {}: the NIC's bursts {cbs}/{ebs} encode below the software's {}/{} with leases",
            nic.name,
            software.committed_burst(),
            software.excess_burst()
        );
    }
}

pub(crate) fn fate() -> TemplateAction {
    TemplateAction::Rss(dpdk::flow::template::RssTarget {
        queues: vec![RxQueueIndex(0), RxQueueIndex(1)],
        types: 0,
    })
}

impl Frame {
    /// Where the flow filter sends the decapsulated packet, as it does: no flow state, so an
    /// ordinary lookup.
    fn route(&mut self, flow_filter: &mut FlowFilter) {
        self.dst_vni = None;
        let Ok(mut packet) = Packet::new(TestBuffer::from_raw_data(&self.inner)) else {
            return;
        };
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(
            Vni::new_checked(self.src_vni).unwrap_or_else(|_| unreachable!()),
        ));
        let Some(packet) = flow_filter.process([packet]).next() else {
            return;
        };
        if packet.is_done() {
            return;
        }
        self.dst_vni = match packet.meta().dst_vpcd {
            Some(VpcDiscriminant::VNI(vni)) => Some(vni.as_u32()),
            _ => None,
        };
    }
}

/// Where the flow filter sends each source VPC's traffic in `overlay`.
pub(crate) fn destinations(overlay: &ValidatedOverlay) -> Vec<flow_filter::Destination> {
    flow_filter::FlowFilterContext::reference(overlay).destinations()
}

/// The flow filter stage of `overlay`, with the reference classifier.
fn flow_filter(overlay: &ValidatedOverlay) -> FlowFilter {
    let writer = FlowFilterContextWriter::new();
    writer.store(FlowFilterContext::reference(overlay));
    FlowFilter::new("flow-filter", writer.get_reader())
}

/// Compile and lower `overlay`'s ACLs and rate limits, and hold every frame to the cascade
/// contract, panicking at the first violation. Frames are aimed at `targets`.
fn check_overlay(overlay: &ValidatedOverlay, targets: &[RawRule], frames: &[RawFrame]) -> Tally {
    let writer: RateLimitWriter<PeeringRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    writer.apply(overlay, Backend::Reference).unwrap();
    let limits = writer.load();
    let acls = AclFilterContext::reference(overlay).unwrap();
    let routes = destinations(overlay);
    let mut routing = flow_filter(overlay);
    // As installing does: peerings of meters faster than the NIC meters stay in software.
    let program = Program::compile(&acls, &limits, &routes, &BTreeSet::new());
    let program = Program::compile(&acls, &limits, &routes, &crate::mlx5::unfit(&program));
    let plan = Plan::new(&program, &vteps(&program), &fate()).unwrap();
    check_profiles(&limits, &program, &plan);
    let mut tally = Tally::default();
    for raw in frames {
        let mut frame = raw.frame(targets);
        frame.route(&mut routing);
        let software = frame.software(&acls, &limits);
        let outcomes = plan.outcomes(&frame.wire()).unwrap();
        // Transit VXLAN is the underlay's: the NIC neither drops it nor charges a meter for it.
        for outcome in plan.outcomes(&frame.transit()).unwrap() {
            assert!(
                outcome.meters.is_empty()
                    && matches!(outcome.verdict, Verdict::Delivered | Verdict::Untouched),
                "transit VXLAN touched\nframe: {raw:?}\noutcome: {outcome:?}"
            );
        }
        // Software drops what it cannot route; the NIC may too.
        if frame.dst_vni.is_none() {
            continue;
        }
        for outcome in &outcomes {
            if let Some(why) = violation(&program, outcome, &software, &mut tally) {
                panic!(
                    "{why}\nframe: {raw:?}\ninner: {:02x?}\nsoftware: {software:?}\noutcome: {outcome:?}\nprogram: {program:#?}",
                    frame.inner
                );
            }
        }
    }
    tally
}

#[test]
fn the_nic_only_ever_does_what_the_software_would() {
    let total = std::panic::AssertUnwindSafe(std::cell::RefCell::new(Tally::default()));
    bolero::check!()
        .with_type::<([RawMeter; 4], Vec<RawRule>, RawAcls, Vec<RawFrame>)>()
        .for_each(|(meters, rules, acls, frames)| {
            let rules = &rules[..rules.len().min(6)];
            let overlay = overlay(meters, rules, acls).expect("generated configurations are valid");
            let tally = check_overlay(
                &overlay,
                &targets(rules, acls),
                &frames[..frames.len().min(16)],
            );
            let exposed = exposes(meters, rules, acls)
                .iter()
                .flatten()
                .any(|e| !matches!(e, RawExpose::Own));
            let mut total = total.borrow_mut();
            total.charged += tally.charged;
            total.charged_dropped += tally.charged_dropped;
            total.cases += 1;
            total.exposed += usize::from(exposed);
        });
    let total = total.0.into_inner();
    eprintln!(
        "differential: {} outcome(s) charged a meter, {} of them for unclassifiable packets; {} of {} cases with other exposes than the VPCs' own prefixes",
        total.charged, total.charged_dropped, total.exposed, total.cases
    );
}

fn meters() -> [RawMeter; 4] {
    std::array::from_fn(|_| RawMeter {
        rate: 1000,
        committed_burst: 1500,
        excess_burst: 0,
        excess_rate: None,
    })
}

fn check(rules: &[RawRule], frames: &[RawFrame]) -> usize {
    let acls = RawAcls::default();
    let overlay = overlay(&meters(), rules, &acls).expect("a valid configuration");
    check_overlay(&overlay, &targets(rules, &acls), frames).charged
}

fn aimed(aim: u8, l4: RawL4, fragment: RawFragment) -> RawFrame {
    RawFrame {
        aim: Some(aim),
        src_vpc: 0,
        src_bits: 1,
        dst_vpc: None,
        dst_bits: 5,
        l4,
        src_port: 0,
        dst_port: 1,
        fragment,
        hop_by_hop: false,
        vlan: None,
        tcp_flags: 0x10,
    }
}

fn peering_rule(v6: bool, proto: RawProto) -> RawRule {
    RawRule {
        peering: if v6 { 3 } else { 0 },
        reverse: false,
        src: vec![],
        dst: vec![],
        proto,
        meter: 0,
    }
}

/// Software sees a fragment's protocol as the fragment, and no ports: a rule naming a protocol
/// must not charge fragments in the NIC either.
#[test]
fn fragments_are_left_to_software_by_rules_naming_a_protocol() {
    let rules = [false, true].map(|v6| peering_rule(v6, RawProto::Udp));
    for aim in [0, 1] {
        assert!(check(&rules, &[aimed(aim, RawL4::Udp, RawFragment::Whole)]) > 0);
        for fragment in [RawFragment::First, RawFragment::Later(3)] {
            assert_eq!(check(&rules, &[aimed(aim, RawL4::Udp, fragment)]), 0);
        }
    }
}

/// The tolerated deviation: the ACL filter drops a packet whose upper-layer protocol it cannot
/// tell, before the rate limiter, while a rule for any protocol charges it in the NIC. Here, IPv4
/// carrying protocol 60 (an IPv6 extension header number).
#[test]
fn unclassifiable_packets_are_charged_by_the_nic_only() {
    let rules = [peering_rule(false, RawProto::Any)];
    let acls = RawAcls::default();
    let frame = aimed(0, RawL4::Other(60), RawFragment::Whole).frame(&rules);
    let overlay = overlay(&meters(), &rules, &acls).unwrap();
    let writer: RateLimitWriter<PeeringRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    writer.apply(&overlay, Backend::Reference).unwrap();
    let limits = writer.load();
    let filter = AclFilterContext::reference(&overlay).unwrap();
    assert_eq!(frame.software(&filter, &limits), Software::Unclassifiable);
    let program = Program::compile(&filter, &limits, &destinations(&overlay), &BTreeSet::new());
    let plan = Plan::new(&program, &vteps(&program), &fate()).unwrap();
    let outcomes = plan.outcomes(&frame.wire()).unwrap();
    assert!(outcomes.iter().all(|o| o.meters == [0]), "{outcomes:?}");
}

/// A deny the NIC enforces drops in the NIC what the ACL filter drops, before any meter charges
/// it. An allow before it keeps it out of the NIC, and with it the rest of its peering's policy.
#[test]
fn denies_drop_in_the_nic_unless_an_earlier_allow_overlaps() {
    let deny = |deny: bool| RawAclRule {
        rule: peering_rule(false, RawProto::Udp),
        deny,
        flow: false,
    };
    let rules = [peering_rule(false, RawProto::Any)];
    for (acl, denied) in [
        (vec![deny(true)], true),
        (vec![deny(false), deny(true)], false),
    ] {
        let acls = RawAcls {
            exposes: Default::default(),
            defaults: [Some(false), None, None, None],
            rules: acl,
        };
        let overlay = overlay(&meters(), &rules, &acls).unwrap();
        let writer: RateLimitWriter<PeeringRules> =
            RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
        writer.apply(&overlay, Backend::Reference).unwrap();
        let filter = AclFilterContext::reference(&overlay).unwrap();
        let program = Program::compile(
            &filter,
            &writer.load(),
            &destinations(&overlay),
            &BTreeSet::new(),
        );
        assert_eq!(program.denies.len(), usize::from(denied), "{program:#?}");
        let tally = check_overlay(
            &overlay,
            &rules,
            &[aimed(0, RawL4::Udp, RawFragment::Whole)],
        );
        // Denied in the NIC, nothing is charged; with the deny in software, so is the peering.
        assert_eq!(tally.charged_dropped, 0);
        assert_eq!(program.rules.len(), usize::from(denied), "{program:#?}");
        let frame = aimed(0, RawL4::Udp, RawFragment::Whole).frame(&rules);
        let plan = Plan::new(&program, &vteps(&program), &fate()).unwrap();
        let outcomes = plan.outcomes(&frame.wire()).unwrap();
        assert_eq!(
            outcomes
                .iter()
                .all(|o| o.verdict == Verdict::Dropped && o.meters.is_empty()),
            denied,
            "{outcomes:?}"
        );
    }
}

/// A default deny keeps its peering in software, rate limits too; other peerings are not
/// affected.
#[test]
fn a_default_deny_keeps_its_peering_and_only_it_in_software() {
    let limit = |peering| RawRule {
        peering,
        reverse: false,
        src: vec![],
        dst: vec![],
        proto: RawProto::Any,
        meter: 0,
    };
    let rules = [limit(0), limit(1)];
    let acls = RawAcls {
        exposes: Default::default(),
        defaults: [Some(true), None, None, None],
        rules: vec![RawAclRule {
            rule: peering_rule(false, RawProto::Udp),
            deny: false,
            flow: true,
        }],
    };
    let overlay = overlay(&meters(), &rules, &acls).unwrap();
    let writer: RateLimitWriter<PeeringRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    writer.apply(&overlay, Backend::Reference).unwrap();
    let filter = AclFilterContext::reference(&overlay).unwrap();
    let program = Program::compile(
        &filter,
        &writer.load(),
        &destinations(&overlay),
        &BTreeSet::new(),
    );
    // Only the second peering's rate limit is offloaded.
    assert_eq!(program.rules.len(), 1, "{program:#?}");
    assert_eq!(program.rules[0].matches.src_vni.as_u32(), VPCS[0].vni);
    let dst = program.rules[0].matches.destination;
    assert!(
        matches!(dst, crate::program::Prefix::V4(a, _) if a.octets()[1] == 2),
        "{dst:?}"
    );
    assert!(
        program
            .refused
            .iter()
            .all(|(_, _, refusal)| *refusal == crate::program::Refusal::DefaultDeny)
    );
}

/// A deny of connection openings (SYN without ACK), the crude SYN-flood defense TCP flag matches
/// are for, is enforced in the NIC: it drops a SYN, and lets a SYN-ACK through.
#[test]
fn a_syn_deny_drops_syns_in_the_nic() {
    let rules = [peering_rule(false, RawProto::Any)];
    let acls = RawAcls {
        exposes: Default::default(),
        defaults: [Some(false), None, None, None],
        rules: vec![RawAclRule {
            rule: peering_rule(false, RawProto::TcpFlags(0x02, 0x12)),
            deny: true,
            flow: false,
        }],
    };
    let overlay = overlay(&meters(), &rules, &acls).unwrap();
    let writer: RateLimitWriter<PeeringRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    writer.apply(&overlay, Backend::Reference).unwrap();
    let filter = AclFilterContext::reference(&overlay).unwrap();
    let program = Program::compile(
        &filter,
        &writer.load(),
        &destinations(&overlay),
        &BTreeSet::new(),
    );
    assert_eq!(program.denies.len(), 1, "{program:#?}");
    assert_eq!(program.denies[0].matches.tcp_flags, Some((0x02, 0x12)));
    let plan = Plan::new(&program, &vteps(&program), &fate()).unwrap();
    let targets = targets(&rules, &acls);
    for (flags, dropped) in [(0x02, true), (0x12, false), (0x10, false)] {
        let mut raw = aimed(0, RawL4::Tcp, RawFragment::Whole);
        raw.tcp_flags = flags;
        let frame = raw.frame(&targets);
        let outcomes = plan.outcomes(&frame.wire()).unwrap();
        assert!(
            outcomes
                .iter()
                .all(|o| (o.verdict == Verdict::Dropped && o.meters.is_empty()) == dropped),
            "flags {flags:#04x}: {outcomes:?}"
        );
    }
    check_overlay(
        &overlay,
        &targets,
        &[aimed(1, RawL4::Tcp, RawFragment::Whole)],
    );
}

/// A masquerading peer's prefix takes only replies, and a port-forwarding peer only its port of
/// its published address: software sends the rest to another peer, here one with a default
/// expose. The NIC must leave that traffic alone, even with a rate limit and a deny of the
/// partly-taking peering covering it.
#[test]
fn traffic_a_peer_takes_only_part_of_is_left_alone() {
    // B -> A, UDP; C exposes a default to B.
    let rule = RawRule {
        reverse: true,
        ..peering_rule(false, RawProto::Udp)
    };
    for partly in [
        RawExpose::Masquerade,
        RawExpose::PortForward {
            tcp: false,
            port: 1,
        },
    ] {
        let mut exposes = [[RawExpose::Own; 2]; 4];
        exposes[0][0] = partly;
        exposes[2][1] = RawExpose::Default;
        let acls = RawAcls {
            exposes,
            defaults: [Some(false), None, None, None],
            rules: vec![RawAclRule {
                rule: rule.clone(),
                deny: true,
                flow: false,
            }],
        };
        let overlay = with_exposes(&meters(), std::slice::from_ref(&rule), &acls, &exposes)
            .unwrap_or_else(|| panic!("{partly:?} does not validate"));
        let frames: Vec<RawFrame> = [1u8, 2]
            .map(|dst_port| RawFrame {
                dst_port,
                ..aimed(0, RawL4::Udp, RawFragment::Whole)
            })
            .into();
        check_overlay(&overlay, std::slice::from_ref(&rule), &frames);
        // The frames go where the case needs them, or it proves nothing (frames software cannot
        // route are not checked): a masquerading peer takes neither, a port-forwarding one only
        // its port; the default-exposing peer the rest.
        let mut routing = flow_filter(&overlay);
        let routed: Vec<Option<u32>> = frames
            .iter()
            .map(|raw| {
                let mut frame = raw.frame(std::slice::from_ref(&rule));
                frame.route(&mut routing);
                frame.dst_vni
            })
            .collect();
        let (a, c) = (Some(VPCS[0].vni), Some(VPCS[2].vni));
        let expected = match partly {
            RawExpose::Masquerade => vec![c, c],
            _ => vec![a, c],
        };
        assert_eq!(routed, expected, "{partly:?}");
    }
}
