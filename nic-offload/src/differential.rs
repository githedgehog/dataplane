// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The software rate limiter as the oracle for the NIC: generated rate limits are compiled and
//! lowered onto mlx5 as they would be on a port, and every way the [model](crate::model) says the
//! NIC may treat a generated frame is held to the cascade contract against what the software
//! classifier does with the decapsulated packet:
//!
//! - the NIC charges a frame only to the meter the software charges it to;
//! - the NIC drops a frame only as red from such a meter, and only for a meter that drops red;
//! - every meter the NIC enforces is at least as permissive as the software component it stands
//!   for.
//!
//! Frames the software could not route (no peer exposes the destination) are dropped by it
//! anyway, so the NIC may do anything with them but change them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU64, NonZeroUsize};

use acl::table::Backend;
use acl_filter::AclFilterContext;
use config::external::overlay::acl::{
    Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope,
};
use config::external::overlay::ratelimit::{
    ColorAction, ColorActions, Meter, MeterProfile, RateLimitRule, RateLimitTables,
};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use dpdk::flow::template::{Color, MeterAlgorithm, MeterUnit, TemplateAction};
use dpdk::queue::rx::RxQueueIndex;
use lpm::prefix::with_ports::{PortRange, PrefixPortsSet};
use lpm::prefix::{Prefix as LpmPrefix, PrefixWithOptionalPorts};
use net::buffer::TestBuffer;
use net::packet::{Packet, VpcDiscriminant};
use net::vxlan::Vni;
use policer::{Profile, Rate};
use rate_limit::{Classify, PeeringRules, RateLimitWriter, RateLimits, Unit};

use crate::mlx5::{Plan, Role};
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
    Icmp,
    Other(u8),
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
        let ports = matches!(self.proto, RawProto::Udp | RawProto::Tcp);
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
    defaults: [Option<bool>; 4],
    pub(crate) rules: Vec<RawAclRule>,
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
                    scope: if r.flow {
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
    let mut vpcs = VpcTable::new();
    for spec in &VPCS {
        vpcs.add(Vpc::new(spec.name, spec.id, spec.vni).ok()?)
            .ok()?;
    }
    let mut peerings = VpcPeeringTable::new();
    for (peering, &(l, r)) in PEERINGS.iter().enumerate() {
        let manifest = |vpc: usize| {
            let spec = &VPCS[vpc];
            let mut manifest = VpcManifest::new(spec.name);
            let prefix = LpmPrefix::try_from((spec.expose, spec.len)).ok()?;
            manifest.add_expose(VpcExpose::empty().ip(prefix.into()));
            Some(manifest)
        };
        let mut vpc_peering = VpcPeering::new(
            &peering_name(peering),
            manifest(l)?,
            manifest(r)?,
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
            Some(RawProto::Tcp) => RawL4::Tcp,
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
                h.extend([0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0]);
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

impl Frame {
    /// The frame on the underlay wire: IPv4, UDP to the VXLAN port, VXLAN with the source VNI.
    fn wire(&self) -> Vec<u8> {
        self.wire_to([0x02, 0, 0, 0, 0, 4], 0)
    }

    /// The frame on the underlay wire to `dst`, with outer IP identification `id`, which no
    /// pattern matches: it tells frames apart on a real port.
    pub(crate) fn wire_to(&self, dst: [u8; 6], id: u16) -> Vec<u8> {
        let mut f = Vec::from(dst);
        f.extend([0x02, 0, 0, 0, 0, 3, 0x08, 0x00]);
        let udp_len = u16::try_from(16 + self.inner.len()).unwrap_or(u16::MAX);
        let total = udp_len.saturating_add(20);
        let mut ip = vec![0x45, 0];
        ip.extend(total.to_be_bytes());
        ip.extend(id.to_be_bytes());
        ip.extend([0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
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
    /// Outcomes charging a meter for a packet the software drops (or drops unless it is a reply):
    /// the tolerated deviation.
    charged_dropped: usize,
    /// Of those, by why the software drops it: an ACL rule denies it (one the NIC was not given),
    /// the peering denies by default, or the ACL filter cannot classify it.
    by_cause: [usize; 3],
}

/// The ways `outcome` breaks the cascade contract for a frame `software` treats so.
///
/// One deviation is tolerated, explicitly: the NIC may charge a meter for a packet the software
/// drops before its rate limiter (an ACL denies it, or cannot classify it), which the software
/// never charges. Such traffic uses up the NIC's budget but not the software's. Offloading the
/// denies shrinks it; it is counted in [`Tally::charged_dropped`].
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
            Software::Denied | Software::DefaultDenied | Software::Unclassifiable => {
                tally.charged_dropped += 1;
                tally.by_cause[match software {
                    Software::Denied => 0,
                    Software::DefaultDenied => 1,
                    _ => 2,
                }] += 1;
            }
        }
    }
    match outcome.verdict {
        Verdict::Delivered | Verdict::Untouched => None,
        Verdict::Dropped if denied => None,
        Verdict::Dropped if outcome.color == Some(Color::Red) && !outcome.meters.is_empty() => None,
        Verdict::Dropped => Some("the NIC drops without a deny or a red meter".to_string()),
        Verdict::Missed(group) => Some(format!("the NIC misses in group {}", group.0)),
    }
}

/// The NIC meter must be at least as permissive as the software component it stands for.
fn check_profiles(limits: &RateLimits<PeeringRules>, program: &Program, plan: &Plan) {
    for (nic, lowered) in program.meters.iter().zip(&plan.profiles) {
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
        assert_eq!(
            cir,
            software.committed_rate().per_second().get(),
            "meter {}",
            nic.name
        );
        assert_eq!(
            eir,
            software.excess_rate().map(|r| r.per_second().get()),
            "meter {}",
            nic.name
        );
        assert!(
            cbs >= software.committed_burst() && ebs >= software.excess_burst(),
            "meter {}: the NIC's bursts {cbs}/{ebs} are below the software's {}/{}",
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

/// Compile and lower `overlay`'s ACLs and rate limits, and hold every frame to the cascade
/// contract, panicking at the first violation. Frames are aimed at `targets`.
fn check_overlay(overlay: &ValidatedOverlay, targets: &[RawRule], frames: &[RawFrame]) -> Tally {
    let writer: RateLimitWriter<PeeringRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    writer.apply(overlay, Backend::Reference).unwrap();
    let limits = writer.load();
    let acls = AclFilterContext::reference(overlay).unwrap();
    let program = Program::compile(&acls, &limits);
    let plan = Plan::new(&program, &fate()).unwrap();
    check_profiles(&limits, &program, &plan);
    let mut tally = Tally::default();
    for raw in frames {
        let frame = raw.frame(targets);
        let software = frame.software(&acls, &limits);
        let outcomes = plan.outcomes(&frame.wire()).unwrap();
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
            let mut total = total.borrow_mut();
            total.charged += tally.charged;
            total.charged_dropped += tally.charged_dropped;
            for (sum, n) in total.by_cause.iter_mut().zip(tally.by_cause) {
                *sum += n;
            }
        });
    let total = total.0.into_inner();
    let [denied, default_denied, unclassifiable] = total.by_cause;
    eprintln!(
        "differential: {} outcome(s) charged a meter, {} of them for packets the software drops: \
         {denied} denied by a rule the NIC lacks, {default_denied} denied by default, \
         {unclassifiable} unclassifiable",
        total.charged, total.charged_dropped
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
    let plan = Plan::new(&Program::compile(&filter, &limits), &fate()).unwrap();
    let outcomes = plan.outcomes(&frame.wire()).unwrap();
    assert!(outcomes.iter().all(|o| o.meters == [0]), "{outcomes:?}");
}

/// A deny the NIC enforces drops in the NIC what the ACL filter drops, before any meter charges
/// it; an allow before it keeps it out of the NIC, and the frame is charged, as in software.
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
            defaults: [Some(false), None, None, None],
            rules: acl,
        };
        let overlay = overlay(&meters(), &rules, &acls).unwrap();
        let writer: RateLimitWriter<PeeringRules> =
            RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
        writer.apply(&overlay, Backend::Reference).unwrap();
        let filter = AclFilterContext::reference(&overlay).unwrap();
        let program = Program::compile(&filter, &writer.load());
        assert_eq!(program.denies.len(), usize::from(denied), "{program:#?}");
        let tally = check_overlay(
            &overlay,
            &rules,
            &[aimed(0, RawL4::Udp, RawFragment::Whole)],
        );
        // Denied in the NIC, nothing is charged; allowed first, the software charges it too.
        assert_eq!(tally.charged_dropped, 0);
        let frame = aimed(0, RawL4::Udp, RawFragment::Whole).frame(&rules);
        let plan = Plan::new(&program, &fate()).unwrap();
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
