// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fuzz generators shared by the flow-filter property tests: valid-by-construction overlays and
//! probes biased to land inside the generated prefixes.
//!
//! bolero generates a compact [`OverlaySpec`] (so shrinking operates on structure, not on whole
//! configs); [`OverlaySpec::build`] normalizes it into a config that satisfies every validation
//! rule and then runs the *real* validation. A rejection is itself a finding: either the
//! generator's model of the rules or the config rules themselves drifted.
//!
//! Prefixes come from a pool of disjoint per-expose blocks, so overlaps never arise by accident.
//! The overlaps config explicitly permits are then injected deliberately, because that is where
//! priority/precedence bugs live:
//!
//! - a port-forwarding `/32` (or `/128`) nested inside a masquerade block,
//! - a port-forwarding block of the *same length* as a masquerade block (the rte_acl priority
//!   tie that the port-forwarding tie-break bit resolves),
//! - two port-forwarding exposes sharing prefixes and ports, distinguished only by L4 protocol.
//!
//! Deliberately out of scope: cross-peering masquerade/masquerade destination overlaps (legal,
//! but the winning destination VPC of the resulting equal-priority marker rules is unspecified,
//! and benign only because the NF gates masquerade verdicts on the flow's destination), and
//! mixed-IP-version manifests (they currently pass validation but yield one-sided tables).

#![cfg(test)]

use bolero::TypeGenerator;
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use lpm::prefix::{L4Protocol, PortRange, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use net::vxlan::Vni;
use std::net::IpAddr;

/// The four VPCs every generated overlay contains.
pub(crate) const VNIS: [u32; 4] = [100, 200, 300, 400];
/// A VNI no generated VPC uses; probes drawing it must miss.
const BOGUS_VNI: u32 = 999;

/// A source VPC discriminant no generated overlay contains: every stage-1 lookup with it misses.
pub(crate) fn bogus_vpcd() -> VpcDiscriminant {
    VpcDiscriminant::from_vni(Vni::new_checked(BOGUS_VNI).unwrap())
}
/// Peering slot `i`, when present, connects this fixed VPC pair. Distinct pairs by construction,
/// so the one-peering-per-VPC-pair rule always holds.
const PEERING_PAIRS: [(usize, usize); 4] = [(0, 1), (0, 2), (1, 2), (2, 3)];

/// Port ranges used by every generated port-forwarding expose (private/public side). Config
/// requires equal (address x port) counts on both sides, which these satisfy for every prefix
/// shape the generator emits.
pub(crate) const FW_PRIVATE_PORTS: (u16, u16) = (1000, 1004);
pub(crate) const FW_PUBLIC_PORTS: (u16, u16) = (2000, 2004);
/// Host byte used for the nested port-forwarding `/32` (or `/128`) inside a block.
const FW_HOST: u8 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TypeGenerator)]
pub(crate) enum FwProto {
    Any,
    Tcp,
    Udp,
}

impl FwProto {
    fn to_l4(self) -> Option<L4Protocol> {
        match self {
            FwProto::Any => None,
            FwProto::Tcp => Some(L4Protocol::Tcp),
            FwProto::Udp => Some(L4Protocol::Udp),
        }
    }
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum ExposeSpec {
    Plain,
    StaticNat,
    Masquerade,
    /// Masquerade plus a port-forwarding host prefix nested inside its blocks (legal overlap).
    MasqueradeNestingPortFw(FwProto),
    /// Masquerade plus a port-forwarding block of the SAME prefix length (legal overlap; the
    /// equal-length rte_acl priority tie that the port-forwarding bit must break).
    MasqueradeSameLenPortFw(FwProto),
    PortForwarding(FwProto),
    /// Two port-forwarding exposes sharing prefixes and ports, distinguished only by protocol
    /// (TCP vs UDP): the other overlap config permits.
    PortFwProtoPair,
}

impl ExposeSpec {
    /// Whether this spec includes stateful NAT (masquerade or port forwarding).
    fn is_stateful(self) -> bool {
        !matches!(self, ExposeSpec::Plain | ExposeSpec::StaticNat)
    }

    fn has_nat(self) -> bool {
        !matches!(self, ExposeSpec::Plain)
    }
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct ManifestSpec {
    /// Up to two expose specs (some expand to two actual exposes).
    exposes: [Option<ExposeSpec>; 2],
    /// Whether the manifest carries a default (catch-all) expose.
    default: bool,
}

impl ManifestSpec {
    fn expose_specs(&self) -> impl Iterator<Item = ExposeSpec> + '_ {
        self.exposes.iter().flatten().copied()
    }

    fn is_empty(&self) -> bool {
        self.exposes.iter().all(Option::is_none) && !self.default
    }

    fn has_stateful(&self) -> bool {
        self.expose_specs().any(ExposeSpec::is_stateful)
    }

    fn has_nat(&self) -> bool {
        self.expose_specs().any(ExposeSpec::has_nat)
    }

    fn strip_nat(&mut self) {
        for slot in self.exposes.iter_mut().flatten() {
            if slot.has_nat() {
                *slot = ExposeSpec::Plain;
            }
        }
    }

    fn drop_default(&mut self) {
        self.default = false;
        if self.is_empty() {
            self.exposes[0] = Some(ExposeSpec::Plain);
        }
    }
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct PeeringSpec {
    /// IP version of the whole peering (manifests are kept single-version).
    v6: bool,
    local: ManifestSpec,
    remote: ManifestSpec,
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct OverlaySpec {
    peerings: [Option<PeeringSpec>; 4],
}

/// A materialized overlay plus the number of allocated prefix blocks (probe specs map their
/// block selectors into that range so probes land inside generated prefixes).
pub(crate) struct BuiltOverlay {
    pub(crate) overlay: ValidatedOverlay,
    pub(crate) blocks: u8,
}

impl OverlaySpec {
    /// Normalize the raw spec into a valid configuration and build it. Panics if the result
    /// fails real config validation (generator/config drift).
    pub(crate) fn build(&self) -> BuiltOverlay {
        let mut spec = *self;

        // At least one peering, and no empty manifests.
        if spec.peerings.iter().all(Option::is_none) {
            spec.peerings[0] = Some(PeeringSpec {
                v6: false,
                local: ManifestSpec {
                    exposes: [Some(ExposeSpec::Plain), None],
                    default: false,
                },
                remote: ManifestSpec {
                    exposes: [Some(ExposeSpec::Plain), None],
                    default: false,
                },
            });
        }
        for peering in spec.peerings.iter_mut().flatten() {
            for manifest in [&mut peering.local, &mut peering.remote] {
                if manifest.is_empty() {
                    manifest.exposes[0] = Some(ExposeSpec::Plain);
                }
            }
            // A default expose cannot face another default expose within one peering.
            if peering.local.default && peering.remote.default {
                peering.remote.drop_default();
            }
            // Stateful NAT on one side of a peering forbids any NAT on the other side.
            if peering.local.has_stateful() && peering.remote.has_nat() {
                peering.remote.strip_nat();
            } else if peering.remote.has_stateful() && peering.local.has_nat() {
                peering.local.strip_nat();
            }
        }
        // Each VPC may see at most one default destination across all of its peerings. A default
        // on one side of a peering is a catch-all destination for the VPC on the *other* side.
        let mut has_default_dst = [false; VNIS.len()];
        for (slot, peering) in spec.peerings.iter_mut().enumerate() {
            let Some(peering) = peering else { continue };
            let (a, b) = PEERING_PAIRS[slot];
            if peering.local.default {
                if has_default_dst[b] {
                    peering.local.drop_default();
                } else {
                    has_default_dst[b] = true;
                }
            }
            if peering.remote.default {
                if has_default_dst[a] {
                    peering.remote.drop_default();
                } else {
                    has_default_dst[a] = true;
                }
            }
        }

        // Materialize.
        let mut vpc_table = VpcTable::new();
        for (i, vni) in VNIS.iter().enumerate() {
            vpc_table
                .add(Vpc::new(&vpc_name(i), &format!("VPC{:02}", i + 1), *vni).unwrap())
                .unwrap();
        }
        let mut peering_table = VpcPeeringTable::new();
        let mut blocks: u8 = 0;
        for (slot, peering) in spec.peerings.iter().enumerate() {
            let Some(peering) = peering else { continue };
            let (a, b) = PEERING_PAIRS[slot];
            let local = build_manifest(&vpc_name(a), &peering.local, peering.v6, &mut blocks);
            let remote = build_manifest(&vpc_name(b), &peering.remote, peering.v6, &mut blocks);
            peering_table
                .add(VpcPeering::with_default_group(
                    &format!("{}-to-{}", vpc_name(a), vpc_name(b)),
                    local,
                    remote,
                ))
                .unwrap();
        }
        let overlay = Overlay::new(vpc_table, peering_table)
            .validate()
            .unwrap_or_else(|e| {
                panic!(
                    "generated overlay must validate (generator/config drift): {e}\nspec: {spec:?}"
                )
            });
        BuiltOverlay { overlay, blocks }
    }
}

fn vpc_name(index: usize) -> String {
    format!("vpc{}", index + 1)
}

fn build_manifest(vpc_name: &str, spec: &ManifestSpec, v6: bool, blocks: &mut u8) -> VpcManifest {
    let mut exposes = Vec::new();
    for expose_spec in spec.expose_specs() {
        let n = *blocks;
        *blocks += 1;
        match expose_spec {
            ExposeSpec::Plain => exposes.push(plain(n, v6)),
            ExposeSpec::StaticNat => exposes.push(static_nat(n, v6)),
            ExposeSpec::Masquerade => exposes.push(masquerade(n, v6)),
            ExposeSpec::MasqueradeNestingPortFw(proto) => {
                exposes.push(masquerade(n, v6));
                exposes.push(portfw_host(n, v6, proto));
            }
            ExposeSpec::MasqueradeSameLenPortFw(proto) => {
                exposes.push(masquerade(n, v6));
                exposes.push(portfw_block(n, v6, proto));
            }
            ExposeSpec::PortForwarding(proto) => exposes.push(portfw_host(n, v6, proto)),
            ExposeSpec::PortFwProtoPair => {
                exposes.push(portfw_host(n, v6, FwProto::Tcp));
                exposes.push(portfw_host(n, v6, FwProto::Udp));
            }
        }
    }
    if spec.default {
        exposes.push(VpcExpose::empty().set_default());
    }
    VpcManifest::with_exposes(vpc_name, exposes)
}

// -------------------------------------------------------------------------------------------------
// Prefix pool. Block n owns the disjoint private/public prefixes below; nothing else touches them.

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

fn host_prefix(n: u8, public: bool, v6: bool) -> String {
    if v6 {
        let net = if public { "db9" } else { "db8" };
        format!("2001:{net}:0:{n:x}::{FW_HOST:x}/128")
    } else {
        let net = if public { 20 } else { 10 };
        format!("{net}.{n}.0.{FW_HOST}/32")
    }
}

/// An address inside block `n` (or nowhere near the pool, for hosts outside a generated block's
/// host range -- both are useful probes).
pub(crate) fn block_addr(n: u8, host: u8, public: bool, v6: bool) -> IpAddr {
    if v6 {
        let net = if public { "db9" } else { "db8" };
        format!("2001:{net}:0:{n:x}::{host:x}").parse().unwrap()
    } else {
        let net = if public { 20 } else { 10 };
        format!("{net}.{n}.0.{host}").parse().unwrap()
    }
}

fn plain(n: u8, v6: bool) -> VpcExpose {
    VpcExpose::empty().ip(private_block(n, v6).as_str().into())
}

fn static_nat(n: u8, v6: bool) -> VpcExpose {
    VpcExpose::empty()
        .make_static_nat()
        .unwrap()
        .ip(private_block(n, v6).as_str().into())
        .as_range(public_block(n, v6).as_str().into())
        .unwrap()
}

fn masquerade(n: u8, v6: bool) -> VpcExpose {
    VpcExpose::empty()
        .make_masquerade(None)
        .unwrap()
        .ip(private_block(n, v6).as_str().into())
        .as_range(public_block(n, v6).as_str().into())
        .unwrap()
}

fn portfw(private: &str, public: &str, proto: FwProto) -> VpcExpose {
    VpcExpose::empty()
        .make_port_forwarding(None, proto.to_l4())
        .unwrap()
        .ip(PrefixWithOptionalPorts::new(
            private.into(),
            Some(PortRange::new(FW_PRIVATE_PORTS.0, FW_PRIVATE_PORTS.1).unwrap()),
        ))
        .as_range(PrefixWithOptionalPorts::new(
            public.into(),
            Some(PortRange::new(FW_PUBLIC_PORTS.0, FW_PUBLIC_PORTS.1).unwrap()),
        ))
        .unwrap()
}

/// Port forwarding on a single host inside block `n`.
fn portfw_host(n: u8, v6: bool, proto: FwProto) -> VpcExpose {
    portfw(&host_prefix(n, false, v6), &host_prefix(n, true, v6), proto)
}

/// Port forwarding on the whole of block `n` (same prefix length as a masquerade block).
fn portfw_block(n: u8, v6: bool, proto: FwProto) -> VpcExpose {
    portfw(&private_block(n, v6), &public_block(n, v6), proto)
}

// -------------------------------------------------------------------------------------------------
// Probes.

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum PortSel {
    Exact(u16),
    /// A port inside (or at the edge of) the shared port-forwarding private range.
    FwPrivate(u8),
    /// A port inside (or at the edge of) the shared port-forwarding public range.
    FwPublic(u8),
}

impl PortSel {
    fn resolve(self) -> u16 {
        let span = |(lo, hi): (u16, u16), k: u8| lo + u16::from(k) % (hi - lo + 2); // +1 past end
        match self {
            PortSel::Exact(p) => p,
            PortSel::FwPrivate(k) => span(FW_PRIVATE_PORTS, k),
            PortSel::FwPublic(k) => span(FW_PUBLIC_PORTS, k),
        }
    }
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum ProbeProto {
    Tcp,
    Udp,
    Icmp,
}

impl ProbeProto {
    fn next_header(self) -> NextHeader {
        match self {
            ProbeProto::Tcp => NextHeader::TCP,
            ProbeProto::Udp => NextHeader::UDP,
            ProbeProto::Icmp => NextHeader::ICMP,
        }
    }
}

/// One packet's lookup question, in spec form. Block selectors are reduced modulo the built
/// overlay's block count so probes usually land inside some generated prefix; hits require the
/// blocks to pair up with the right peering, misses come for free.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct ProbeSpec {
    vni_sel: u8,
    v6: bool,
    /// Give the destination the opposite IP version of the source.
    cross_version: bool,
    src_block: u8,
    src_public: bool,
    src_host: u8,
    dst_block: u8,
    dst_public: bool,
    dst_host: u8,
    proto: ProbeProto,
    sport: PortSel,
    dport: PortSel,
}

/// A resolved probe: the arguments of one route lookup.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Probe {
    pub(crate) src_vpcd: VpcDiscriminant,
    pub(crate) src_ip: IpAddr,
    pub(crate) dst_ip: IpAddr,
    pub(crate) proto: NextHeader,
    pub(crate) ports: Option<(u16, u16)>,
}

impl ProbeSpec {
    pub(crate) fn resolve(&self, blocks: u8) -> Probe {
        let nblocks = blocks.max(1);
        let vni = match self.vni_sel as usize % (VNIS.len() + 1) {
            i if i < VNIS.len() => VNIS[i],
            _ => BOGUS_VNI,
        };
        let dst_v6 = self.v6 ^ self.cross_version;
        Probe {
            src_vpcd: VpcDiscriminant::from_vni(Vni::new_checked(vni).unwrap()),
            src_ip: block_addr(
                self.src_block % nblocks,
                self.src_host,
                self.src_public,
                self.v6,
            ),
            dst_ip: block_addr(
                self.dst_block % nblocks,
                self.dst_host,
                self.dst_public,
                dst_v6,
            ),
            proto: self.proto.next_header(),
            ports: match self.proto {
                ProbeProto::Icmp => None,
                _ => Some((self.sport.resolve(), self.dport.resolve())),
            },
        }
    }
}
