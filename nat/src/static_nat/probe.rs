// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packets drawn relative to a static NAT configuration.
//!
//! A [`bolero::TypeGenerator`] over `Packet` produces packets that miss every table a generated
//! configuration builds, so a property driven by one explores the miss path and nothing else. The
//! [development guide][crate] makes the same argument one level up, about generating configuration
//! values rather than building configurations from operations: a generator that does not know what
//! the thing under test is configured for reaches only its rejection paths.
//!
//! So the configuration is a **parameter to resolution**, not a predicate to filter against. A
//! [`ProbeSpec`] is drawn without reference to any configuration -- it is a handful of indices --
//! and [`ProbeSpec::resolve`] interprets it against a [`Fabric`]. Resolution is total: every draw
//! becomes a packet, and the ones that are *meant* to miss miss deliberately, named by [`Stray`],
//! rather than by accident.
//!
//! This mirrors `acl-filter`'s `ProbeSpec`, which resolves against a built overlay the same way.
//!
//! # The arrival state is the network function's precondition
//!
//! [`StaticNat`] sits in the middle of the pipeline and assumes its predecessors have annotated the
//! packet: a source and destination VPC discriminant, the overlay flag, and the two flags saying
//! which directions of translation are wanted. Nothing in the type system says so -- `process`
//! silently passes over a packet that lacks them, and `process_packet` drops one whose
//! discriminants are missing.
//!
//! [`Arrival`] writes that state down in one place. It is the network function's precondition made
//! explicit, which is what the development guide asks for when it puts contracts on functions
//! rather than on the pipeline: the assumption travels with the stage instead of being re-derived
//! by every test that drives it. `masquerade`'s tests hand-roll the same thing as a mock stage.

#![cfg(test)]

use crate::static_nat::nf::StaticNat;
use crate::static_nat::setup::build_nat_configuration;
use bolero::TypeGenerator;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::{
    LOCAL_VNI, REMOTE_VNI, overlay_with_exposes,
};
use lpm::prefix::{PortRange, PrefixWithOptionalPorts};
use net::buffer::TestBuffer;
use net::ip::{NextHeader, UnicastIpAddr};
use net::packet::test_utils::{
    build_test_ipv4_packet_with_transport, build_test_ipv6_packet_with_transport,
};
use net::packet::{Packet, VpcDiscriminant};
use net::tcp::port::TcpPort;
use net::udp::UdpPort;
use net::vxlan::Vni;
use std::net::IpAddr;

/// The TTL every probe is built with, so that a property can tell a translation from a rewrite of
/// anything else.
pub(crate) const PROBE_TTL: u8 = 64;

/// A VNI no generated configuration uses, for the probe that asks to be looked up in a table that
/// does not exist.
const ABSENT_VNI: u32 = 4_000;

pub(crate) fn vni(raw: u32) -> Vni {
    Vni::new_checked(raw).unwrap_or_else(|_| unreachable!("{raw} is a legal vni"))
}

/// One address the configuration names, and the ports it names alongside it.
///
/// Static NAT permits a port range on a prefix, and a prefix that carries one is mapped address and
/// port *together*: the private side's total, counted as addresses times ports, has to equal the
/// public side's, but the two may divide that total differently. So an address on its own is not a
/// thing the configuration maps -- the pair is -- and a probe has to carry the range it may draw a
/// port from or it will miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Endpoint {
    pub(crate) addr: IpAddr,
    /// The ports the prefix this address came from carries, if any.
    pub(crate) ports: Option<PortRange>,
}

impl Endpoint {
    /// A port this endpoint is mapped on, chosen by an arbitrary index.
    ///
    /// Total, so a draw always lands on a port the configuration covers rather than near one. Port
    /// 0 is not a legal port on either transport and no expose may name it.
    pub(crate) fn port(&self, index: u16) -> u16 {
        match self.ports {
            None => index.max(1),
            Some(range) => {
                let len = u32::try_from(range.len()).unwrap_or(u32::from(u16::MAX));
                let offset = u32::from(index) % len.max(1);
                u16::try_from(u32::from(range.start()) + offset).unwrap_or(range.end())
            }
        }
    }
}

/// Every address-and-ports pair a set of prefixes covers.
///
/// The static NAT generator keeps both sides of an expose small enough that this is a handful of
/// endpoints, which is what lets a property enumerate rather than sample.
pub(crate) fn endpoints<'a>(
    prefixes: impl IntoIterator<Item = &'a PrefixWithOptionalPorts>,
) -> Vec<Endpoint> {
    let mut out = Vec::new();
    for prefix_with_ports in prefixes {
        let ports = prefix_with_ports.ports();
        let prefix = prefix_with_ports.prefix();
        let (start, end) = (prefix.as_address(), prefix.last_address());
        let (mut bits, last) = match (start, end) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (u128::from(a.to_bits()), u128::from(b.to_bits())),
            (IpAddr::V6(a), IpAddr::V6(b)) => (a.to_bits(), b.to_bits()),
            _ => unreachable!("a prefix does not change address family"),
        };
        while bits <= last {
            out.push(Endpoint {
                addr: match start {
                    IpAddr::V4(_) => IpAddr::V4(
                        u32::try_from(bits)
                            .unwrap_or_else(|_| unreachable!())
                            .into(),
                    ),
                    IpAddr::V6(_) => IpAddr::V6(bits.into()),
                },
                ports,
            });
            bits += 1;
        }
    }
    out
}

/// A built static NAT configuration, and the address sets it declares.
///
/// The two vpcs are the ones [`overlay_with_exposes`] builds: `VPC-1` at [`LOCAL_VNI`] offers the
/// generated exposes, and `VPC-2` at [`REMOTE_VNI`] offers one unrelated prefix with no translation
/// on it. That asymmetry is what makes the round trip a property over two independently built
/// tables rather than over one:
///
/// * `VPC-1`'s table translates **sources**, private to public, since the exposes are its own; and
/// * `VPC-2`'s table translates **destinations**, public back to private, since it builds that half
///   from its peer's manifest.
///
/// So a packet leaving `VPC-1` and the reply coming back to it are handled by different tables built
/// from opposite ends of the same expose, and the two must agree.
pub(crate) struct Fabric {
    writer: crate::static_nat::natrw::NatTablesWriter,
    /// Every endpoint the local exposes offer, before translation.
    pub(crate) private: Vec<Endpoint>,
    /// Every endpoint the local exposes translate to.
    pub(crate) public: Vec<Endpoint>,
    /// Addresses in the peer vpc, which no expose translates.
    pub(crate) peer: Vec<IpAddr>,
    /// Whether the exposes carry port ranges, so the mapping moves ports as well as addresses.
    ///
    /// The two paths differ in what a property may assert: with no port range the transport ports
    /// are part of the frame and must survive untouched, and with one they are part of what is
    /// being translated.
    pub(crate) uses_ports: bool,
}

impl Fabric {
    /// Build the tables a set of exposes implies, or `None` if the overlay they form is not valid.
    ///
    /// A rejection here is a legitimate outcome rather than a failure: exposes are generated one at
    /// a time and two of them may overlap, which a manifest refuses. The properties count how often
    /// it happens so that a generator change that starts rejecting everything cannot pass quietly.
    pub(crate) fn build(exposes: &[VpcExpose]) -> Option<Self> {
        let overlay = overlay_with_exposes(exposes.to_vec()).ok()?;
        let validated = overlay.validate().ok()?;
        let tables = build_nat_configuration(validated.vpc_table()).ok()?;

        // Both sets come from the *validated* overlay rather than from `exposes`, for the reason
        // `masquerade::probe::Fabric::build` gives: validation collapses exclusion prefixes, so the
        // raw lists are supersets of what the tables were built from. The consequence is worse on
        // this side than on that one. `private` is what `every_source` sweeps, so an excluded
        // address in it would make `a_translated_source_comes_back` and
        // `distinct_sources_stay_distinct` fail on a correct implementation; `public` is what
        // membership is tested against, so a superset there accepts a translation to an address
        // the operator excluded. Latent either way -- `StaticNatExposes` emits no exclusions --
        // which is the only reason the two agree and not something a property should rest on.
        // The offering vpc only. `overlay_with_exposes` gives the peer a manifest of its own --
        // one unrelated /24 with no translation -- and walking every vpc's peerings would sweep
        // those 256 addresses as though they were sources this configuration maps.
        let local: Vec<&config::external::overlay::vpcpeering::ValidatedExpose> = validated
            .vpc_table()
            .values()
            .filter(|vpc| vpc.vni() == vni(LOCAL_VNI))
            .flat_map(config::external::overlay::vpc::ValidatedVpc::peerings)
            .flat_map(|peering| peering.local().valexp())
            .collect();
        let private: Vec<Endpoint> = local
            .iter()
            .flat_map(|expose| endpoints(expose.ips().iter()))
            .collect();
        let public: Vec<Endpoint> = local
            .iter()
            .flat_map(|expose| endpoints(expose.as_range_or_empty().iter()))
            .collect();
        let uses_ports = private.iter().chain(&public).any(|e| e.ports.is_some());

        // The peer prefix `overlay_with_exposes` fixes, in whichever family the exposes chose.
        let peer = match private.first().map(|e| e.addr) {
            Some(IpAddr::V6(_)) => vec![
                "2001:db8:ffff::1"
                    .parse()
                    .unwrap_or_else(|_| unreachable!()),
                "2001:db8:ffff::2"
                    .parse()
                    .unwrap_or_else(|_| unreachable!()),
            ],
            _ => vec![
                "3.3.3.1".parse().unwrap_or_else(|_| unreachable!()),
                "3.3.3.2".parse().unwrap_or_else(|_| unreachable!()),
            ],
        };

        let mut writer = crate::static_nat::natrw::NatTablesWriter::new();
        writer.update_nat_tables(tables);
        Some(Self {
            writer,
            private,
            public,
            peer,
            uses_ports,
        })
    }

    /// A network function reading these tables.
    ///
    /// Fresh per call: `StaticNat` holds no state of its own, so a property that wants to know a
    /// batch was not influenced by an earlier one can simply take another.
    pub(crate) fn nf(&self) -> StaticNat {
        StaticNat::with_reader("probe", self.writer.get_reader())
    }

    /// An outbound packet from `source` on `port` to the peer.
    ///
    /// For a property that wants to sweep everything the configuration offers rather than the drawn
    /// ones -- injectivity, which is only visible across distinct inputs and so cannot be left to a
    /// draw that may repeat.
    pub(crate) fn outbound_to_peer(&self, source: Endpoint, port: u16) -> Packet<TestBuffer> {
        let mut packet = build(source.addr, self.peer[0], false, port, 80);
        Arrival::outbound().stamp(&mut packet);
        packet
    }

    /// Every distinct thing the configuration maps, as a source and a port to send it from.
    ///
    /// With no port range that is one entry per address. With one it is every address-and-port pair,
    /// since the pair is what the mapping is one to one over -- sweeping addresses alone would check
    /// a diagonal of the space and call it injective.
    pub(crate) fn every_source(&self) -> Vec<(Endpoint, u16)> {
        self.private
            .iter()
            .flat_map(|endpoint| match endpoint.ports {
                None => vec![(*endpoint, 1024)],
                Some(range) => (range.start()..=range.end())
                    .map(|port| (*endpoint, port))
                    .collect(),
            })
            .collect()
    }

    /// Whether this fabric can be probed at all.
    ///
    /// An expose whose two sides are empty builds a table with nothing in it, and every probe
    /// against it misses. Properties skip those rather than count them as passes.
    pub(crate) fn is_probeable(&self) -> bool {
        !self.private.is_empty() && !self.public.is_empty()
    }
}

/// The metadata a packet must carry for [`StaticNat`] to look at it.
///
/// Every field here is something an upstream stage sets in production. Writing them out is what
/// makes this a test of static NAT rather than a test of whatever mock supplies them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival {
    /// The vpc the packet came from, which selects the table.
    pub(crate) src_vpcd: Option<Vni>,
    /// The vpc the packet is going to, which selects the source-translation half of it.
    pub(crate) dst_vpcd: Option<Vni>,
    pub(crate) wants_src_nat: bool,
    pub(crate) wants_dst_nat: bool,
    /// Set when an earlier stage has already translated the source, which static NAT must respect.
    pub(crate) already_src_natted: bool,
}

impl Arrival {
    /// Leaving the local vpc for its peer: source translation, private to public.
    pub(crate) fn outbound() -> Self {
        Self {
            src_vpcd: Some(vni(LOCAL_VNI)),
            dst_vpcd: Some(vni(REMOTE_VNI)),
            wants_src_nat: true,
            wants_dst_nat: false,
            already_src_natted: false,
        }
    }

    /// The reply, arriving at the peer for the local vpc: destination translation, public back to
    /// private.
    pub(crate) fn inbound() -> Self {
        Self {
            src_vpcd: Some(vni(REMOTE_VNI)),
            dst_vpcd: Some(vni(LOCAL_VNI)),
            wants_src_nat: false,
            wants_dst_nat: true,
            already_src_natted: false,
        }
    }

    /// Stamp the state onto a packet.
    ///
    /// `set_keep` is what makes a dropped packet observable: `Packet::enforce` removes a dropped
    /// packet from the output iterator, so without it a drop and a translation-that-did-nothing are
    /// the same event seen from outside, and no property could tell them apart.
    pub(crate) fn stamp(self, packet: &mut Packet<TestBuffer>) {
        let meta = packet.meta_mut();
        meta.src_vpcd = self.src_vpcd.map(VpcDiscriminant::from_vni);
        meta.dst_vpcd = self.dst_vpcd.map(VpcDiscriminant::from_vni);
        meta.set_overlay(true);
        meta.set_keep(true);
        meta.set_static_nat_src(self.wants_src_nat);
        meta.set_static_nat_dst(self.wants_dst_nat);
        meta.src_natted(self.already_src_natted);
    }
}

/// A deliberate deviation from a packet the configuration translates.
///
/// Each one is a question about the network function's own decisions rather than about the mapping:
/// the mapping is covered by enumeration at the table level, and none of these reach it.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum Stray {
    /// A source address no expose offers. Nothing should translate it.
    SourceNotExposed,
    /// No source vpc annotation, which the stage cannot proceed without.
    NoSourceVni,
    /// A source vpc with no table of its own.
    UnknownSourceVni,
    /// A destination vpc the local vpc does not peer with, so the source half finds no table.
    UnknownDestVni,
    /// An earlier stage has already translated the source.
    AlreadySourceNatted,
    /// Nothing asked for translation, so the stage should pass the packet through untouched.
    NotAskedFor,
}

/// A drawn probe, before it knows anything about a configuration.
///
/// Deliberately all indices and raw values: nothing here refers to a prefix, an address or a vni, so
/// the same draw is meaningful against any fabric and shrinking stays interpretable.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct ProbeSpec {
    source: u8,
    peer: u8,
    tcp: bool,
    sport: u16,
    dport: u16,
    stray: Option<Stray>,
}

/// A probe resolved against a fabric: the packet, and the facts a property may reason from.
///
/// The facts are all *inputs* -- what was built and what was asked for. None of them is a
/// prediction of what static NAT should produce, because a prediction is a second implementation of
/// the mapping and the point of resolving against the configuration is not to need one.
pub(crate) struct Probe {
    /// The packet itself, taken out by [`Probe::take`] when it is handed to the stage.
    ///
    /// Held in an `Option` so that taking it does not move out of the probe: the remaining fields
    /// are what a property asserts against afterwards, and [`Probe::reply`] needs them once the
    /// outbound packet is gone.
    packet: Option<Packet<TestBuffer>>,
    /// The source address as built.
    pub(crate) source: IpAddr,
    /// The destination address as built.
    pub(crate) destination: IpAddr,
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    pub(crate) tcp: bool,
    /// Whether the local exposes offer `source`.
    pub(crate) exposed: bool,
    /// The arrival state the packet carries.
    pub(crate) arrival: Arrival,
    pub(crate) stray: Option<Stray>,
}

impl Probe {
    /// The packet, to hand to the stage.
    ///
    /// # Panics
    ///
    /// Panics if called twice. A probe is one packet; a property that wants the same five-tuple
    /// again should resolve the spec again, which is cheap and says so plainly.
    pub(crate) fn take(&mut self) -> Packet<TestBuffer> {
        self.packet
            .take()
            .unwrap_or_else(|| unreachable!("a probe's packet is taken once"))
    }

    /// Whether static NAT was both asked to translate the source and given everything it needs to.
    ///
    /// This is a statement about the *request*, not about the mapping: a probe that is `expected` may
    /// still legitimately go untranslated if no rule covers its source. What it may not do is come
    /// out translated when this is false.
    pub(crate) fn asks_for_translation(&self) -> bool {
        self.arrival.wants_src_nat
            && !self.arrival.already_src_natted
            && self.arrival.src_vpcd == Some(vni(LOCAL_VNI))
            && self.arrival.dst_vpcd == Some(vni(REMOTE_VNI))
    }

    /// The packet that answers this one, addressed to `translated`.
    ///
    /// The reply is what the peer would send back: the two ends swapped, and the local end named by
    /// whatever the outbound translation produced rather than by what the sender used. It arrives at
    /// the peer's vpc, so it is looked up in the peer's table -- the other half of the same expose,
    /// built independently.
    ///
    /// The port matters as much as the address once the expose carries port ranges: the peer
    /// answers the port it was contacted *from*, which is the translated one, and a reply sent to
    /// the original port would miss the mapping and prove nothing.
    pub(crate) fn reply(&self, translated: IpAddr, translated_port: u16) -> Packet<TestBuffer> {
        let mut packet = build(
            self.destination,
            translated,
            self.tcp,
            self.dport,
            translated_port,
        );
        Arrival::inbound().stamp(&mut packet);
        packet
    }
}

impl ProbeSpec {
    /// Drop the deviation, leaving a probe the configuration is meant to translate.
    ///
    /// For the properties about what happens *after* a translation: a probe that misses on purpose
    /// has no translation to say anything about, and would only dilute the batch.
    pub(crate) fn clear_stray(&mut self) {
        self.stray = None;
    }

    /// Interpret this draw against a fabric.
    ///
    /// Total by construction: an index is taken modulo the set it selects from, so there is no draw
    /// that fails to become a packet and no rejection loop to bias the distribution.
    pub(crate) fn resolve(self, fabric: &Fabric) -> Probe {
        let mut arrival = Arrival::outbound();
        let endpoint = fabric.private[self.source as usize % fabric.private.len()];

        let destination = fabric.peer[self.peer as usize % fabric.peer.len()];
        let mut source = endpoint.addr;
        // Drawn from the range the endpoint's prefix carries, so a probe against a configuration
        // that maps ports lands on one it maps rather than beside it.
        let mut sport = endpoint.port(self.sport);
        let mut exposed = true;

        match self.stray {
            None => {}
            Some(Stray::SourceNotExposed) => {
                source = destination;
                // The peer's prefix carries no port range, so no port is the right one either.
                sport = self.sport.max(1);
                exposed = false;
            }
            Some(Stray::NoSourceVni) => arrival.src_vpcd = None,
            Some(Stray::UnknownSourceVni) => arrival.src_vpcd = Some(vni(ABSENT_VNI)),
            Some(Stray::UnknownDestVni) => arrival.dst_vpcd = Some(vni(ABSENT_VNI)),
            Some(Stray::AlreadySourceNatted) => arrival.already_src_natted = true,
            Some(Stray::NotAskedFor) => {
                arrival.wants_src_nat = false;
                arrival.wants_dst_nat = false;
            }
        }

        // Port 0 is not a legal port on either transport. The destination is in the peer vpc, which
        // no expose translates, so its port is free.
        let dport = self.dport.max(1);
        let mut packet = build(source, destination, self.tcp, sport, dport);
        arrival.stamp(&mut packet);

        Probe {
            packet: Some(packet),
            source,
            destination,
            sport,
            dport,
            tcp: self.tcp,
            exposed,
            arrival,
            stray: self.stray,
        }
    }
}

/// Build a packet with the given five-tuple.
///
/// # Panics
///
/// Panics if the two addresses are of different families. Resolution never mixes them, since an
/// expose is of one family throughout and the peer prefix is chosen to match.
pub(crate) fn build(
    source: IpAddr,
    destination: IpAddr,
    tcp: bool,
    sport: u16,
    dport: u16,
) -> Packet<TestBuffer> {
    let next_header = if tcp {
        NextHeader::TCP
    } else {
        NextHeader::UDP
    };
    let mut packet = match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            build_test_ipv4_packet_with_transport(PROBE_TTL, Some(next_header))
                .unwrap_or_else(|e| unreachable!("{e:?}"))
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => {
            build_test_ipv6_packet_with_transport(PROBE_TTL, Some(next_header))
                .unwrap_or_else(|e| unreachable!("{e:?}"))
        }
        _ => unreachable!("a probe never mixes address families"),
    };

    packet
        .set_ip_source(UnicastIpAddr::try_from(source).unwrap_or_else(|_| {
            unreachable!("{source} is drawn from a prefix an expose offers, so it is unicast")
        }))
        .unwrap_or_else(|e| unreachable!("{e:?}"));
    packet
        .set_ip_destination(destination)
        .unwrap_or_else(|e| unreachable!("{e:?}"));

    if tcp {
        packet
            .set_tcp_source_port(TcpPort::new_checked(sport).unwrap_or_else(|_| unreachable!()))
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        packet
            .set_tcp_destination_port(
                TcpPort::new_checked(dport).unwrap_or_else(|_| unreachable!()),
            )
            .unwrap_or_else(|e| unreachable!("{e:?}"));
    } else {
        packet
            .set_udp_source_port(UdpPort::new_checked(sport).unwrap_or_else(|_| unreachable!()))
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        packet
            .set_udp_destination_port(
                UdpPort::new_checked(dport).unwrap_or_else(|_| unreachable!()),
            )
            .unwrap_or_else(|e| unreachable!("{e:?}"));
    }

    packet
}
