// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packets drawn relative to a port-forwarding configuration.
//!
//! The third network function harness, and the same shape as the first two: a [`ProbeSpec`] of bare
//! indices, resolved against a built [`Fabric`], with the configuration a parameter to resolution
//! rather than a predicate to filter against.
//!
//! # What is different about port forwarding
//!
//! Static NAT and masquerade both translate a packet's **source** on the way out. Port forwarding
//! translates its **destination** on the way in, which reverses everything:
//!
//! * The interesting packet arrives *from the peer*, addressed to a public tuple the local vpc
//!   published, and leaves addressed to a private one. `expose.ips` is the private side and
//!   `expose.nat.as_range` the public one, as everywhere else -- but here traffic enters at
//!   `as_range` rather than leaving through it.
//! * A rule is keyed by `(source vpc, protocol)`, not by address. So the *source* vpc annotation
//!   selects the rule and the destination address selects the mapping within it.
//! * The mapping is **positional**: one prefix and port range onto another of the same size, address
//!   for address and port for port. That is a stricter contract than static NAT's, which only
//!   requires the two sides to have equal totals.
//!
//! It is stateful like masquerade -- the first packet creates a flow pair carrying the translation,
//! and later packets in either direction take a fast path through it -- so the stage ordering
//! constraint is the same, and [`run`] handles it the same way.

#![cfg(test)]

use crate::portfw::{PortForwarder, PortFwTableWriter, build_port_forwarding_configuration};
use crate::static_nat::probe::{build, vni};
use bolero::TypeGenerator;
use clock::Duration;
use concurrency::sync::Arc;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::{
    LOCAL_VNI, REMOTE_VNI, overlay_with_exposes,
};
use flow_entry::flow_table::{FlowLookup, FlowTable};
use lpm::prefix::Prefix;
use net::buffer::TestBuffer;
use net::packet::{Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::net::IpAddr;

/// Flow table capacity, large enough that a translation failure is never the table being full.
const FLOW_CAPACITY: usize = 4096;

/// A VNI no generated configuration uses.
const ABSENT_VNI: u32 = 4_000;

/// One side of a port-forwarding rule: a prefix and the port range it carries.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Side {
    pub(crate) prefix: Prefix,
    pub(crate) first_port: u16,
    pub(crate) last_port: u16,
}

impl Side {
    /// Whether this side covers an address and port.
    pub(crate) fn covers(&self, addr: IpAddr, port: u16) -> bool {
        self.prefix.covers_addr(&addr) && port >= self.first_port && port <= self.last_port
    }

    /// An address and port inside this side, chosen by two arbitrary indices.
    ///
    /// Total, so a draw always lands on something the rule covers rather than beside it.
    pub(crate) fn endpoint(&self, host: u16, port: u16) -> (IpAddr, u16) {
        let span = self.span();
        let offset = u128::from(host) % span.max(1);
        let addr = match self.prefix.as_address() {
            IpAddr::V4(base) => IpAddr::V4(
                u32::try_from(u128::from(base.to_bits()) + offset)
                    .unwrap_or_else(|_| unreachable!())
                    .into(),
            ),
            IpAddr::V6(base) => IpAddr::V6((base.to_bits() + offset).into()),
        };
        let ports = u32::from(self.last_port - self.first_port) + 1;
        let port = self.first_port + u16::try_from(u32::from(port) % ports).unwrap_or(0);
        (addr, port)
    }

    /// How many addresses this side covers.
    fn span(&self) -> u128 {
        let host_bits = match self.prefix.as_address() {
            IpAddr::V4(_) => 32 - u32::from(self.prefix.length()),
            IpAddr::V6(_) => 128 - u32::from(self.prefix.length()),
        };
        1u128 << host_bits.min(64)
    }

    /// A spread of the address-and-port pairs this side covers, for a property that sweeps.
    ///
    /// **Capped.** A rule may publish 256 addresses over 1024 ports, and enumerating that costs a
    /// quarter of a million packets -- which one property did, exhausting its whole budget on two
    /// configurations. Two hundred and fifty six pairs is plenty to catch a collision and leaves the
    /// budget to explore configurations, which is where the shapes differ.
    ///
    /// Strided rather than truncated, so the sample spans the whole of both dimensions instead of
    /// sitting in one corner: a mapping that goes wrong only at the top of a range would survive a
    /// sample of the bottom of it.
    pub(crate) fn every(&self) -> Vec<(IpAddr, u16)> {
        const CAP: usize = 256;
        let hosts = u32::try_from(self.span())
            .unwrap_or(u32::from(u16::MAX))
            .max(1);
        let ports = u32::from(self.last_port - self.first_port) + 1;
        let total = u64::from(hosts) * u64::from(ports);
        let stride = (total / CAP as u64).max(1);

        let mut out = Vec::new();
        let mut index = 0u64;
        while index < total {
            let host = u16::try_from(index / u64::from(ports)).unwrap_or(u16::MAX);
            let port = u16::try_from(index % u64::from(ports)).unwrap_or(0);
            out.push(self.endpoint(host, port));
            index += stride;
        }
        out
    }
}

/// A built port-forwarding configuration, and the two sides each rule declares.
pub(crate) struct Fabric {
    flow_table: Arc<FlowTable>,
    writer: PortFwTableWriter,
    /// One entry per rule: the public side traffic arrives at, the private side it reaches, and
    /// whether the rule is keyed on TCP.
    ///
    /// The protocol has to be carried, not drawn. A rule is keyed by `(source vpc, protocol)`, so a
    /// probe that addresses one rule's public range over the other rule's protocol matches nothing
    /// -- and a property expecting *not* to forward it then passes for the wrong reason. That is how
    /// the port-range guard here was found to be vacuous: it never reached the gate it was testing.
    pub(crate) rules: Vec<(Side, Side, bool)>,
    /// Addresses in the peer vpc, which the rules never name.
    pub(crate) peer: Vec<IpAddr>,
}

impl Fabric {
    /// Build the table a set of exposes implies, or `None` if the overlay they form is not valid.
    pub(crate) fn build(exposes: &[VpcExpose]) -> Option<Self> {
        let overlay = overlay_with_exposes(exposes.to_vec()).ok()?;
        let validated = overlay.validate().ok()?;
        let ruleset = build_port_forwarding_configuration(validated.vpc_table()).ok()?;

        let mut writer = PortFwTableWriter::new();
        writer.update_table(&ruleset).ok()?;

        let rules: Vec<(Side, Side, bool)> = exposes
            .iter()
            .filter_map(|expose| {
                let public = expose.nat.as_ref()?.as_range.first()?;
                let private = expose.ips.first()?;
                let (pub_ports, priv_ports) = (public.ports()?, private.ports()?);
                let tcp = expose.nat.as_ref()?.proto != lpm::prefix::L4Protocol::Udp;
                Some((
                    Side {
                        prefix: public.prefix(),
                        first_port: pub_ports.start(),
                        last_port: pub_ports.end(),
                    },
                    Side {
                        prefix: private.prefix(),
                        first_port: priv_ports.start(),
                        last_port: priv_ports.end(),
                    },
                    tcp,
                ))
            })
            .collect();

        let peer = match rules
            .first()
            .map(|(public, _, _)| public.prefix.as_address())
        {
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

        Some(Self {
            flow_table: Arc::new(FlowTable::new(FLOW_CAPACITY)),
            writer,
            rules,
            peer,
        })
    }

    /// The two stages a port-forwarded packet passes through.
    pub(crate) fn stages(&self) -> (FlowLookup, PortForwarder) {
        (
            FlowLookup::new("flow-lookup", self.flow_table.clone()),
            PortForwarder::new(
                "port-forwarder",
                self.writer.reader(),
                self.flow_table.clone(),
            ),
        )
    }

    pub(crate) fn is_probeable(&self) -> bool {
        !self.rules.is_empty()
    }

    /// The flow table the stages share.
    ///
    /// Exposed for the properties that are about the entries themselves rather than about what
    /// comes out of the stage: a pair that has been torn down and rebuilt forwards exactly like one
    /// that was left alone, so no amount of looking at packets tells them apart.
    pub(crate) fn flows(&self) -> &Arc<FlowTable> {
        &self.flow_table
    }

    /// Whether any rule's private side covers this address and port.
    pub(crate) fn is_private(&self, addr: IpAddr, port: u16) -> bool {
        self.rules
            .iter()
            .any(|(_, private, _)| private.covers(addr, port))
    }
}

/// Put a batch through the stages, in the order the real pipeline uses.
///
/// As for masquerade: `FlowLookup` attaches a flow entry only to a packet whose `dst_vpcd` is
/// absent, and the flow filter that sets `dst_vpcd` runs after it, so the annotation arrives
/// *between* the two stages.
pub(crate) fn run(
    lookup: &mut FlowLookup,
    pfw: &mut PortForwarder,
    packets: Vec<Packet<TestBuffer>>,
    dst_vpcd: Option<Vni>,
) -> Vec<Packet<TestBuffer>> {
    let mut looked: Vec<_> = lookup.process(packets.into_iter()).collect();
    for packet in &mut looked {
        packet.meta_mut().dst_vpcd = dst_vpcd.map(VpcDiscriminant::from_vni);
    }
    pfw.process(looked.into_iter()).collect()
}

/// The metadata a packet must carry for [`PortForwarder`] to look at it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival {
    /// Selects the rule: a rule is keyed by the vpc traffic came *from*.
    pub(crate) src_vpcd: Option<Vni>,
    /// Supplied after the flow lookup, standing in for the flow filter.
    pub(crate) dst_vpcd: Option<Vni>,
    pub(crate) wants_port_forwarding: bool,
}

impl Arrival {
    /// Traffic arriving from the peer for a published tuple. This is the direction port forwarding
    /// exists for.
    pub(crate) fn inbound() -> Self {
        Self {
            src_vpcd: Some(vni(REMOTE_VNI)),
            dst_vpcd: Some(vni(LOCAL_VNI)),
            wants_port_forwarding: true,
        }
    }

    /// The reply, leaving the local vpc for the peer.
    pub(crate) fn outbound() -> Self {
        Self {
            src_vpcd: Some(vni(LOCAL_VNI)),
            dst_vpcd: Some(vni(REMOTE_VNI)),
            wants_port_forwarding: true,
        }
    }

    /// Everything an upstream stage sets before the flow lookup.
    pub(crate) fn stamp(self, packet: &mut Packet<TestBuffer>) {
        let meta = packet.meta_mut();
        meta.src_vpcd = self.src_vpcd.map(VpcDiscriminant::from_vni);
        meta.set_overlay(true);
        meta.set_keep(true);
        meta.set_port_forwarding(self.wants_port_forwarding);
    }
}

/// A deliberate deviation from a packet the configuration forwards.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum Stray {
    /// A destination no rule publishes. Nothing should forward it.
    DestinationNotPublished,
    /// A port outside the published range, on a published address.
    PortOutsideRange,
    /// A source vpc no rule is keyed by.
    UnknownSourceVni,
    /// Nothing asked for port forwarding.
    NotAskedFor,
}

/// A drawn probe, before it knows anything about a configuration.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct ProbeSpec {
    rule: u8,
    host: u16,
    port: u16,
    peer: u8,
    sport: u16,
    stray: Option<Stray>,
}

/// A probe resolved against a fabric.
pub(crate) struct Probe {
    /// The public address and port the packet is addressed to.
    pub(crate) destination: (IpAddr, u16),
    /// The peer address it comes from.
    pub(crate) source: IpAddr,
    pub(crate) sport: u16,
    pub(crate) tcp: bool,
    /// Whether some rule publishes `destination`.
    pub(crate) published: bool,
    pub(crate) arrival: Arrival,
    pub(crate) stray: Option<Stray>,
}

impl Probe {
    /// Whether port forwarding was asked to translate this packet and given what it needs to.
    pub(crate) fn asks_for_forwarding(&self) -> bool {
        self.arrival.wants_port_forwarding && self.arrival.src_vpcd == Some(vni(REMOTE_VNI))
    }

    /// The inbound packet, which may be built more than once so a property can send the same flow
    /// twice and reach the fast path.
    pub(crate) fn packet(&self) -> Packet<TestBuffer> {
        let mut packet = build(
            self.source,
            self.destination.0,
            self.tcp,
            self.sport,
            self.destination.1,
        );
        self.arrival.stamp(&mut packet);
        packet
    }

    /// The reply the forwarded-to host sends back, from the private tuple it was reached on.
    pub(crate) fn reply(&self, translated: (IpAddr, u16)) -> Packet<TestBuffer> {
        let mut packet = build(
            translated.0,
            self.source,
            self.tcp,
            translated.1,
            self.sport,
        );
        Arrival::outbound().stamp(&mut packet);
        packet
    }
}

impl ProbeSpec {
    /// Drop the deviation, leaving a packet the configuration is meant to forward.
    pub(crate) fn clear_stray(&mut self) {
        self.stray = None;
    }

    /// Interpret this draw against a fabric.
    pub(crate) fn resolve(self, fabric: &Fabric) -> Probe {
        // The protocol comes from the rule, not from the draw: addressing a rule's public range
        // over the wrong protocol matches nothing, and every property would then be judging a
        // packet that never reached the code it is about.
        let (public, _private, tcp) = fabric.rules[self.rule as usize % fabric.rules.len()];
        let mut arrival = Arrival::inbound();
        let mut destination = public.endpoint(self.host, self.port);
        let source = fabric.peer[self.peer as usize % fabric.peer.len()];
        let mut published = true;

        match self.stray {
            None => {}
            Some(Stray::DestinationNotPublished) => {
                // An address in the peer's own space, which no rule publishes.
                destination = (fabric.peer[0], destination.1);
                published = false;
            }
            Some(Stray::PortOutsideRange) => {
                // Just past the top of the range, on an address a rule does publish.
                if public.last_port < u16::MAX {
                    destination = (destination.0, public.last_port + 1);
                    published = false;
                }
            }
            Some(Stray::UnknownSourceVni) => arrival.src_vpcd = Some(vni(ABSENT_VNI)),
            Some(Stray::NotAskedFor) => arrival.wants_port_forwarding = false,
        }

        Probe {
            destination,
            source,
            sport: self.sport.max(1),
            tcp,
            published,
            arrival,
            stray: self.stray,
        }
    }
}

/// How long a port-forwarding flow lives before it is first refreshed.
///
/// The generator draws `None`, five seconds or five minutes for the idle timeout, so a property that
/// wants a flow to have expired must outrun the longest of them.
pub(crate) const PAST_ANY_TIMEOUT: Duration = Duration::from_mins(30);
