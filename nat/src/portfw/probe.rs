// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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

const FLOW_CAPACITY: usize = 4096;

const ABSENT_VNI: u32 = 4_000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Side {
    pub(crate) prefix: Prefix,
    pub(crate) first_port: u16,
    pub(crate) last_port: u16,
}

impl Side {
    pub(crate) fn covers(&self, addr: IpAddr, port: u16) -> bool {
        self.prefix.covers_addr(&addr) && port >= self.first_port && port <= self.last_port
    }

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

    fn span(&self) -> u128 {
        let host_bits = match self.prefix.as_address() {
            IpAddr::V4(_) => 32 - u32::from(self.prefix.length()),
            IpAddr::V6(_) => 128 - u32::from(self.prefix.length()),
        };
        1u128 << host_bits.min(64)
    }

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

pub(crate) struct Fabric {
    flow_table: Arc<FlowTable>,
    writer: PortFwTableWriter,
    pub(crate) rules: Vec<(Side, Side, bool)>,
    pub(crate) peer: Vec<IpAddr>,
}

impl Fabric {
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

    pub(crate) fn flows(&self) -> &Arc<FlowTable> {
        &self.flow_table
    }

    pub(crate) fn is_private(&self, addr: IpAddr, port: u16) -> bool {
        self.rules
            .iter()
            .any(|(_, private, _)| private.covers(addr, port))
    }
}

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

#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival {
    pub(crate) src_vpcd: Option<Vni>,
    pub(crate) dst_vpcd: Option<Vni>,
    pub(crate) wants_port_forwarding: bool,
}

impl Arrival {
    pub(crate) fn inbound() -> Self {
        Self {
            src_vpcd: Some(vni(REMOTE_VNI)),
            dst_vpcd: Some(vni(LOCAL_VNI)),
            wants_port_forwarding: true,
        }
    }

    pub(crate) fn outbound() -> Self {
        Self {
            src_vpcd: Some(vni(LOCAL_VNI)),
            dst_vpcd: Some(vni(REMOTE_VNI)),
            wants_port_forwarding: true,
        }
    }

    pub(crate) fn stamp(self, packet: &mut Packet<TestBuffer>) {
        let meta = packet.meta_mut();
        meta.src_vpcd = self.src_vpcd.map(VpcDiscriminant::from_vni);
        meta.set_overlay(true);
        meta.set_keep(true);
        meta.set_port_forwarding(self.wants_port_forwarding);
    }
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum Stray {
    DestinationNotPublished,
    PortOutsideRange,
    UnknownSourceVni,
    NotAskedFor,
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct ProbeSpec {
    rule: u8,
    host: u16,
    port: u16,
    peer: u8,
    sport: u16,
    stray: Option<Stray>,
}

pub(crate) struct Probe {
    pub(crate) destination: (IpAddr, u16),
    pub(crate) source: IpAddr,
    pub(crate) sport: u16,
    pub(crate) tcp: bool,
    pub(crate) published: bool,
    pub(crate) arrival: Arrival,
    pub(crate) stray: Option<Stray>,
}

impl Probe {
    pub(crate) fn asks_for_forwarding(&self) -> bool {
        self.arrival.wants_port_forwarding && self.arrival.src_vpcd == Some(vni(REMOTE_VNI))
    }

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
    pub(crate) fn clear_stray(&mut self) {
        self.stray = None;
    }

    pub(crate) fn resolve(self, fabric: &Fabric) -> Probe {
        let (public, _private, tcp) = fabric.rules[self.rule as usize % fabric.rules.len()];
        let mut arrival = Arrival::inbound();
        let mut destination = public.endpoint(self.host, self.port);
        let source = fabric.peer[self.peer as usize % fabric.peer.len()];
        let mut published = true;

        match self.stray {
            None => {}
            Some(Stray::DestinationNotPublished) => {
                destination = (fabric.peer[0], destination.1);
                published = false;
            }
            Some(Stray::PortOutsideRange) => {
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

pub(crate) const PAST_ANY_TIMEOUT: Duration = Duration::from_mins(30);
