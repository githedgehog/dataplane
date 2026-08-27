// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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

pub(crate) const PROBE_TTL: u8 = 64;

const ABSENT_VNI: u32 = 4_000;

pub(crate) fn vni(raw: u32) -> Vni {
    Vni::new_checked(raw).unwrap_or_else(|_| unreachable!("{raw} is a legal vni"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Endpoint {
    pub(crate) addr: IpAddr,
    pub(crate) ports: Option<PortRange>,
}

impl Endpoint {
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

pub(crate) struct Fabric {
    writer: crate::static_nat::natrw::NatTablesWriter,
    pub(crate) private: Vec<Endpoint>,
    pub(crate) public: Vec<Endpoint>,
    pub(crate) peer: Vec<IpAddr>,
    pub(crate) uses_ports: bool,
}

impl Fabric {
    pub(crate) fn build(exposes: &[VpcExpose]) -> Option<Self> {
        let overlay = overlay_with_exposes(exposes.to_vec()).ok()?;
        let validated = overlay.validate().ok()?;
        let tables = build_nat_configuration(validated.vpc_table()).ok()?;

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

    pub(crate) fn nf(&self) -> StaticNat {
        StaticNat::with_reader("probe", self.writer.get_reader())
    }

    pub(crate) fn outbound_to_peer(&self, source: Endpoint, port: u16) -> Packet<TestBuffer> {
        let mut packet = build(source.addr, self.peer[0], false, port, 80);
        Arrival::outbound().stamp(&mut packet);
        packet
    }

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

    pub(crate) fn is_probeable(&self) -> bool {
        !self.private.is_empty() && !self.public.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival {
    pub(crate) src_vpcd: Option<Vni>,
    pub(crate) dst_vpcd: Option<Vni>,
    pub(crate) wants_src_nat: bool,
    pub(crate) wants_dst_nat: bool,
    pub(crate) already_src_natted: bool,
}

impl Arrival {
    pub(crate) fn outbound() -> Self {
        Self {
            src_vpcd: Some(vni(LOCAL_VNI)),
            dst_vpcd: Some(vni(REMOTE_VNI)),
            wants_src_nat: true,
            wants_dst_nat: false,
            already_src_natted: false,
        }
    }

    pub(crate) fn inbound() -> Self {
        Self {
            src_vpcd: Some(vni(REMOTE_VNI)),
            dst_vpcd: Some(vni(LOCAL_VNI)),
            wants_src_nat: false,
            wants_dst_nat: true,
            already_src_natted: false,
        }
    }

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

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum Stray {
    SourceNotExposed,
    NoSourceVni,
    UnknownSourceVni,
    UnknownDestVni,
    AlreadySourceNatted,
    NotAskedFor,
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct ProbeSpec {
    source: u8,
    peer: u8,
    tcp: bool,
    sport: u16,
    dport: u16,
    stray: Option<Stray>,
}

pub(crate) struct Probe {
    packet: Option<Packet<TestBuffer>>,
    pub(crate) source: IpAddr,
    pub(crate) destination: IpAddr,
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    pub(crate) tcp: bool,
    pub(crate) exposed: bool,
    pub(crate) arrival: Arrival,
    pub(crate) stray: Option<Stray>,
}

impl Probe {
    pub(crate) fn take(&mut self) -> Packet<TestBuffer> {
        self.packet
            .take()
            .unwrap_or_else(|| unreachable!("a probe's packet is taken once"))
    }

    pub(crate) fn asks_for_translation(&self) -> bool {
        self.arrival.wants_src_nat
            && !self.arrival.already_src_natted
            && self.arrival.src_vpcd == Some(vni(LOCAL_VNI))
            && self.arrival.dst_vpcd == Some(vni(REMOTE_VNI))
    }

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
    pub(crate) fn clear_stray(&mut self) {
        self.stray = None;
    }

    pub(crate) fn resolve(self, fabric: &Fabric) -> Probe {
        let mut arrival = Arrival::outbound();
        let endpoint = fabric.private[self.source as usize % fabric.private.len()];

        let destination = fabric.peer[self.peer as usize % fabric.peer.len()];
        let mut source = endpoint.addr;
        let mut sport = endpoint.port(self.sport);
        let mut exposed = true;

        match self.stray {
            None => {}
            Some(Stray::SourceNotExposed) => {
                source = destination;
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
