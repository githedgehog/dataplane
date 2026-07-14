// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared helpers for the crate's tests: concise overlay/expose/peering builders
//! and packet-header builders (via the `HeaderStack` builder). Used by both the
//! routing-context tests (`context::tests`) and the end-to-end NF tests
//! (`crate::tests`).

#![cfg(test)]

use crate::context::FlofiContext;
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use lpm::prefix::{L4Protocol, PortRange, PrefixWithOptionalPorts};
use net::headers::Headers;
use net::headers::builder::HeaderStack;
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::VpcDiscriminant;
use net::tcp::TcpPort;
use net::udp::UdpPort;
use net::vxlan::Vni;
use std::net::{Ipv4Addr, Ipv6Addr};

// -------------------------------------------------------------------------------------------------
// IP address builders

/// An Ethernet-only frame (no IP layer), for exercising the "not IP" path.
pub(crate) fn build_nonip_packet() -> Headers {
    HeaderStack::new().eth(|_| {}).build_headers().unwrap()
}

pub(crate) fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

pub(crate) fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

// -------------------------------------------------------------------------------------------------
// Identifiers

pub(crate) fn vni(id: u32) -> Vni {
    Vni::new_checked(id).unwrap()
}

pub(crate) fn vpcd(id: u32) -> VpcDiscriminant {
    VpcDiscriminant::from_vni(vni(id))
}

// -------------------------------------------------------------------------------------------------
// Expose / peering / overlay builders

/// Plain expose (no NAT): the listed prefix is both private and public.
pub(crate) fn expose(ip: &str) -> VpcExpose {
    VpcExpose::empty().ip(ip.into())
}

/// Default expose (catch-all): matches anything not matched by another expose.
pub(crate) fn expose_default() -> VpcExpose {
    VpcExpose::empty().set_default()
}

/// Static-NAT expose: `private` addresses are translated 1:1 to `public`.
pub(crate) fn expose_static(private: &str, public: &str) -> VpcExpose {
    VpcExpose::empty()
        .make_static_nat()
        .unwrap()
        .ip(private.into())
        .as_range(public.into())
        .unwrap()
}

/// Masquerade expose: `private` addresses are masqueraded behind `public`.
pub(crate) fn expose_masquerade(private: &str, public: &str) -> VpcExpose {
    VpcExpose::empty()
        .make_masquerade(None)
        .unwrap()
        .ip(private.into())
        .as_range(public.into())
        .unwrap()
}

/// Port-forwarding expose: `private_ip:private_ports` is reachable as
/// `public_ip:public_ports`, optionally restricted to a single L4 protocol.
pub(crate) fn expose_port_forwarding(
    private_ip: &str,
    private_ports: (u16, u16),
    public_ip: &str,
    public_ports: (u16, u16),
    proto: Option<L4Protocol>,
) -> VpcExpose {
    VpcExpose::empty()
        .make_port_forwarding(None, proto)
        .unwrap()
        .ip(PrefixWithOptionalPorts::new(
            private_ip.into(),
            Some(PortRange::new(private_ports.0, private_ports.1).unwrap()),
        ))
        .as_range(PrefixWithOptionalPorts::new(
            public_ip.into(),
            Some(PortRange::new(public_ports.0, public_ports.1).unwrap()),
        ))
        .unwrap()
}

/// Build a peering between `local` and `remote`, each given as `(vpc_name, exposes)`.
pub(crate) fn peering(
    name: &str,
    local: (&str, Vec<VpcExpose>),
    remote: (&str, Vec<VpcExpose>),
) -> VpcPeering {
    VpcPeering::with_default_group(
        name,
        VpcManifest::with_exposes(local.0, local.1),
        VpcManifest::with_exposes(remote.0, remote.1),
    )
}

/// Assemble a `VpcTable` from `(name, vni)` pairs, generating valid 5-char ids.
pub(crate) fn vpc_table(vpcs: &[(&str, u32)]) -> VpcTable {
    assert!(vpcs.len() <= 99, "too many VPCs for test (max 99)"); // Related to id formatting below
    let mut table = VpcTable::new();
    for (i, (name, vni_id)) in vpcs.iter().enumerate() {
        let id = format!("VPC{:02}", i + 1); // VpcId must be exactly 5 chars
        table.add(Vpc::new(name, &id, *vni_id).unwrap()).unwrap();
    }
    table
}

/// Build and validate an overlay. Panics if the config does not validate.
pub(crate) fn overlay(vpcs: &[(&str, u32)], peerings: Vec<VpcPeering>) -> ValidatedOverlay {
    let mut peering_table = VpcPeeringTable::new();
    for p in peerings {
        peering_table.add(p).unwrap();
    }
    Overlay::new(vpc_table(vpcs), peering_table)
        .validate()
        .unwrap()
}

/// Build a flofi context (reference backend: fast, EAL-free) from a set of VPCs and peerings.
pub(crate) fn context(vpcs: &[(&str, u32)], peerings: Vec<VpcPeering>) -> FlofiContext {
    FlofiContext::for_test(&overlay(vpcs, peerings))
}

// -------------------------------------------------------------------------------------------------
// Packet-header builders (via the HeaderStack builder)

pub(crate) fn build_tcp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(UnicastIpv4Addr::new(src).unwrap());
            ip.set_destination(dst);
        })
        .tcp(|tcp| {
            tcp.set_source(TcpPort::try_from(sport).unwrap());
            tcp.set_destination(TcpPort::try_from(dport).unwrap());
        })
        .build_headers()
        .unwrap()
}

pub(crate) fn build_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(UnicastIpv4Addr::new(src).unwrap());
            ip.set_destination(dst);
        })
        .udp(|udp| {
            udp.set_source(UdpPort::try_from(sport).unwrap());
            udp.set_destination(UdpPort::try_from(dport).unwrap());
        })
        .build_headers()
        .unwrap()
}

pub(crate) fn build_icmp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(UnicastIpv4Addr::new(src).unwrap());
            ip.set_destination(dst);
        })
        .icmp4(|_| {})
        .build_headers()
        .unwrap()
}

pub(crate) fn build_tcp_packet_v6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv6(|ip| {
            ip.set_source(UnicastIpv6Addr::new(src).unwrap());
            ip.set_destination(dst);
        })
        .tcp(|tcp| {
            tcp.set_source(TcpPort::try_from(sport).unwrap());
            tcp.set_destination(TcpPort::try_from(dport).unwrap());
        })
        .build_headers()
        .unwrap()
}
