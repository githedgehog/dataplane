// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::lldp::NEAREST_BRIDGE;

use crate::key::{ICMP6, TCP, UDP};
use crate::{Class, ClassTable, ControlPlane, Fate, Frame, Ip, Key, L4, Ports, Rule};

const V4: [Ipv4Addr; 5] = [
    Ipv4Addr::new(10, 0, 0, 1),
    Ipv4Addr::new(10, 0, 0, 2),
    Ipv4Addr::new(10, 0, 0, 3),
    Ipv4Addr::new(10, 0, 0, 4),
    Ipv4Addr::new(192, 0, 2, 1),
];

const V6: [Ipv6Addr; 7] = [
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3),
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 4),
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
    // All nodes, and a solicited-node address.
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 1),
];

const PORTS: [u16; 6] = [179, 3784, 4784, 3785, 4789, 22];
const PROTOS: [u8; 5] = [1, TCP, UDP, ICMP6, 0];
const ETHER_TYPES: [EthType; 5] = [
    EthType::ARP,
    EthType::LLDP,
    EthType::VLAN,
    EthType::IPV4,
    EthType::new(0x1234),
];
const MACS: [Mac; 4] = [
    NEAREST_BRIDGE,
    Mac::BROADCAST,
    Mac([0x02, 0, 0, 0, 0, 1]),
    Mac([0x01, 0x80, 0xc2, 0, 0, 0x03]),
];

/// Picks from `pool` most of the time, so generated frames hit the table, and otherwise
/// generates a value of its own.
fn pick<T: Copy>(pool: &[T], index: u8, otherwise: T) -> T {
    pool.get(usize::from(index)).copied().unwrap_or(otherwise)
}

/// The members of `pool` the bits of `mask` select.
fn subset<T: Copy>(pool: &[T], mask: u8) -> impl Iterator<Item = T> + '_ {
    pool.iter()
        .enumerate()
        .filter(move |(i, _)| mask & (1 << i) != 0)
        .map(|(_, a)| *a)
}

#[derive(Debug, bolero::TypeGenerator)]
struct RawControl {
    local_v4: u8,
    local_v6: u8,
    neighbours_v4: u8,
    neighbours_v6: u8,
    vtep: Option<(bool, u8)>,
}

impl RawControl {
    fn control(&self) -> ControlPlane {
        let local = subset(&V4, self.local_v4)
            .map(IpAddr::from)
            .chain(subset(&V6, self.local_v6).map(IpAddr::from));
        let neighbours = subset(&V4, self.neighbours_v4)
            .map(IpAddr::from)
            .chain(subset(&V6, self.neighbours_v6).map(IpAddr::from));
        let vtep = self.vtep.map(|(v6, i)| {
            if v6 {
                IpAddr::from(pick(&V6, i % 8, V6[0]))
            } else {
                IpAddr::from(pick(&V4, i % 8, V4[0]))
            }
        });
        ControlPlane::new(local, vtep, neighbours)
    }
}

#[derive(Debug, bolero::TypeGenerator)]
enum RawL4 {
    Tcp((u8, u16), (u8, u16)),
    Udp((u8, u16), (u8, u16)),
    Proto(u8, u8),
}

#[derive(Debug, bolero::TypeGenerator)]
enum RawFrame {
    Ipv4((u8, [u8; 4]), (u8, [u8; 4]), RawL4),
    Ipv6((u8, [u8; 16]), (u8, [u8; 16]), RawL4),
    Other(u8, u16),
}

#[derive(Debug, bolero::TypeGenerator)]
struct RawKey {
    dst_mac: (u8, [u8; 6]),
    frame: RawFrame,
}

impl RawL4 {
    fn l4(&self) -> L4 {
        let port = |(i, p): (u8, u16)| pick(&PORTS, i % 8, p);
        let ports = |src, dst| Ports {
            src: port(src),
            dst: port(dst),
        };
        match *self {
            RawL4::Tcp(src, dst) => L4::Tcp(ports(src, dst)),
            RawL4::Udp(src, dst) => L4::Udp(ports(src, dst)),
            RawL4::Proto(i, p) => L4::Proto(pick(&PROTOS, i % 8, p)),
        }
    }
}

impl RawKey {
    fn key(&self) -> Key {
        let frame = match &self.frame {
            RawFrame::Ipv4((si, s), (di, d), l4) => Frame::Ipv4(Ip {
                src: pick(&V4, si % 8, Ipv4Addr::from(*s)),
                dst: pick(&V4, di % 8, Ipv4Addr::from(*d)),
                l4: l4.l4(),
            }),
            RawFrame::Ipv6((si, s), (di, d), l4) => Frame::Ipv6(Ip {
                src: pick(&V6, si % 10, Ipv6Addr::from(*s)),
                dst: pick(&V6, di % 10, Ipv6Addr::from(*d)),
                l4: l4.l4(),
            }),
            RawFrame::Other(i, t) => Frame::Other(pick(&ETHER_TYPES, i % 8, EthType::new(*t))),
        };
        let (i, mac) = self.dst_mac;
        Key {
            dst_mac: pick(&MACS, i % 6, Mac(mac)),
            frame,
        }
    }
}

/// What a NIC does with `rules`: the fate of the highest tier rule that matches.
///
/// # Panics
///
/// If two rules of that tier match with different fates: the NIC would pick either.
fn steer(rules: &[Rule], key: &Key) -> Option<Fate> {
    let tier = rules
        .iter()
        .filter(|r| r.matches(key))
        .map(|r| r.tier)
        .min()?;
    let mut fates = rules
        .iter()
        .filter(|r| r.tier == tier && r.matches(key))
        .map(|r| r.fate);
    let fate = fates.next()?;
    for other in fates {
        assert_eq!(fate, other, "rules of one tier disagree on {key:?}");
    }
    Some(fate)
}

#[test]
fn the_rules_steer_exactly_what_the_classifier_classifies() {
    bolero::check!()
        .with_type::<(RawControl, RawKey)>()
        .for_each(|(control, key)| {
            let table = ClassTable::new(control.control());
            let key = key.key();
            let steered = match steer(table.rules(), &key) {
                Some(Fate::Control(class)) => Some(class),
                Some(Fate::Data) | None => None,
            };
            assert_eq!(steered, table.classify(&key), "{key:?} under {table:?}");
        });
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, l4: L4) -> Key {
    Key {
        dst_mac: Mac([0x02, 0, 0, 0, 0, 1]),
        frame: Frame::Ipv4(Ip { src, dst, l4 }),
    }
}

fn ipv6(dst_mac: Mac, src: Ipv6Addr, dst: Ipv6Addr, l4: L4) -> Key {
    Key {
        dst_mac,
        frame: Frame::Ipv6(Ip { src, dst, l4 }),
    }
}

fn tcp(src: u16, dst: u16) -> L4 {
    L4::Tcp(Ports { src, dst })
}

fn udp(src: u16, dst: u16) -> L4 {
    L4::Udp(Ports { src, dst })
}

/// Local `10.0.0.1` and `2001:db8::1`, VTEP `10.0.0.2`, neighbour `10.0.0.3`.
fn table() -> ClassTable {
    ClassTable::new(ControlPlane::new(
        [V4[0].into(), V6[0].into()],
        Some(V4[1].into()),
        [V4[2].into()],
    ))
}

#[test]
fn bgp_and_bfd_count_only_from_neighbours() {
    let table = table();
    let (local, neighbour, stranger) = (V4[0], V4[2], V4[3]);
    assert_eq!(
        table.classify(&ipv4(neighbour, local, tcp(40000, 179))),
        Some(Class::Bgp)
    );
    assert_eq!(
        table.classify(&ipv4(neighbour, local, tcp(179, 40000))),
        Some(Class::Bgp)
    );
    assert_eq!(
        table.classify(&ipv4(neighbour, local, udp(49152, 3784))),
        Some(Class::Bfd)
    );
    assert_eq!(
        table.classify(&ipv4(neighbour, local, udp(49152, 4784))),
        Some(Class::Bfd)
    );
    assert_eq!(
        table.classify(&ipv4(stranger, local, tcp(40000, 179))),
        Some(Class::OtherLocal)
    );
    // BFD echo is looped back by the neighbour, from our own address: just local traffic.
    assert_eq!(
        table.classify(&ipv4(local, local, udp(3785, 3785))),
        Some(Class::OtherLocal)
    );
    // Passing through is the data plane's.
    assert_eq!(
        table.classify(&ipv4(neighbour, stranger, tcp(40000, 179))),
        None
    );
}

#[test]
fn vxlan_to_the_vtep_is_data() {
    let table = table();
    let (local, vtep, neighbour) = (V4[0], V4[1], V4[2]);
    assert_eq!(
        table.classify(&ipv4(neighbour, vtep, udp(50000, 4789))),
        None
    );
    assert_eq!(
        table.classify(&ipv4(neighbour, vtep, L4::Proto(1))),
        Some(Class::OtherLocal)
    );
    assert_eq!(
        table.classify(&ipv4(neighbour, local, udp(50000, 4789))),
        Some(Class::OtherLocal)
    );
}

#[test]
fn icmpv6_to_us_is_icmpv6() {
    let table = table();
    let (local, remote) = (V6[0], V6[3]);
    let (link_local, solicited_node) = (V6[4], V6[6]);
    let mac = Mac([0x33, 0x33, 0xff, 0, 0, 1]);
    let icmp6 = L4::Proto(ICMP6);
    assert_eq!(
        table.classify(&ipv6(mac, link_local, solicited_node, icmp6)),
        Some(Class::Icmpv6)
    );
    assert_eq!(
        table.classify(&ipv6(mac, remote, link_local, icmp6)),
        Some(Class::Icmpv6)
    );
    assert_eq!(
        table.classify(&ipv6(mac, remote, local, icmp6)),
        Some(Class::Icmpv6)
    );
    // A ping through the gateway is not for it.
    assert_eq!(table.classify(&ipv6(mac, local, remote, icmp6)), None);
}

#[test]
fn arp_and_lldp_are_recognized_by_ethertype() {
    let table = table();
    let other = |dst_mac, ether_type| Key {
        dst_mac,
        frame: Frame::Other(ether_type),
    };
    assert_eq!(
        table.classify(&other(Mac::BROADCAST, EthType::ARP)),
        Some(Class::Arp)
    );
    assert_eq!(
        table.classify(&other(NEAREST_BRIDGE, EthType::LLDP)),
        Some(Class::Lldp)
    );
    assert_eq!(table.classify(&other(MACS[3], EthType::LLDP)), None);
    assert_eq!(table.classify(&other(Mac::BROADCAST, EthType::VLAN)), None);
}

mod keys {
    use net::eth::Eth;
    use net::eth::mac::{DestinationMac, SourceMac};
    use net::headers::HeadersBuilder;
    use net::headers::builder::HeaderStack;
    use net::ipv4::UnicastIpv4Addr;
    use net::tcp::TcpPort;
    use net::udp::UdpPort;

    use super::*;

    #[test]
    fn a_tcp_packets_key_has_its_addresses_and_ports() {
        let headers = HeaderStack::new()
            .eth(|eth| {
                eth.set_destination(DestinationMac::new(MACS[2]).unwrap());
            })
            .ipv4(|ip| {
                ip.set_source(UnicastIpv4Addr::new(V4[2]).unwrap());
                ip.set_destination(V4[0]);
            })
            .tcp(|tcp| {
                tcp.set_source(TcpPort::new_checked(40000).unwrap());
                tcp.set_destination(TcpPort::new_checked(179).unwrap());
            })
            .build_headers()
            .unwrap();
        assert_eq!(
            Key::of(&headers),
            Ok(Key {
                dst_mac: MACS[2],
                frame: Frame::Ipv4(Ip {
                    src: V4[2],
                    dst: V4[0],
                    l4: tcp(40000, 179),
                }),
            })
        );
    }

    #[test]
    fn a_udp_packets_key_has_its_ports() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .udp(|udp| {
                udp.set_source(UdpPort::new_checked(49152).unwrap());
                udp.set_destination(UdpPort::new_checked(3784).unwrap());
            })
            .build_headers()
            .unwrap();
        let key = Key::of(&headers).unwrap();
        assert!(matches!(key.frame, Frame::Ipv4(Ip { l4, .. }) if l4 == udp(49152, 3784)));
    }

    #[test]
    fn a_non_ip_frames_key_is_its_ethertype() {
        let eth = Eth::new(
            SourceMac::new(MACS[2]).unwrap(),
            DestinationMac::new(Mac::BROADCAST).unwrap(),
            EthType::ARP,
        );
        let headers = HeadersBuilder::default().eth(Some(eth)).build().unwrap();
        assert_eq!(
            Key::of(&headers),
            Ok(Key {
                dst_mac: Mac::BROADCAST,
                frame: Frame::Other(EthType::ARP),
            })
        );
    }

    #[test]
    fn a_frame_without_ethernet_has_no_key() {
        let headers = HeadersBuilder::default().build().unwrap();
        assert_eq!(Key::of(&headers), Err(crate::NotEthernet));
    }
}
