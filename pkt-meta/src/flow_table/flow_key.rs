// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use net::packet::VpcDiscriminant;
use net::tcp::TcpPort;
use net::udp::UdpPort;

trait SrcLeqDst {
    fn src_leq_dst(&self) -> bool;
}

trait HashSrc {
    fn hash_src<H: Hasher>(&self, state: &mut H);
}

trait HashDst {
    fn hash_dst<H: Hasher>(&self, state: &mut H);
}

trait SrcDstPort {
    type Port: PartialEq + Eq + PartialOrd + Ord + Hash;
    fn src_port(&self) -> &Self::Port;
    fn dst_port(&self) -> &Self::Port;

    fn symmetric_eq(&self, other: &Self) -> bool {
        (self.src_port() == other.src_port() && self.dst_port() == other.dst_port())
            || (self.src_port() == other.dst_port() && self.dst_port() == other.src_port())
    }

    fn src_leq_dst(&self) -> bool {
        self.src_port() <= self.dst_port()
    }

    fn hash_src<H: Hasher>(&self, state: &mut H) {
        self.src_port().hash(state);
    }

    fn hash_dst<H: Hasher>(&self, state: &mut H) {
        self.dst_port().hash(state);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialOrd, Ord)]
struct TcpProtoKey {
    src_port: TcpPort,
    dst_port: TcpPort,
}

impl SrcDstPort for TcpProtoKey {
    type Port = TcpPort;
    fn src_port(&self) -> &Self::Port {
        &self.src_port
    }
    fn dst_port(&self) -> &Self::Port {
        &self.dst_port
    }
}

impl PartialEq for TcpProtoKey {
    fn eq(&self, other: &Self) -> bool {
        self.symmetric_eq(other)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialOrd, Ord)]
struct UdpProtoKey {
    src_port: UdpPort,
    dst_port: UdpPort,
}

impl SrcDstPort for UdpProtoKey {
    type Port = UdpPort;
    fn src_port(&self) -> &Self::Port {
        &self.src_port
    }
    fn dst_port(&self) -> &Self::Port {
        &self.dst_port
    }
}

impl PartialEq for UdpProtoKey {
    fn eq(&self, other: &Self) -> bool {
        self.symmetric_eq(other)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
enum IpProtoKey {
    Tcp(TcpProtoKey),
    Udp(UdpProtoKey),
    Icmp, // TODO(mvachhar): add icmp key information, varies by message type :(
}

impl SrcLeqDst for IpProtoKey {
    fn src_leq_dst(&self) -> bool {
        match self {
            IpProtoKey::Tcp(tcp) => tcp.src_leq_dst(),
            IpProtoKey::Udp(udp) => udp.src_leq_dst(),
            IpProtoKey::Icmp => true,
        }
    }
}

impl HashSrc for IpProtoKey {
    fn hash_src<H: Hasher>(&self, state: &mut H) {
        match self {
            IpProtoKey::Tcp(tcp) => tcp.hash_src(state),
            IpProtoKey::Udp(udp) => udp.hash_src(state),
            IpProtoKey::Icmp => (),
        }
    }
}

impl HashDst for IpProtoKey {
    fn hash_dst<H: Hasher>(&self, state: &mut H) {
        match self {
            IpProtoKey::Tcp(tcp) => tcp.hash_dst(state),
            IpProtoKey::Udp(udp) => udp.hash_dst(state),
            IpProtoKey::Icmp => (),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialOrd, Ord)]
pub struct FlowKey {
    src_vpcd: VpcDiscriminant,
    dst_vpcd: Option<VpcDiscriminant>, // If None, the dst_vpcd is ambiguous and the flow table is needed to resolve it
    src_ip: IpAddr,
    dst_ip: IpAddr,
    proto_key_info: IpProtoKey,
}

// The FlowKey Eq is symmetric, src == src or src == dst
impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        // Straightforward comparison
        let src_to_src = self.src_vpcd == other.src_vpcd
            && self.dst_vpcd == other.dst_vpcd
            && self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.proto_key_info == other.proto_key_info;

        // Src to dst
        src_to_src
            || other
                .dst_vpcd
                .map_or_else(|| true, |dst_vpcd| (dst_vpcd == self.src_vpcd))
                && self
                    .dst_vpcd
                    .map_or_else(|| true, |dst_vpcd| (dst_vpcd == other.src_vpcd))
                && self.src_ip == other.dst_ip
                && self.dst_ip == other.src_ip
                && self.proto_key_info == other.proto_key_info
    }
}

impl SrcLeqDst for FlowKey {
    fn src_leq_dst(&self) -> bool {
        let Some(dst_vpcd) = self.dst_vpcd else {
            return false; // Treat None as greater than all VpcDiscriminants
        };
        self.src_vpcd < dst_vpcd
            || (self.src_vpcd == dst_vpcd && (self.src_ip < self.dst_ip))
            || (self.src_ip == self.dst_ip && self.proto_key_info.src_leq_dst())
    }
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.src_leq_dst() {
            self.src_vpcd.hash(state);
            self.src_ip.hash(state);
            self.proto_key_info.hash_src(state);
            self.dst_vpcd.hash(state);
            self.dst_ip.hash(state);
            self.proto_key_info.hash_dst(state);
        } else {
            self.dst_vpcd.hash(state);
            self.dst_ip.hash(state);
            self.proto_key_info.hash_dst(state);
            self.src_vpcd.hash(state);
            self.src_ip.hash(state);
            self.proto_key_info.hash_src(state);
        }
    }
}
