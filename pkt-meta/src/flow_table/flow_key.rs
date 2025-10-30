// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::num::NonZero;

use etherparse::{Icmpv4Type, Icmpv6Type};
use net::buffer::PacketBufferMut;
use net::headers::{
    EmbeddedTransport, Transport, TryEmbeddedHeaders, TryEmbeddedTransport, TryHeaders, TryInnerIp,
    TryIp, TryTransport,
};
use net::icmp_any::TruncatedIcmpAny;
use net::icmp4::{Icmp4, TruncatedIcmp4};
use net::icmp6::{Icmp6, TruncatedIcmp6};
use net::packet::Packet;
use net::packet::VpcDiscriminant;
use net::tcp::TcpPort;
use net::udp::UdpPort;

#[derive(Debug, thiserror::Error)]
pub enum FlowKeyError {
    #[error("Flow key data not found in packet")]
    NoFlowKeyData,
}

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
pub struct TcpProtoKey {
    pub src_port: TcpPort,
    pub dst_port: TcpPort,
}

impl TcpProtoKey {
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
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
pub struct UdpProtoKey {
    pub src_port: UdpPort,
    pub dst_port: UdpPort,
}

impl UdpProtoKey {
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
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

type IcmpIdentifier = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InnerIcmpProtoKey {
    QueryMsgData(IcmpIdentifier),
    Unsupported,
}

impl InnerIcmpProtoKey {
    fn new_icmp_v4(icmp: &TruncatedIcmp4) -> Self {
        if icmp.is_query_message()
            && let Some(id) = icmp.identifier()
        {
            InnerIcmpProtoKey::QueryMsgData(id)
        } else {
            InnerIcmpProtoKey::Unsupported
        }
    }

    fn new_icmp_v6(icmp: &TruncatedIcmp6) -> Self {
        if icmp.is_query_message()
            && let Some(id) = icmp.identifier()
        {
            InnerIcmpProtoKey::QueryMsgData(id)
        } else {
            InnerIcmpProtoKey::Unsupported
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InnerIpProtoKey {
    Tcp(TcpProtoKey),
    Udp(UdpProtoKey),
    Icmp(InnerIcmpProtoKey),
}

impl InnerIpProtoKey {
    #[must_use]
    pub fn reverse(&self) -> Self {
        match self {
            InnerIpProtoKey::Tcp(tcp) => InnerIpProtoKey::Tcp(tcp.reverse()),
            InnerIpProtoKey::Udp(udp) => InnerIpProtoKey::Udp(udp.reverse()),
            InnerIpProtoKey::Icmp(_) => *self,
        }
    }
}

impl From<InnerIpProtoKey> for IpProtoKey {
    fn from(value: InnerIpProtoKey) -> Self {
        match value {
            InnerIpProtoKey::Tcp(tcp) => IpProtoKey::Tcp(tcp),
            InnerIpProtoKey::Udp(udp) => IpProtoKey::Udp(udp),
            InnerIpProtoKey::Icmp(icmp) => match icmp {
                InnerIcmpProtoKey::QueryMsgData(id) => {
                    IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(id))
                }
                InnerIcmpProtoKey::Unsupported => IpProtoKey::Icmp(IcmpProtoKey::Unsupported),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EmbeddedPacketData {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    proto_key_info: InnerIpProtoKey,
}

impl EmbeddedPacketData {
    pub fn try_from_packet<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<Self> {
        let headers = packet.embedded_headers()?;

        let ip = headers.try_inner_ip()?;
        let src_ip = ip.src_addr();
        let dst_ip = ip.dst_addr();

        let transport = headers.try_embedded_transport()?;
        let proto_key_info = match transport {
            EmbeddedTransport::Tcp(tcp) => InnerIpProtoKey::Tcp(TcpProtoKey {
                src_port: tcp.source(),
                dst_port: tcp.destination(),
            }),
            EmbeddedTransport::Udp(udp) => InnerIpProtoKey::Udp(UdpProtoKey {
                src_port: udp.source(),
                dst_port: udp.destination(),
            }),
            EmbeddedTransport::Icmp4(icmp) => {
                InnerIpProtoKey::Icmp(InnerIcmpProtoKey::new_icmp_v4(icmp))
            }
            EmbeddedTransport::Icmp6(icmp) => {
                InnerIpProtoKey::Icmp(InnerIcmpProtoKey::new_icmp_v6(icmp))
            }
        };
        Some(Self {
            src_ip,
            dst_ip,
            proto_key_info,
        })
    }
    #[must_use]
    pub fn src_ip(&self) -> &IpAddr {
        &self.src_ip
    }
    #[must_use]
    pub fn dst_ip(&self) -> &IpAddr {
        &self.dst_ip
    }
    #[must_use]
    pub fn proto_key_info(&self) -> &InnerIpProtoKey {
        &self.proto_key_info
    }
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            proto_key_info: self.proto_key_info.reverse(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IcmpProtoKey {
    QueryMsgData(IcmpIdentifier),
    ErrorMsgData(Option<EmbeddedPacketData>),
    Unsupported,
}

impl IcmpProtoKey {
    fn new_icmp_v4<Buf: PacketBufferMut>(packet: &Packet<Buf>, icmp: &Icmp4) -> Self {
        match icmp.icmp_type() {
            Icmpv4Type::EchoRequest(echo_header) | Icmpv4Type::EchoReply(echo_header) => {
                IcmpProtoKey::QueryMsgData(echo_header.id)
            }
            Icmpv4Type::TimeExceeded(_) | Icmpv4Type::DestinationUnreachable(_) => {
                IcmpProtoKey::ErrorMsgData(EmbeddedPacketData::try_from_packet(packet))
            }
            _ => IcmpProtoKey::Unsupported,
        }
    }

    fn new_icmp_v6<Buf: PacketBufferMut>(packet: &Packet<Buf>, icmp: &Icmp6) -> Self {
        #[allow(clippy::match_single_binding)]
        match icmp.icmp_type() {
            Icmpv6Type::EchoRequest(echo_header) | Icmpv6Type::EchoReply(echo_header) => {
                IcmpProtoKey::QueryMsgData(echo_header.id)
            }
            Icmpv6Type::TimeExceeded(_) | Icmpv6Type::DestinationUnreachable(_) => {
                IcmpProtoKey::ErrorMsgData(EmbeddedPacketData::try_from_packet(packet))
            }
            _ => IcmpProtoKey::Unsupported,
        }
    }

    #[must_use]
    pub fn reverse(&self) -> Self {
        match self {
            IcmpProtoKey::QueryMsgData(id) => IcmpProtoKey::QueryMsgData(*id),
            IcmpProtoKey::ErrorMsgData(inner) => {
                IcmpProtoKey::ErrorMsgData(inner.as_ref().map(EmbeddedPacketData::reverse))
            }
            IcmpProtoKey::Unsupported => IcmpProtoKey::Unsupported,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, thiserror::Error)]
pub enum IpProtoKeyError {
    #[error("Variant does not use ports (e.g. ICMP)")]
    NoPortsForType,
    #[error("Variant, or variant's value, does not use identifier (e.g. TCP, ICMP Error message)")]
    NoIdentifierForType,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub enum IpProtoKey {
    Tcp(TcpProtoKey),
    Udp(UdpProtoKey),
    Icmp(IcmpProtoKey),
}

impl IpProtoKey {
    #[must_use]
    pub fn reverse(&self) -> Self {
        match self {
            IpProtoKey::Tcp(tcp) => IpProtoKey::Tcp(tcp.reverse()),
            IpProtoKey::Udp(udp) => IpProtoKey::Udp(udp.reverse()),
            IpProtoKey::Icmp(icmp) => IpProtoKey::Icmp(icmp.reverse()),
        }
    }

    /// Sets the source port of the flow key.
    ///
    /// # Errors
    ///
    /// Returns [`IpProtoKeyError::NoPortsForType`] if the [`IpProtoKey`] enum value does not have a
    /// source port.
    pub fn try_set_src_port(&mut self, port: NonZero<u16>) -> Result<(), IpProtoKeyError> {
        match self {
            IpProtoKey::Tcp(tcp) => tcp.src_port = TcpPort::new(port),
            IpProtoKey::Udp(udp) => udp.src_port = UdpPort::new(port),
            IpProtoKey::Icmp(_) => return Err(IpProtoKeyError::NoPortsForType),
        }
        Ok(())
    }

    /// Sets the destination port of the flow key.
    ///
    /// # Errors
    ///
    /// Returns [`IpProtoKeyError::NoPortsForType`] if the [`IpProtoKey`] enum value does not have a
    /// destination port.
    pub fn try_set_dst_port(&mut self, port: NonZero<u16>) -> Result<(), IpProtoKeyError> {
        match self {
            IpProtoKey::Tcp(tcp) => tcp.dst_port = TcpPort::new(port),
            IpProtoKey::Udp(udp) => udp.dst_port = UdpPort::new(port),
            IpProtoKey::Icmp(_) => return Err(IpProtoKeyError::NoPortsForType),
        }
        Ok(())
    }

    /// Sets the ICMP Query identifier of the flow key, if possible
    ///
    /// # Errors
    ///
    /// Returns [`IpProtoKeyError::NoIdentifierForType`] if the [`IpProtoKey`] enum value does not
    /// have an identifier.
    pub fn try_set_identifier(&mut self, identifier: u16) -> Result<(), IpProtoKeyError> {
        if let IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(_)) = self {
            *self = IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(identifier));
            return Ok(());
        }
        Err(IpProtoKeyError::NoIdentifierForType)
    }
}

impl SrcLeqDst for IpProtoKey {
    fn src_leq_dst(&self) -> bool {
        match self {
            IpProtoKey::Tcp(tcp) => tcp.src_leq_dst(),
            IpProtoKey::Udp(udp) => udp.src_leq_dst(),
            IpProtoKey::Icmp(_) => true,
        }
    }
}

impl HashSrc for IpProtoKey {
    fn hash_src<H: Hasher>(&self, state: &mut H) {
        match self {
            IpProtoKey::Tcp(tcp) => tcp.hash_src(state),
            IpProtoKey::Udp(udp) => udp.hash_src(state),
            IpProtoKey::Icmp(_) => (),
        }
    }
}

impl HashDst for IpProtoKey {
    fn hash_dst<H: Hasher>(&self, state: &mut H) {
        match self {
            IpProtoKey::Tcp(tcp) => tcp.hash_dst(state),
            IpProtoKey::Udp(udp) => udp.hash_dst(state),
            IpProtoKey::Icmp(_) => (),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct FlowKeyData {
    src_vpcd: Option<VpcDiscriminant>,
    dst_vpcd: Option<VpcDiscriminant>, // If None, the dst_vpcd is ambiguous and the flow table is needed to resolve it
    src_ip: IpAddr,
    dst_ip: IpAddr,
    proto_key_info: IpProtoKey,
}

impl FlowKeyData {
    #[must_use]
    pub fn new(
        src_vpcd: Option<VpcDiscriminant>,
        src_ip: IpAddr,
        dst_vpcd: Option<VpcDiscriminant>,
        dst_ip: IpAddr,
        ip_proto_key: IpProtoKey,
    ) -> Self {
        Self {
            src_vpcd,
            src_ip,
            dst_vpcd,
            dst_ip,
            proto_key_info: ip_proto_key,
        }
    }

    #[must_use]
    pub fn src_vpcd(&self) -> Option<VpcDiscriminant> {
        self.src_vpcd
    }

    #[must_use]
    pub fn dst_vpcd(&self) -> Option<VpcDiscriminant> {
        self.dst_vpcd
    }

    #[must_use]
    pub fn src_ip(&self) -> &IpAddr {
        &self.src_ip
    }

    #[must_use]
    pub fn dst_ip(&self) -> &IpAddr {
        &self.dst_ip
    }

    #[must_use]
    pub fn proto_key_info(&self) -> &IpProtoKey {
        &self.proto_key_info
    }

    #[must_use]
    fn symmetric_eq(&self, other: &Self) -> bool {
        // Straightforward comparison
        let src_to_src = self.src_vpcd == other.src_vpcd
            && self.dst_vpcd == other.dst_vpcd
            && self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.proto_key_info == other.proto_key_info;

        // Src to dst
        src_to_src
            || self.src_vpcd == other.dst_vpcd
                && self.dst_vpcd == other.src_vpcd
                && self.src_ip == other.dst_ip
                && self.dst_ip == other.src_ip
                && self.proto_key_info == other.proto_key_info.reverse()
    }

    fn symmetric_hash<H: Hasher>(&self, state: &mut H) {
        0xb1d1_u16.hash(state); // Magic number to make sure the hash is different for bidirectional and unidirectional flows
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

    /// Creates a new flow key with src and dst swapped
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            src_vpcd: self.dst_vpcd,
            dst_vpcd: self.src_vpcd,
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            proto_key_info: self.proto_key_info.reverse(),
        }
    }
}

impl SrcLeqDst for FlowKeyData {
    fn src_leq_dst(&self) -> bool {
        match (self.src_vpcd, self.dst_vpcd) {
            (Some(src_vpcd), Some(dst_vpcd)) => {
                src_vpcd < dst_vpcd
                    || (src_vpcd == dst_vpcd && self.src_ip < self.dst_ip)
                    || (src_vpcd == dst_vpcd
                        && self.src_ip == self.dst_ip
                        && self.proto_key_info.src_leq_dst())
            }
            (Some(_), None) => true, // No dst vpcd is bigger than anything with a src vpcd
            (None, Some(_)) => false, // No src vpcd is bigger than anything with a dst vpcd
            (None, None) => {
                (self.src_ip < self.dst_ip)
                    || (self.src_ip == self.dst_ip && self.proto_key_info.src_leq_dst())
            }
        }
    }
}

impl Hash for FlowKeyData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_vpcd.hash(state);
        self.src_ip.hash(state);
        self.proto_key_info.hash_src(state);
        self.dst_vpcd.hash(state);
        self.dst_ip.hash(state);
        self.proto_key_info.hash_dst(state);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialOrd, Ord)]
pub enum FlowKey {
    Bidirectional(FlowKeyData),
    Unidirectional(FlowKeyData),
}

impl FlowKey {
    #[must_use]
    pub fn data(&self) -> &FlowKeyData {
        match self {
            FlowKey::Bidirectional(data) | FlowKey::Unidirectional(data) => data,
        }
    }

    /// Create a unidirectional flow key
    ///
    /// packets with src -> dst will match, but dst -> src will not
    #[must_use]
    pub fn uni(
        src_vpcd: Option<VpcDiscriminant>,
        src_ip: IpAddr,
        dst_vpcd: Option<VpcDiscriminant>, // If None, the dst_vpcd is ambiguous and the flow table is needed to resolve it
        dst_ip: IpAddr,
        proto_key_info: IpProtoKey,
    ) -> FlowKey {
        FlowKey::Unidirectional(FlowKeyData::new(
            src_vpcd,
            src_ip,
            dst_vpcd,
            dst_ip,
            proto_key_info,
        ))
    }

    /// Create a bidirectional flow key
    ///
    /// packets with src -> dst and dst -> src will match and hash to the same value.
    #[must_use]
    pub fn bidi(
        src_vpcd: Option<VpcDiscriminant>,
        src_ip: IpAddr,
        dst_vpcd: Option<VpcDiscriminant>, // If None, the dst_vpcd is ambiguous and the flow table is needed to resolve it
        dst_ip: IpAddr,
        proto_key_info: IpProtoKey,
    ) -> FlowKey {
        FlowKey::Bidirectional(FlowKeyData::new(
            src_vpcd,
            src_ip,
            dst_vpcd,
            dst_ip,
            proto_key_info,
        ))
    }

    // Creates the flow key with src and dst swapped
    #[must_use]
    pub fn reverse(&self) -> FlowKey {
        match self {
            FlowKey::Bidirectional(data) => FlowKey::Bidirectional(data.reverse()),
            FlowKey::Unidirectional(data) => FlowKey::Unidirectional(data.reverse()),
        }
    }
}

// The FlowKey Eq is symmetric, src == src or src == dst
impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FlowKey::Bidirectional(a), FlowKey::Bidirectional(b)) => a.symmetric_eq(b),
            (FlowKey::Unidirectional(a), FlowKey::Unidirectional(b)) => a == b,
            _ => false,
        }
    }
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            FlowKey::Bidirectional(a) => a.symmetric_hash(state),
            FlowKey::Unidirectional(a) => a.hash(state),
        }
    }
}

/// Wrapper to specify unidirectional `FlowKey` creation
///
/// Example:
/// ```
/// # use dataplane_pkt_meta::flow_table::FlowKey;
/// # use dataplane_pkt_meta::flow_table::flow_key::{Uni};
/// # use net::ip::NextHeader;
/// # let packet = net::packet::test_utils::build_test_ipv4_packet_with_transport(100, Some(NextHeader::TCP)).unwrap();
/// let flow_key = FlowKey::try_from(Uni(&packet));
/// # assert!(flow_key.is_ok());
/// ```
#[repr(transparent)]
#[derive(Debug)]
pub struct Uni<T>(pub T);

/// Wrapper to specify bidirectional `FlowKey` creation
///
/// Example:
/// ```
/// # use dataplane_pkt_meta::flow_table::FlowKey;
/// # use dataplane_pkt_meta::flow_table::flow_key::{Bidi};
/// # use net::ip::NextHeader;
/// # let packet = net::packet::test_utils::build_test_ipv4_packet_with_transport(100, Some(NextHeader::TCP)).unwrap();
/// let flow_key = FlowKey::try_from(Bidi(&packet));
/// # assert!(flow_key.is_ok());
/// ```
#[repr(transparent)]
#[derive(Debug)]
pub struct Bidi<T>(pub T);

fn flow_key_data_from_packet<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<FlowKeyData> {
    let ip = packet.headers().try_ip()?;
    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();

    let transport = packet.headers().try_transport()?;
    let ip_proto_key = match transport {
        Transport::Tcp(tcp) => IpProtoKey::Tcp(TcpProtoKey {
            src_port: tcp.source(),
            dst_port: tcp.destination(),
        }),
        Transport::Udp(udp) => IpProtoKey::Udp(UdpProtoKey {
            src_port: udp.source(),
            dst_port: udp.destination(),
        }),
        Transport::Icmp4(icmp) => IpProtoKey::Icmp(IcmpProtoKey::new_icmp_v4(packet, icmp)),
        Transport::Icmp6(icmp) => IpProtoKey::Icmp(IcmpProtoKey::new_icmp_v6(packet, icmp)),
        #[allow(unreachable_patterns)]
        _ => return None,
    };

    let src_vpcd = packet.meta.src_vpcd;
    let dst_vpcd = packet.meta.dst_vpcd;
    Some(FlowKeyData::new(
        src_vpcd,
        src_ip,
        dst_vpcd,
        dst_ip,
        ip_proto_key,
    ))
}

impl<Buf: PacketBufferMut> TryFrom<Uni<&Packet<Buf>>> for FlowKey {
    type Error = FlowKeyError;
    fn try_from(packet: Uni<&Packet<Buf>>) -> Result<Self, Self::Error> {
        let packet = packet.0;
        let FlowKeyData {
            src_vpcd,
            src_ip,
            dst_vpcd,
            dst_ip,
            proto_key_info,
        } = flow_key_data_from_packet(packet).ok_or(FlowKeyError::NoFlowKeyData)?;

        Ok(FlowKey::uni(
            src_vpcd,
            src_ip,
            dst_vpcd,
            dst_ip,
            proto_key_info,
        ))
    }
}

impl<Buf: PacketBufferMut> TryFrom<Bidi<&Packet<Buf>>> for FlowKey {
    type Error = FlowKeyError;
    fn try_from(packet: Bidi<&Packet<Buf>>) -> Result<Self, Self::Error> {
        let packet = packet.0;
        let FlowKeyData {
            src_vpcd,
            src_ip,
            dst_vpcd,
            dst_ip,
            proto_key_info,
        } = flow_key_data_from_packet(packet).ok_or(FlowKeyError::NoFlowKeyData)?;

        Ok(FlowKey::bidi(
            src_vpcd,
            src_ip,
            dst_vpcd,
            dst_ip,
            proto_key_info,
        ))
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{
        EmbeddedPacketData, FlowKey, FlowKeyData, IcmpProtoKey, InnerIcmpProtoKey, InnerIpProtoKey,
        IpProtoKey, TcpProtoKey, UdpProtoKey,
    };
    use bolero::{Driver, TypeGenerator};
    use net::ip::UnicastIpAddr;
    use net::ipv4::addr::UnicastIpv4Addr;
    use net::ipv6::addr::UnicastIpv6Addr;

    impl TypeGenerator for TcpProtoKey {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let src_port = driver.produce()?;
            let dst_port = driver.produce()?;
            Some(TcpProtoKey { src_port, dst_port })
        }
    }

    impl TypeGenerator for UdpProtoKey {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let src_port = driver.produce()?;
            let dst_port = driver.produce()?;
            Some(UdpProtoKey { src_port, dst_port })
        }
    }

    impl TypeGenerator for InnerIcmpProtoKey {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            // More weight to QueryMsgData
            if driver.produce::<u8>()? % 8 == 0 {
                Some(InnerIcmpProtoKey::Unsupported)
            } else {
                let id = driver.produce()?;
                Some(InnerIcmpProtoKey::QueryMsgData(id))
            }
        }
    }

    impl TypeGenerator for InnerIpProtoKey {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            match driver.produce::<u8>()? % 3 {
                0 => {
                    let tcp = TcpProtoKey::generate(driver)?;
                    Some(InnerIpProtoKey::Tcp(tcp))
                }
                1 => {
                    let udp = UdpProtoKey::generate(driver)?;
                    Some(InnerIpProtoKey::Udp(udp))
                }
                _ => {
                    let icmp = InnerIcmpProtoKey::generate(driver)?;
                    Some(InnerIpProtoKey::Icmp(icmp))
                }
            }
        }
    }

    impl TypeGenerator for EmbeddedPacketData {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let src_ip = driver.produce()?;
            let dst_ip = driver.produce()?;
            let proto_key_info = InnerIpProtoKey::generate(driver)?;
            Some(EmbeddedPacketData {
                src_ip,
                dst_ip,
                proto_key_info,
            })
        }
    }

    impl TypeGenerator for IcmpProtoKey {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let variant = driver.produce::<u8>()?;
            match variant % 3 {
                0 => {
                    let id = driver.produce()?;
                    Some(IcmpProtoKey::QueryMsgData(id))
                }
                1 => {
                    let variant = driver.produce::<u8>()?;
                    let inner = match variant % 2 {
                        0 => None,
                        _ => Some(EmbeddedPacketData::generate(driver)?),
                    };
                    Some(IcmpProtoKey::ErrorMsgData(inner))
                }
                _ => Some(IcmpProtoKey::Unsupported),
            }
        }
    }

    impl TypeGenerator for IpProtoKey {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            // Pick a variant at random
            let variant = driver.produce::<u8>()?;
            match variant % 3 {
                0 => {
                    let tcp = TcpProtoKey::generate(driver)?;
                    Some(IpProtoKey::Tcp(tcp))
                }
                1 => {
                    let udp = UdpProtoKey::generate(driver)?;
                    Some(IpProtoKey::Udp(udp))
                }
                _ => {
                    let icmp = IcmpProtoKey::generate(driver)?;
                    Some(IpProtoKey::Icmp(icmp))
                }
            }
        }
    }

    impl TypeGenerator for FlowKeyData {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            let src_vpcd = driver.produce();
            let dst_vpcd = driver.produce();
            let v6 = driver.produce::<bool>()?;
            // In theory, src_ip and dst_ip could have different versions, e.g., for NAT64, but we don't support that yet
            let (src_ip, dst_ip) = if v6 {
                (
                    UnicastIpAddr::from(driver.produce::<UnicastIpv6Addr>()?).into(),
                    UnicastIpAddr::from(driver.produce::<UnicastIpv6Addr>()?).into(),
                )
            } else {
                (
                    UnicastIpAddr::from(driver.produce::<UnicastIpv4Addr>()?).into(),
                    UnicastIpAddr::from(driver.produce::<UnicastIpv4Addr>()?).into(),
                )
            };
            let proto_key_info = super::IpProtoKey::generate(driver)?;
            Some(FlowKeyData {
                src_vpcd,
                dst_vpcd,
                src_ip,
                dst_ip,
                proto_key_info,
            })
        }
    }

    impl TypeGenerator for FlowKey {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            // Pick between Bidirectional and Unidirectional at random
            let variant = driver.produce::<u8>()?;
            let data = FlowKeyData::generate(driver)?;
            match variant % 2 {
                0 => Some(FlowKey::Bidirectional(data)),
                _ => Some(FlowKey::Unidirectional(data)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::AHasher;
    use bolero::{Driver, ValueGenerator};
    use net::buffer::TestBuffer;
    use net::headers::TryIpv6;
    use net::ip::UnicastIpAddr;
    use net::ipv4::addr::UnicastIpv4Addr;
    use net::ipv6::addr::UnicastIpv6Addr;
    use net::packet::contract::CommonPacket;
    use net::packet::{Packet, VpcDiscriminant};
    use net::vxlan::Vni;

    #[test]
    fn test_flow_key_src_leq_dst() {
        // VNI
        let flow_key_1 = FlowKey::uni(
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(1024).unwrap(),
                dst_port: TcpPort::new_checked(2048).unwrap(),
            }),
        );

        assert!(!flow_key_1.data().src_leq_dst());

        let flow_key_2 = FlowKey::uni(
            Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(1025).unwrap(),
                dst_port: TcpPort::new_checked(2048).unwrap(),
            }),
        );

        assert!(flow_key_2.data().src_leq_dst());

        // IP decides
        let flow_key_3 = FlowKey::uni(
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.5".parse::<IpAddr>().unwrap(),
            IpProtoKey::Udp(UdpProtoKey {
                src_port: UdpPort::new_checked(1025).unwrap(),
                dst_port: UdpPort::new_checked(2048).unwrap(),
            }),
        );

        assert!(flow_key_3.data().src_leq_dst());

        let flow_key_4 = FlowKey::uni(
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.5".parse::<IpAddr>().unwrap(),
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            IpProtoKey::Udp(UdpProtoKey {
                src_port: UdpPort::new_checked(1025).unwrap(),
                dst_port: UdpPort::new_checked(2048).unwrap(),
            }),
        );

        assert!(!flow_key_4.data().src_leq_dst());

        // Port decides
        let flow_key_5 = FlowKey::uni(
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            IpProtoKey::Udp(UdpProtoKey {
                src_port: UdpPort::new_checked(1025).unwrap(),
                dst_port: UdpPort::new_checked(2048).unwrap(),
            }),
        );

        assert!(flow_key_5.data().src_leq_dst());

        let flow_key_6 = FlowKey::uni(
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            IpProtoKey::Udp(UdpProtoKey {
                src_port: UdpPort::new_checked(2048).unwrap(),
                dst_port: UdpPort::new_checked(1025).unwrap(),
            }),
        );

        assert!(!flow_key_6.data().src_leq_dst());
    }

    #[test]
    fn test_flow_key_symmetric_eq() {
        let flow_key_1 = FlowKey::bidi(
            Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.5".parse::<IpAddr>().unwrap(),
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(1025).unwrap(),
                dst_port: TcpPort::new_checked(2048).unwrap(),
            }),
        );

        let flow_key_2 = FlowKey::bidi(
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "1.2.3.5".parse::<IpAddr>().unwrap(),
            Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(2048).unwrap(),
                dst_port: TcpPort::new_checked(1025).unwrap(),
            }),
        );

        assert_eq!(flow_key_1, flow_key_2);
        assert_eq!(flow_key_1, flow_key_1);
        assert_eq!(flow_key_2, flow_key_2);
    }

    #[test]
    fn test_flow_key_reverse() {
        let flow_key = FlowKey::uni(
            Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            Some(VpcDiscriminant::VNI(Vni::new_checked(2).unwrap())),
            "4.5.6.7".parse::<IpAddr>().unwrap(),
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(1025).unwrap(),
                dst_port: TcpPort::new_checked(2048).unwrap(),
            }),
        );

        let reverse_flow_key = flow_key.reverse();

        assert_eq!(flow_key.data().src_vpcd, reverse_flow_key.data().dst_vpcd);
        assert_eq!(flow_key.data().dst_vpcd, reverse_flow_key.data().src_vpcd);
        assert_eq!(flow_key.data().src_ip, reverse_flow_key.data().dst_ip);
        assert_eq!(flow_key.data().dst_ip, reverse_flow_key.data().src_ip);
        assert_eq!(
            flow_key.data().proto_key_info,
            reverse_flow_key.data().proto_key_info.reverse()
        );
    }

    #[test]
    fn test_flow_key_bidi_hash() {
        let flow_key = FlowKey::bidi(
            None,
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            None,
            "4.5.6.7".parse::<IpAddr>().unwrap(),
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(1025).unwrap(),
                dst_port: TcpPort::new_checked(2048).unwrap(),
            }),
        );

        let reverse_flow_key = flow_key.reverse();

        // Reverse should be equal to the original
        assert_eq!(flow_key, reverse_flow_key);

        // Hash should be the same
        let mut hash = AHasher::default();
        let mut reverse_hash = AHasher::default();
        flow_key.hash(&mut hash);
        reverse_flow_key.hash(&mut reverse_hash);
        assert_eq!(hash.finish(), reverse_hash.finish());
    }

    #[test]
    fn test_flow_key_uni_hash() {
        let flow_key = FlowKey::uni(
            None,
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            None,
            "4.5.6.7".parse::<IpAddr>().unwrap(),
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(1025).unwrap(),
                dst_port: TcpPort::new_checked(2048).unwrap(),
            }),
        );

        let reverse_flow_key = flow_key.reverse();

        // Reverse should not be equal to the original
        assert_ne!(flow_key, reverse_flow_key);

        // Hash should be different
        let mut hash = AHasher::default();
        let mut reverse_hash = AHasher::default();
        flow_key.hash(&mut hash);
        reverse_flow_key.hash(&mut reverse_hash);
        assert_ne!(hash.finish(), reverse_hash.finish());
    }

    /// Set the packet fields based on the flow key
    ///
    /// # Panics
    ///
    /// This function panics if the packet has a different transport protocol than the flow key.
    /// It also panics if the packet IP address family does not match the flow key.
    fn set_packet_fields(packet: &mut Packet<TestBuffer>, flow_key: &FlowKey) {
        let flow_key_data = flow_key.data();
        packet
            .set_ip_source(flow_key_data.src_ip.try_into().unwrap())
            .unwrap();
        packet.set_ip_destination(flow_key_data.dst_ip).unwrap();
        match flow_key_data.proto_key_info {
            IpProtoKey::Tcp(tcp) => {
                packet.set_tcp_source_port(tcp.src_port).unwrap();
                packet.set_tcp_destination_port(tcp.dst_port).unwrap();
            }
            IpProtoKey::Udp(udp) => {
                packet.set_udp_source_port(udp.src_port).unwrap();
                packet.set_udp_destination_port(udp.dst_port).unwrap();
            }
            IpProtoKey::Icmp(icmp) => match icmp {
                IcmpProtoKey::QueryMsgData(id) => {
                    packet.set_icmp_query_identifier(id).unwrap();
                }
                IcmpProtoKey::ErrorMsgData(Some(data)) => {
                    // FIXME: This code is never exercised.
                    // This is because we never produce packets with non-empty embedded headers from
                    // the packet generator. As a result, we never have embedded headers to pass to
                    // the IcmpProtoKey::ErrorMsgData().
                    match data.proto_key_info() {
                        InnerIpProtoKey::Tcp(tcp) => {
                            packet
                                .set_icmp_error_message_data_with_ports(
                                    data.src_ip(),
                                    data.dst_ip(),
                                    (*tcp.src_port()).into(),
                                    (*tcp.dst_port()).into(),
                                )
                                .unwrap();
                        }
                        InnerIpProtoKey::Udp(udp) => {
                            packet
                                .set_icmp_error_message_data_with_ports(
                                    data.src_ip(),
                                    data.dst_ip(),
                                    (*udp.src_port()).into(),
                                    (*udp.dst_port()).into(),
                                )
                                .unwrap();
                        }
                        InnerIpProtoKey::Icmp(icmp) => match icmp {
                            InnerIcmpProtoKey::QueryMsgData(id) => {
                                packet
                                    .set_icmp_error_message_data_with_identifier(
                                        data.src_ip(),
                                        data.dst_ip(),
                                        *id,
                                    )
                                    .unwrap();
                            }
                            InnerIcmpProtoKey::Unsupported => {}
                        },
                    }
                }
                IcmpProtoKey::ErrorMsgData(None) | IcmpProtoKey::Unsupported => {}
            },
        }
    }

    struct FlowKeyAndPacket;
    impl ValueGenerator for FlowKeyAndPacket {
        type Output = (Option<FlowKey>, Packet<TestBuffer>);
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let packet = CommonPacket.generate(driver)?;
            let v6 = packet.headers().try_ipv6().is_some();
            let bidi = driver.produce::<bool>()?;
            let (src_ip, dst_ip) = if v6 {
                (
                    UnicastIpAddr::from(driver.produce::<UnicastIpv6Addr>()?).into(),
                    UnicastIpAddr::from(driver.produce::<UnicastIpv6Addr>()?).into(),
                )
            } else {
                (
                    UnicastIpAddr::from(driver.produce::<UnicastIpv4Addr>()?).into(),
                    UnicastIpAddr::from(driver.produce::<UnicastIpv4Addr>()?).into(),
                )
            };

            let src_vpcd = packet.meta.src_vpcd;
            let dst_vpcd = packet.meta.dst_vpcd;

            let transport = packet.headers().try_transport()?;
            let proto = match transport {
                Transport::Tcp(_) => Some(IpProtoKey::Tcp(TcpProtoKey {
                    src_port: driver.produce()?,
                    dst_port: driver.produce()?,
                })),
                Transport::Udp(_) => Some(IpProtoKey::Udp(UdpProtoKey {
                    src_port: driver.produce()?,
                    dst_port: driver.produce()?,
                })),
                // To keep in sync with IcmpProtoKey::new_icmp_v4()
                Transport::Icmp4(icmp) => match icmp.icmp_type() {
                    Icmpv4Type::EchoRequest(_) | Icmpv4Type::EchoReply(_) => Some(
                        IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(driver.produce()?)),
                    ),
                    Icmpv4Type::DestinationUnreachable(_) | Icmpv4Type::TimeExceeded(_) => {
                        Some(IpProtoKey::Icmp(IcmpProtoKey::ErrorMsgData(None)))
                    }
                    _ => Some(IpProtoKey::Icmp(IcmpProtoKey::Unsupported)),
                },
                // To keep in sync with IcmpProtoKey::new_icmp_v6()
                Transport::Icmp6(icmp) => match icmp.icmp_type() {
                    Icmpv6Type::EchoRequest(_) | Icmpv6Type::EchoReply(_) => Some(
                        IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(driver.produce()?)),
                    ),
                    Icmpv6Type::DestinationUnreachable(_) | Icmpv6Type::TimeExceeded(_) => {
                        Some(IpProtoKey::Icmp(IcmpProtoKey::ErrorMsgData(None)))
                    }
                    _ => Some(IpProtoKey::Icmp(IcmpProtoKey::Unsupported)),
                },
            };
            if let Some(proto) = proto {
                let (flow_key, mut packet) = if bidi {
                    (
                        FlowKey::bidi(src_vpcd, src_ip, dst_vpcd, dst_ip, proto),
                        packet,
                    )
                } else {
                    (
                        FlowKey::uni(src_vpcd, src_ip, dst_vpcd, dst_ip, proto),
                        packet,
                    )
                };
                set_packet_fields(&mut packet, &flow_key);
                Some((Some(flow_key), packet))
            } else {
                Some((None, packet))
            }
        }
    }

    #[test]
    fn test_flow_key_data_from_packet() {
        bolero::check!()
            .with_generator(FlowKeyAndPacket)
            .for_each(|(flow_key, packet)| match flow_key {
                Some(FlowKey::Bidirectional(_)) => {
                    let gen_flow_key = FlowKey::try_from(Bidi(packet)).unwrap();
                    assert_eq!(
                        gen_flow_key,
                        flow_key.unwrap(),
                        "Flow key mismatch: {gen_flow_key:#?} != {:#?}",
                        flow_key.unwrap()
                    );
                }
                Some(FlowKey::Unidirectional(_)) => {
                    let gen_flow_key = FlowKey::try_from(Uni(packet)).unwrap();
                    assert_eq!(
                        gen_flow_key,
                        flow_key.unwrap(),
                        "Flow key mismatch: {gen_flow_key:#?} != {:#?}",
                        flow_key.unwrap()
                    );
                }
                None => {
                    assert!(FlowKey::try_from(Uni(packet)).is_err());
                    assert!(FlowKey::try_from(Bidi(packet)).is_err());
                }
            });
    }
}
