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

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub enum IpProtoKey {
    Tcp(TcpProtoKey),
    Udp(UdpProtoKey),
    Icmp, // TODO(mvachhar): add icmp key information, varies by message type :(
}

impl IpProtoKey {
    #[must_use]
    pub fn reverse(&self) -> Self {
        match self {
            IpProtoKey::Tcp(tcp) => IpProtoKey::Tcp(tcp.reverse()),
            IpProtoKey::Udp(udp) => IpProtoKey::Udp(udp.reverse()),
            IpProtoKey::Icmp => IpProtoKey::Icmp,
        }
    }
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

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{FlowKey, FlowKeyData, IpProtoKey, TcpProtoKey, UdpProtoKey};
    use bolero::{Driver, TypeGenerator};
    use net::ip::UnicastIpAddr;

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
                _ => Some(IpProtoKey::Icmp),
            }
        }
    }

    impl TypeGenerator for FlowKeyData {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            let src_vpcd = driver.produce();
            let dst_vpcd = driver.produce();
            let src_ip = driver.produce::<UnicastIpAddr>()?.into();
            let dst_ip = driver.produce::<UnicastIpAddr>()?.into();
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
    use net::packet::VpcDiscriminant;
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
}
