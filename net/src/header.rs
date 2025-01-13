use crate::eth::{DestinationMacAddressError, MacAddress, SourceMacAddressError};
use crate::parse::{Cursor, DeParse, DeParseError, LengthError, Parse, ParseError, ParseWith};
use crate::vlan::{InvalidVid, Vid};
use etherparse::{
    EtherType, Ethernet2Header, Icmpv4Header, Icmpv6Header, IpAuthHeader, IpFragOffset, IpNumber,
    Ipv4Dscp, Ipv4Ecn, Ipv4Header, Ipv4Options, Ipv6Extensions, Ipv6Header, SingleVlanHeader,
    TcpHeader, UdpHeader, VlanId, VlanPcp,
};
use std::num::NonZero;
use tracing::{debug, trace};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eth {
    inner: Ethernet2Header,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vlan {
    inner: SingleVlanHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4 {
    inner: Ipv4Header,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAuth {
    inner: Box<IpAuthHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    inner: Ipv6Header,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Ext {
    inner: Box<Ipv6Extensions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcp {
    inner: TcpHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    inner: UdpHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp4 {
    inner: Icmpv4Header,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp6 {
    inner: Icmpv6Header,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Net {
    Ipv4(Ipv4),
    Ipv6(Ipv6),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetExt {
    IpAuth(IpAuth),
    Ipv6Ext(Ipv6Ext),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Eth(Eth),
    Vlan(Vlan),
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
    IpV6Ext(Ipv6Ext), // TODO: break out nested enum.  Nesting is counter productive here
}

impl Parse for Eth {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Ethernet2Header::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::LengthError(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl DeParse for Eth {
    type Error = LengthError;

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.inner.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn write(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        let unused = self.inner.write_to_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            DeParseError::LengthError(LengthError {
                expected,
                actual: len,
            })
        })?;
        assert!(
            unused.len() < len,
            "unused.len() >= buf.len() ({unused} >= {len})",
            unused = unused.len(),
        );
        let consumed = NonZero::new(len - unused.len()).ok_or_else(|| unreachable!())?;
        Ok(consumed)
    }
}

impl Parse for Vlan {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = SingleVlanHeader::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::LengthError(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl DeParse for Vlan {
    type Error = LengthError;

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.inner.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn write(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::LengthError(LengthError {
                expected: self.size(),
                actual: len,
            }));
        };
        buf[..self.size().get()].copy_from_slice(&self.inner.to_bytes());
        Ok(self.size())
    }
}

impl Parse for Ipv4 {
    type Error = etherparse::err::ipv4::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Ipv4Header::from_slice(buf).map_err(ParseError::FailedToParse)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl DeParse for Ipv4 {
    type Error = LengthError;

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.inner.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn write(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::LengthError(LengthError {
                expected: self.size(),
                actual: len,
            }));
        };
        buf[..self.size().get()].copy_from_slice(&self.inner.to_bytes());
        Ok(self.size())
    }
}

impl Parse for Ipv6 {
    type Error = etherparse::err::ipv6::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Ipv6Header::from_slice(buf).map_err(ParseError::FailedToParse)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl Parse for IpAuth {
    type Error = etherparse::err::ip_auth::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = IpAuthHeader::from_slice(buf)
            .map(|(h, rest)| (Box::new(h), rest))
            .map_err(ParseError::FailedToParse)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl ParseWith for Ipv6Ext {
    type Error = etherparse::err::ipv6_exts::HeaderSliceError;
    type Param = IpNumber;

    fn parse_with(
        ip_number: IpNumber,
        buf: &[u8],
    ) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Ipv6Extensions::from_slice(ip_number, buf)
            .map(|(h, _, rest)| (Box::new(h), rest))
            .map_err(ParseError::FailedToParse)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl Parse for Tcp {
    type Error = etherparse::err::tcp::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = TcpHeader::from_slice(buf).map_err(ParseError::FailedToParse)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl Parse for Udp {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = UdpHeader::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::LengthError(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl Parse for Icmp4 {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Icmpv4Header::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::LengthError(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl Parse for Icmp6 {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Icmpv6Header::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::LengthError(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

pub(crate) trait Step {
    type Next;
    fn step(&self, cursor: &mut Cursor) -> Option<Self::Next>;
}

pub(crate) trait StepWith {
    type Param;
    type Next;
    fn step_with(&self, param: &Self::Param, cursor: &mut Cursor) -> Option<Self::Next>;
}

pub enum EthNext {
    Vlan(Vlan),
    Ipv4(Ipv4),
    Ipv6(Ipv6),
}

fn parse_from_ethertype(ether_type: EtherType, cursor: &mut Cursor) -> Option<EthNext> {
    match ether_type {
        EtherType::IPV4 => cursor
            .parse::<Ipv4>()
            .map_err(|e| {
                debug!("failed to parse ipv4: {:?}", e);
            })
            .map(|(ipv4, _)| EthNext::Ipv4(ipv4))
            .ok(),
        EtherType::IPV6 => cursor
            .parse::<Ipv6>()
            .map_err(|e| {
                debug!("failed to parse ipv6: {:?}", e);
            })
            .map(|(ipv6, _)| EthNext::Ipv6(ipv6))
            .ok(),
        EtherType::VLAN_TAGGED_FRAME
        | EtherType::VLAN_DOUBLE_TAGGED_FRAME
        | EtherType::PROVIDER_BRIDGING => cursor
            .parse::<Vlan>()
            .map_err(|e| {
                debug!("failed to parse vlan: {:?}", e);
            })
            .map(|(vlan, _)| EthNext::Vlan(vlan))
            .ok(),
        _ => {
            trace!("unsupported ether type: {:?}", ether_type);
            None
        }
    }
}

impl Step for Eth {
    type Next = EthNext;
    fn step(&self, cursor: &mut Cursor) -> Option<EthNext> {
        parse_from_ethertype(self.inner.ether_type, cursor)
    }
}

impl Step for Vlan {
    type Next = EthNext;

    fn step(&self, cursor: &mut Cursor) -> Option<EthNext> {
        parse_from_ethertype(self.inner.ether_type, cursor)
    }
}

pub enum Ipv4Next {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    IpAuth(IpAuth),
}

impl Step for Ipv4 {
    type Next = Ipv4Next;

    fn step(&self, cursor: &mut Cursor) -> Option<Self::Next> {
        match self.inner.protocol {
            IpNumber::TCP => cursor
                .parse::<Tcp>()
                .map_err(|e| {
                    debug!("failed to parse tcp: {e:?}");
                })
                .map(|(val, _)| Ipv4Next::Tcp(val))
                .ok(),
            IpNumber::UDP => cursor
                .parse::<Udp>()
                .map_err(|e| {
                    debug!("failed to parse udp: {e:?}");
                })
                .map(|(val, _)| Ipv4Next::Udp(val))
                .ok(),
            IpNumber::ICMP => cursor
                .parse::<Icmp4>()
                .map_err(|e| {
                    debug!("failed to parse icmp4: {e:?}");
                })
                .map(|(val, _)| Ipv4Next::Icmp4(val))
                .ok(),
            IpNumber::AUTHENTICATION_HEADER => cursor
                .parse::<IpAuth>()
                .map_err(|e| {
                    debug!("failed to parse IpAuth: {e:?}");
                })
                .map(|(val, _)| Ipv4Next::IpAuth(val))
                .ok(),
            _ => {
                trace!("unsupported protocol: {:?}", self.inner.protocol);
                None
            }
        }
    }
}

pub enum Ipv6Next {
    Tcp(Tcp),
    Udp(Udp),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
    Ipv6Ext(Ipv6Ext),
}

impl Step for Ipv6 {
    type Next = Ipv6Next;

    fn step(&self, cursor: &mut Cursor) -> Option<Self::Next> {
        match self.inner.next_header {
            IpNumber::TCP => cursor
                .parse::<Tcp>()
                .map_err(|e| {
                    debug!("failed to parse tcp: {e:?}");
                })
                .map(|(val, _)| Ipv6Next::Tcp(val))
                .ok(),
            IpNumber::UDP => cursor
                .parse::<Udp>()
                .map_err(|e| {
                    debug!("failed to parse udp: {e:?}");
                })
                .map(|(val, _)| Ipv6Next::Udp(val))
                .ok(),
            IpNumber::ICMP => cursor
                .parse::<Icmp6>()
                .map_err(|e| {
                    debug!("failed to parse icmp4: {e:?}");
                })
                .map(|(val, _)| Ipv6Next::Icmp6(val))
                .ok(),
            IpNumber::AUTHENTICATION_HEADER => cursor
                .parse::<IpAuth>()
                .map_err(|e| {
                    debug!("failed to parse IpAuth: {e:?}");
                })
                .map(|(val, _)| Ipv6Next::IpAuth(val))
                .ok(),
            IpNumber::IPV6_HEADER_HOP_BY_HOP
            | IpNumber::IPV6_ROUTE_HEADER
            | IpNumber::IPV6_FRAGMENTATION_HEADER
            | IpNumber::IPV6_DESTINATION_OPTIONS => cursor
                .parse_with::<Ipv6Ext>(self.inner.next_header)
                .map_err(|e| {
                    debug!("failed to parse ipv6 extension header: {e:?}");
                })
                .map(|(val, _)| Self::Next::Ipv6Ext(val))
                .ok(),
            _ => {
                trace!("unsupported protocol: {:?}", self.inner.next_header);
                None
            }
        }
    }
}

pub enum IpAuthNext {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
}

impl Step for IpAuth {
    type Next = IpAuthNext;

    fn step(&self, cursor: &mut Cursor) -> Option<Self::Next> {
        match self.inner.next_header {
            IpNumber::TCP => cursor
                .parse::<Tcp>()
                .map_err(|e| {
                    debug!("failed to parse tcp: {e:?}");
                })
                .map(|(val, _)| Self::Next::Tcp(val))
                .ok(),
            IpNumber::UDP => cursor
                .parse::<Udp>()
                .map_err(|e| {
                    debug!("failed to parse udp: {e:?}");
                })
                .map(|(val, _)| Self::Next::Udp(val))
                .ok(),
            IpNumber::ICMP => cursor
                .parse::<Icmp4>()
                .map_err(|e| {
                    debug!("failed to parse icmp4: {e:?}");
                })
                .map(|(val, _)| Self::Next::Icmp4(val))
                .ok(),
            IpNumber::IPV6_ICMP => cursor
                .parse::<Icmp6>()
                .map_err(|e| {
                    debug!("failed to parse icmp6: {e:?}");
                })
                .map(|(val, _)| Self::Next::Icmp6(val))
                .ok(),
            IpNumber::AUTHENTICATION_HEADER => {
                debug!("nested ip auth header");
                cursor
                    .parse::<IpAuth>()
                    .map_err(|e| {
                        debug!("failed to parse ip auth header: {e:?}");
                    })
                    .map(|(val, _)| Self::Next::IpAuth(val))
                    .ok()
            }
            _ => {
                trace!("unsupported protocol: {:?}", self.inner.next_header);
                None
            }
        }
    }
}

pub enum Ipv6ExtNext {
    Tcp(Tcp),
    Udp(Udp),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
    Ipv6Ext(Ipv6Ext),
}

impl StepWith for Ipv6Ext {
    type Param = IpNumber;
    type Next = Ipv6ExtNext;

    fn step_with(&self, first_ip_number: &IpNumber, cursor: &mut Cursor) -> Option<Self::Next> {
        use etherparse::ip_number::{
            AUTHENTICATION_HEADER, IPV6_DESTINATION_OPTIONS, IPV6_FRAGMENTATION_HEADER,
            IPV6_HEADER_HOP_BY_HOP, IPV6_ICMP, IPV6_ROUTE_HEADER, TCP, UDP,
        };
        let next_header = self
            .inner
            .next_header(*first_ip_number)
            .map_err(|e| debug!("failed to parse: {e:?}"))
            .ok()?;
        match next_header {
            TCP => cursor
                .parse::<Tcp>()
                .map_err(|e| {
                    debug!("failed to parse tcp: {e:?}");
                })
                .map(|(val, _)| Self::Next::Tcp(val))
                .ok(),
            UDP => cursor
                .parse::<Udp>()
                .map_err(|e| {
                    debug!("failed to parse udp: {e:?}");
                })
                .map(|(val, _)| Self::Next::Udp(val))
                .ok(),
            IPV6_ICMP => cursor
                .parse::<Icmp6>()
                .map_err(|e| {
                    debug!("failed to parse icmp4: {e:?}");
                })
                .map(|(val, _)| Self::Next::Icmp6(val))
                .ok(),
            AUTHENTICATION_HEADER => {
                debug!("nested ip auth header");
                cursor
                    .parse::<IpAuth>()
                    .map_err(|e| {
                        debug!("failed to parse ip auth header: {e:?}");
                    })
                    .map(|(val, _)| Self::Next::IpAuth(val))
                    .ok()
            }
            IPV6_HEADER_HOP_BY_HOP
            | IPV6_ROUTE_HEADER
            | IPV6_FRAGMENTATION_HEADER
            | IPV6_DESTINATION_OPTIONS => cursor
                .parse_with::<Ipv6Ext>(next_header)
                .map_err(|e| {
                    debug!("failed to parse ipv6 extension header: {e:?}");
                })
                .map(|(val, _)| Self::Next::Ipv6Ext(val))
                .ok(),
            _ => {
                trace!("unsupported protocol: {next_header:?}");
                None
            }
        }
    }
}

impl From<EthNext> for Header {
    fn from(value: EthNext) -> Self {
        match value {
            EthNext::Vlan(x) => Header::Vlan(x),
            EthNext::Ipv4(x) => Header::Ipv4(x),
            EthNext::Ipv6(x) => Header::Ipv6(x),
        }
    }
}

impl From<Ipv4Next> for Header {
    fn from(value: Ipv4Next) -> Self {
        match value {
            Ipv4Next::Tcp(x) => Header::Tcp(x),
            Ipv4Next::Udp(x) => Header::Udp(x),
            Ipv4Next::Icmp4(x) => Header::Icmp4(x),
            Ipv4Next::IpAuth(x) => Header::IpAuth(x),
        }
    }
}

impl From<Ipv6Next> for Header {
    fn from(value: Ipv6Next) -> Self {
        match value {
            Ipv6Next::Tcp(x) => Header::Tcp(x),
            Ipv6Next::Udp(x) => Header::Udp(x),
            Ipv6Next::Icmp6(x) => Header::Icmp6(x),
            Ipv6Next::IpAuth(x) => Header::IpAuth(x),
            Ipv6Next::Ipv6Ext(x) => Header::IpV6Ext(x),
        }
    }
}

impl From<IpAuthNext> for Header {
    fn from(value: IpAuthNext) -> Self {
        match value {
            IpAuthNext::Tcp(x) => Header::Tcp(x),
            IpAuthNext::Udp(x) => Header::Udp(x),
            IpAuthNext::Icmp4(x) => Header::Icmp4(x),
            IpAuthNext::Icmp6(x) => Header::Icmp6(x),
            IpAuthNext::IpAuth(x) => Header::IpAuth(x),
        }
    }
}

impl From<Ipv6ExtNext> for Header {
    fn from(value: Ipv6ExtNext) -> Self {
        match value {
            Ipv6ExtNext::Tcp(x) => Header::Tcp(x),
            Ipv6ExtNext::Udp(x) => Header::Udp(x),
            Ipv6ExtNext::Icmp6(x) => Header::Icmp6(x),
            Ipv6ExtNext::IpAuth(x) => Header::IpAuth(x),
            Ipv6ExtNext::Ipv6Ext(x) => Header::IpV6Ext(x),
        }
    }
}

impl Step for Header {
    type Next = Header;

    fn step(&self, cursor: &mut Cursor) -> Option<Self::Next> {
        use Header::{Eth, Icmp4, Icmp6, IpAuth, IpV6Ext, Ipv4, Ipv6, Tcp, Udp, Vlan};
        match self {
            Eth(eth) => eth.step(cursor).map(Header::from),
            Vlan(vlan) => vlan.step(cursor).map(Header::from),
            Ipv4(ipv4) => ipv4.step(cursor).map(Header::from),
            Ipv6(ipv6) => ipv6.step(cursor).map(Header::from),
            IpAuth(auth) => auth.step(cursor).map(Header::from),
            IpV6Ext(ext) => {
                if let Ipv6(ipv6) = self {
                    ext.step_with(&ipv6.inner.next_header, cursor)
                        .map(Header::from)
                } else {
                    debug!("ipv6 extension header outside ipv6 packet");
                    None
                }
            }
            Tcp(_) | Udp(_) | Icmp4(_) | Icmp6(_) => None,
        }
    }
}

impl Eth {
    pub fn new(source: MacAddress, destination: MacAddress, ether_type: EtherType) -> Eth {
        Eth {
            inner: Ethernet2Header {
                source: source.0,
                destination: destination.0,
                ether_type,
            },
        }
    }

    pub fn source(&self) -> MacAddress {
        MacAddress(self.inner.source)
    }

    pub fn destination(&self) -> MacAddress {
        MacAddress(self.inner.destination)
    }

    pub fn ether_type(&self) -> EtherType {
        self.inner.ether_type
    }

    pub fn set_source(&mut self, source: MacAddress) -> Result<&mut Eth, SourceMacAddressError> {
        if source.is_zero() {
            return Err(SourceMacAddressError::ZeroSource);
        }
        if source.is_multicast() {
            return Err(SourceMacAddressError::MulticastSource);
        }
        Ok(self.set_source_unchecked(source))
    }

    pub fn set_destination(
        &mut self,
        destination: MacAddress,
    ) -> Result<&mut Eth, DestinationMacAddressError> {
        if destination.is_zero() {
            return Err(DestinationMacAddressError::ZeroDestination);
        }
        Ok(self.set_destination_unchecked(destination))
    }

    pub fn set_source_unchecked(&mut self, source: MacAddress) -> &mut Eth {
        debug_assert!(!source.is_valid_src());
        self.inner.source = source.0;
        self
    }

    pub fn set_destination_unchecked(&mut self, destination: MacAddress) -> &mut Eth {
        debug_assert!(!destination.is_valid_dst());
        self.inner.destination = destination.0;
        self
    }

    pub fn set_ether_type(&mut self, ether_type: EtherType) -> &mut Eth {
        self.inner.ether_type = ether_type;
        self
    }
}

impl Vlan {
    pub fn new(vid: Vid, ether_type: EtherType) -> Vlan {
        Vlan {
            inner: SingleVlanHeader {
                pcp: VlanPcp::ZERO,
                drop_eligible_indicator: false,
                #[allow(unsafe_code)] // SAFETY: overlapping check between libraries.
                vlan_id: unsafe { VlanId::new_unchecked(vid.to_u16()) },
                ether_type,
            },
        }
    }

    pub fn vid(&self) -> Result<Vid, InvalidVid> {
        Vid::new(self.inner.vlan_id.value())
    }

    /// Get the vlan id without ensuring it is a valid [`Vid`].
    ///
    /// # Safety
    ///
    /// This function does not ensure that the [`Vid`] is greater than zero or less than 4095.
    /// Avoid using this method on untrusted data.
    #[allow(unsafe_code)] // explicitly unsafe
    pub unsafe fn vid_unchecked(&self) -> Vid {
        Vid::new_unchecked(self.inner.vlan_id.value())
    }
}

impl Ipv4 {
    /// TODO: this is a temporary function.  Don't merge while this silly thing still exists.
    pub fn new() -> Ipv4 {
        Ipv4 {
            inner: Ipv4Header {
                dscp: Ipv4Dscp::default(),
                ecn: Ipv4Ecn::default(),
                total_len: 0,
                identification: 0,
                dont_fragment: false,
                more_fragments: false,
                fragment_offset: IpFragOffset::default(),
                time_to_live: 64,
                protocol: IpNumber::TCP,
                header_checksum: 27365,
                source: [1, 2, 3, 4],
                destination: [5, 6, 7, 8],
                options: Ipv4Options::default(),
            },
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
pub mod test {
    use tracing_test::traced_test;
    use super::*;
    use crate::packet::Packet;

    #[test]
    #[traced_test]
    fn check_serialize() {
        let eth = Eth::new(
            MacAddress([1, 2, 3, 4, 5, 6]),
            MacAddress([6, 5, 4, 3, 2, 1]),
            EtherType::VLAN_TAGGED_FRAME,
        );
        let vlan = [
            Vlan::new(Vid::new(17).unwrap(), EtherType::VLAN_TAGGED_FRAME),
            Vlan::new(Vid::new(27).unwrap(), EtherType::VLAN_TAGGED_FRAME),
            Vlan::new(Vid::new(2).unwrap(), EtherType::IPV4),
        ];
        let ipv4 = Ipv4::new();
        let mut buffer = [0_u8; 128];
        {
            let mut cursor = std::io::Cursor::new(&mut buffer[..]);
            eth.inner.write(&mut cursor).unwrap();
            vlan[0].inner.write(&mut cursor).unwrap();
            vlan[1].inner.write(&mut cursor).unwrap();
            vlan[2].inner.write(&mut cursor).unwrap();
            ipv4.inner.write(&mut cursor).unwrap();
        }
        let (packet, _) = Packet::parse(&buffer).unwrap();
        let mut buffer2 = [0_u8; 128];
        {
            let mut cursor = Cursor::new(&buffer2[..]);
            cursor.write(&eth).unwrap();
            cursor.write(&vlan[0]).unwrap();
            cursor.write(&vlan[1]).unwrap();
            cursor.write(&vlan[2]).unwrap();
            cursor.write(&ipv4).unwrap();
        }
        let mut cursor = Cursor::new(&buffer2[..]);
        let (packet2, size) = cursor.parse::<Packet>().unwrap();
        assert_eq!(packet, packet2);
        debug!("size: {size}");
        debug!("sizeof vlan: {size}", size = size_of::<Vlan>());
        debug!("sizeof packet: {size}", size = size_of::<Packet>());
    }
}
