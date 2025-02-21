// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Definition of [`Headers`] and related methods and types.
#![allow(missing_docs, clippy::pedantic)] // temporary

use crate::eth::ethtype::EthType;
use crate::eth::{Eth, EthError};
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::ip_auth::IpAuth;
use crate::ipv4::Ipv4;
use crate::ipv6::{Ipv6, Ipv6Ext};
use crate::parse::{
    DeParse, DeParseError, IllegalBufferLength, IntoNonZeroUSize, LengthError, Parse, ParseError,
    ParsePayload, ParsePayloadWith, Reader, Writer,
};
use crate::tcp::Tcp;
use crate::udp::{Udp, UdpEncap};
use crate::vlan::{Pcp, Vid, Vlan};
use crate::vxlan::Vxlan;
use arrayvec::ArrayVec;
use core::fmt::Debug;
use std::num::NonZero;
use tracing::debug;

const MAX_VLANS: usize = 4;
const MAX_NET_EXTENSIONS: usize = 2;

// TODO: remove `pub` from all fields
#[derive(Debug)]
pub struct Headers {
    pub eth: Eth,
    pub vlan: ArrayVec<Vlan, MAX_VLANS>,
    pub net: Option<Net>,
    pub net_ext: ArrayVec<NetExt, MAX_NET_EXTENSIONS>,
    pub transport: Option<Transport>,
    pub udp_encap: Option<UdpEncap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Net {
    Ipv4(Ipv4),
    Ipv6(Ipv6),
}

impl DeParse for Net {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            Net::Ipv4(ip) => ip.size(),
            Net::Ipv6(ip) => ip.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            Net::Ipv4(ip) => ip.deparse(buf),
            Net::Ipv6(ip) => ip.deparse(buf),
        }
    }
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

impl DeParse for Transport {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            Transport::Tcp(x) => x.size(),
            Transport::Udp(x) => x.size(),
            Transport::Icmp4(x) => x.size(),
            Transport::Icmp6(x) => x.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            Transport::Tcp(x) => x.deparse(buf),
            Transport::Udp(x) => x.deparse(buf),
            Transport::Icmp4(x) => x.deparse(buf),
            Transport::Icmp6(x) => x.deparse(buf),
        }
    }
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
    Encap(UdpEncap),
}

impl ParsePayload for Header {
    type Next = Header;

    fn parse_payload(&self, cursor: &mut Reader) -> Option<Header> {
        use Header::{Encap, Eth, Icmp4, Icmp6, IpAuth, IpV6Ext, Ipv4, Ipv6, Tcp, Udp, Vlan};
        match self {
            Eth(eth) => eth.parse_payload(cursor).map(Header::from),
            Vlan(vlan) => vlan.parse_payload(cursor).map(Header::from),
            Ipv4(ipv4) => ipv4.parse_payload(cursor).map(Header::from),
            Ipv6(ipv6) => ipv6.parse_payload(cursor).map(Header::from),
            IpAuth(auth) => auth.parse_payload(cursor).map(Header::from),
            IpV6Ext(ext) => {
                if let Ipv6(ipv6) = self {
                    ext.parse_payload_with(&ipv6.next_header(), cursor)
                        .map(Header::from)
                } else {
                    debug!("ipv6 extension header outside ipv6 header");
                    None
                }
            }
            Udp(udp) => udp.parse_payload(cursor).map(Header::from),
            Encap(_) | Tcp(_) | Icmp4(_) | Icmp6(_) => None,
        }
    }
}

impl Parse for Headers {
    type Error = EthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let mut cursor =
            Reader::new(buf).map_err(|IllegalBufferLength(len)| ParseError::BufferTooLong(len))?;
        let (eth, _) = cursor.parse::<Eth>()?;
        let mut this = Headers {
            eth: eth.clone(),
            net: None,
            transport: None,
            vlan: ArrayVec::default(),
            net_ext: ArrayVec::default(),
            udp_encap: None,
        };
        let mut prior = Header::Eth(eth);
        loop {
            let header = prior.parse_payload(&mut cursor);
            match prior {
                Header::Eth(eth) => this.eth = eth,
                Header::Ipv4(ip) => this.net = Some(Net::Ipv4(ip)),
                Header::Ipv6(ip) => this.net = Some(Net::Ipv6(ip)),
                Header::Tcp(tcp) => this.transport = Some(Transport::Tcp(tcp)),
                Header::Udp(udp) => this.transport = Some(Transport::Udp(udp)),
                Header::Icmp4(icmp4) => this.transport = Some(Transport::Icmp4(icmp4)),
                Header::Icmp6(icmp6) => this.transport = Some(Transport::Icmp6(icmp6)),
                Header::Encap(encap) => this.udp_encap = Some(encap),
                Header::Vlan(vlan) => {
                    if this.vlan.len() < MAX_VLANS {
                        this.vlan.push(vlan);
                    } else {
                        break;
                    }
                }
                Header::IpAuth(auth) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::IpAuth(auth));
                    } else {
                        break;
                    }
                }
                Header::IpV6Ext(ext) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::Ipv6Ext(ext));
                    } else {
                        break;
                    }
                }
            }
            match header {
                None => {
                    break;
                }
                Some(next) => {
                    prior = next;
                }
            }
        }
        #[allow(unsafe_code, clippy::cast_possible_truncation)] // Non zero checked by parse impl
        let consumed = unsafe {
            NonZero::new_unchecked((cursor.inner.len() - cursor.remaining as usize) as u16)
        };
        Ok((this, consumed))
    }
}

impl DeParse for Headers {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        // TODO(blocking): Deal with ip{v4,v6} extensions
        let eth = self.eth.size().get();
        let vlan = self.vlan.iter().map(|v| v.size().get()).sum::<u16>();
        let net = match self.net {
            None => {
                debug_assert!(self.transport.is_none());
                0
            }
            Some(ref n) => n.size().get(),
        };
        let transport = match self.transport {
            None => 0,
            Some(ref t) => t.size().get(),
        };
        let encap = match self.udp_encap {
            None => 0,
            Some(UdpEncap::Vxlan(vxlan)) => vxlan.size().get(),
        };
        NonZero::new(eth + vlan + net + transport + encap).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        // TODO(blocking): Deal with ip{v4,v6} extensions
        let len = buf.len();
        if len < self.size().into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        let mut cursor = Writer::new(buf)
            .map_err(|IllegalBufferLength(len)| DeParseError::BufferTooLong(len))?;
        cursor.write(&self.eth)?;
        for vlan in self.vlan.iter().rev() {
            cursor.write(vlan)?;
        }
        match self.net {
            None => {
                debug_assert!(self.transport.is_none());
                #[allow(clippy::cast_possible_truncation)] // length bounded on cursor creation
                return Ok(
                    NonZero::new((cursor.inner.len() - cursor.remaining as usize) as u16)
                        .unwrap_or_else(|| unreachable!()),
                );
            }
            Some(ref net) => {
                cursor.write(net)?;
            }
        }

        match self.transport {
            None => {
                #[allow(clippy::cast_possible_truncation)] // length bounded on cursor creation
                return Ok(
                    NonZero::new((cursor.inner.len() - cursor.remaining as usize) as u16)
                        .unwrap_or_else(|| unreachable!()),
                );
            }
            Some(ref transport) => {
                cursor.write(transport)?;
            }
        }

        match self.udp_encap {
            None => {
                #[allow(clippy::cast_possible_truncation)] // length bounded on cursor creation
                return Ok(
                    NonZero::new((cursor.inner.len() - cursor.remaining as usize) as u16)
                        .unwrap_or_else(|| unreachable!()),
                );
            }
            Some(UdpEncap::Vxlan(ref vxlan)) => {
                cursor.write(vxlan)?;
            }
        }
        #[allow(clippy::cast_possible_truncation)] // length bounded on cursor creation
        Ok(
            NonZero::new((cursor.inner.len() - cursor.remaining as usize) as u16)
                .unwrap_or_else(|| unreachable!()),
        )
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Header already has as many VLAN headers as parser can support (max is {MAX_VLANS})")]
pub struct TooManyVlans;

impl Headers {
    /// Create a new [`Headers`] with the supplied `Eth` header.
    pub fn new(eth: Eth) -> Headers {
        Headers {
            eth,
            vlan: ArrayVec::default(),
            net: None,
            net_ext: ArrayVec::default(),
            transport: None,
            udp_encap: None,
        }
    }

    /// Push a VLAN header to the top of the stack.
    ///
    /// # Errors:
    ///
    /// Will return a [`TooManyVlans`] error if there are already more VLANs in the stack than are
    /// supported in this configuration of the parser.
    /// See [`MAX_VLANS`].
    ///
    /// # Safety:
    ///
    /// This method will create an invalid [`Headers`] if the header you push has an _inner_ ethtype
    /// which does not align with the next header below it.
    ///
    /// This method will create an invalid [`Headers`] if the _outer_ ethtype (i.e., the ethtype of
    /// the [`Eth`] header or prior [`Vlan`] in the stack) is not some flavor of `Vlan` ethtype
    /// (e.g. [`EthType::VLAN`] or [`EthType::VLAN_QINQ`])
    #[allow(unsafe_code)]
    #[allow(dead_code)]
    unsafe fn push_vlan_header_unchecked(&mut self, vlan: Vlan) -> Result<(), TooManyVlans> {
        if self.vlan.len() < MAX_VLANS {
            self.vlan.push(vlan);
            Ok(())
        } else {
            Err(TooManyVlans)
        }
    }

    /// Push a vlan header onto the VLAN stack of this [`Headers`].
    ///
    /// This method will ensure that the `eth` field has its [`EthType`] adjusted to
    /// [`EthType::VLAN`] if there are no [`Vlan`]s on the stack at the time this method was called.
    pub fn push_vlan(&mut self, vid: Vid) -> Result<(), TooManyVlans> {
        if self.vlan.len() >= MAX_VLANS {
            return Err(TooManyVlans);
        }
        let old_eth_type = self.eth.ether_type();
        self.eth.set_ether_type(EthType::VLAN);
        let new_vlan_header = Vlan::new(vid, old_eth_type, Pcp::default(), false);
        self.vlan.push(new_vlan_header);
        Ok(())
    }

    /// Pop a vlan header from the stack.
    ///
    /// Returns [`None`] if no [`Vlan`]s are on the stack.
    ///
    /// If `Some` is returned, the popped [`Vlan`]s ethtype is assigned to the `eth` header to
    /// preserve structure.
    ///
    /// If `None` is returned, the [`Headers`] is not modified.
    pub fn pop_vlan(&mut self) -> Option<Vlan> {
        match self.vlan.pop() {
            None => None,
            Some(vlan) => {
                self.eth.set_ether_type(vlan.inner_ethtype());
                Some(vlan)
            }
        }
    }
}

// Eth traits

pub trait WithEth {
    fn eth(&self) -> &Eth;
}

pub trait WithEthMut {
    fn eth_mut(&mut self) -> &mut Eth;
}

pub trait TryEth {
    fn try_eth(&self) -> Option<&Eth>;
}

pub trait TryEthMut {
    fn try_eth_mut(&mut self) -> Option<&mut Eth>;
}

impl WithEth for Headers {
    fn eth(&self) -> &Eth {
        &self.eth
    }
}

impl WithEthMut for Headers {
    fn eth_mut(&mut self) -> &mut Eth {
        &mut self.eth
    }
}

impl TryEth for Headers {
    fn try_eth(&self) -> Option<&Eth> {
        Some(self.eth())
    }
}

impl TryEthMut for Headers {
    fn try_eth_mut(&mut self) -> Option<&mut Eth> {
        Some(self.eth_mut())
    }
}

// Ipv4 traits

pub trait WithIpv4 {
    fn ipv4(&self) -> &Ipv4;
}

pub trait WithIpv4Mut {
    fn ipv4_mut(&mut self) -> &mut Ipv4;
}

pub trait TryIpv4 {
    fn try_ipv4(&self) -> Option<&Ipv4>;
}

pub trait TryIpv4Mut {
    fn try_ipv4_mut(&mut self) -> Option<&mut Ipv4>;
}

impl TryIpv4 for Headers {
    fn try_ipv4(&self) -> Option<&Ipv4> {
        match &self.net {
            Some(Net::Ipv4(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryIpv4Mut for Headers {
    fn try_ipv4_mut(&mut self) -> Option<&mut Ipv4> {
        match &mut self.net {
            Some(Net::Ipv4(header)) => Some(header),
            _ => None,
        }
    }
}

// Ipv6 traits

pub trait WithIpv6 {
    fn ipv6(&self) -> &Ipv6;
}

pub trait WithIpv6Mut {
    fn ipv6_mut(&mut self) -> &mut Ipv6;
}

pub trait TryIpv6 {
    fn try_ipv6(&self) -> Option<&Ipv6>;
}

pub trait TryIpv6Mut {
    fn try_ipv6_mut(&mut self) -> Option<&mut Ipv6>;
}

impl TryIpv6 for Headers {
    fn try_ipv6(&self) -> Option<&Ipv6> {
        match &self.net {
            Some(Net::Ipv6(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryIpv6Mut for Headers {
    fn try_ipv6_mut(&mut self) -> Option<&mut Ipv6> {
        match &mut self.net {
            Some(Net::Ipv6(header)) => Some(header),
            _ => None,
        }
    }
}

// Tcp traits

pub trait WithTcp {
    fn tcp(&self) -> &Tcp;
}

pub trait WithTcpMut {
    fn tcp_mut(&mut self) -> &mut Tcp;
}

pub trait TryTcp {
    fn try_tcp(&self) -> Option<&Tcp>;
}

pub trait TryTcpMut {
    fn try_tcp_mut(&mut self) -> Option<&mut Tcp>;
}

impl TryTcp for Headers {
    fn try_tcp(&self) -> Option<&Tcp> {
        match &self.transport {
            Some(Transport::Tcp(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryTcpMut for Headers {
    fn try_tcp_mut(&mut self) -> Option<&mut Tcp> {
        match &mut self.transport {
            Some(Transport::Tcp(header)) => Some(header),
            _ => None,
        }
    }
}

// UDP traits

pub trait WithUdp {
    fn udp(&self) -> &Udp;
}

pub trait WithUdpMut {
    fn udp_mut(&mut self) -> &mut Udp;
}

pub trait TryUdp {
    fn try_udp(&self) -> Option<&Udp>;
}

pub trait TryUdpMut {
    fn try_udp_mut(&mut self) -> Option<&mut Udp>;
}

impl TryUdp for Headers {
    fn try_udp(&self) -> Option<&Udp> {
        match &self.transport {
            Some(Transport::Udp(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryUdpMut for Headers {
    fn try_udp_mut(&mut self) -> Option<&mut Udp> {
        match &mut self.transport {
            Some(Transport::Udp(header)) => Some(header),
            _ => None,
        }
    }
}

// Icmp traits

pub trait WithIcmp {
    fn icmp(&self) -> &Icmp4;
}

pub trait WithIcmpMut {
    fn icmp_mut(&mut self) -> &mut Icmp4;
}

pub trait TryIcmp {
    fn try_icmp(&self) -> Option<&Icmp4>;
}

pub trait TryIcmpMut {
    fn try_icmp_mut(&mut self) -> Option<&mut Icmp4>;
}

impl TryIcmp for Headers {
    fn try_icmp(&self) -> Option<&Icmp4> {
        match &self.transport {
            Some(Transport::Icmp4(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryIcmpMut for Headers {
    fn try_icmp_mut(&mut self) -> Option<&mut Icmp4> {
        match &mut self.transport {
            Some(Transport::Icmp4(header)) => Some(header),
            _ => None,
        }
    }
}

// ICMP6 traits

pub trait WithIcmp6 {
    fn icmp6(&self) -> &Icmp6;
}

pub trait WithIcmp6Mut {
    fn icmp6_mut(&mut self) -> &mut Icmp6;
}

pub trait TryIcmp6 {
    fn try_icmp6(&self) -> Option<&Icmp6>;
}

pub trait TryIcmp6Mut {
    fn try_icmp6_mut(&mut self) -> Option<&mut Icmp6>;
}

impl TryIcmp6 for Headers {
    fn try_icmp6(&self) -> Option<&Icmp6> {
        match &self.transport {
            Some(Transport::Icmp6(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryIcmp6Mut for Headers {
    fn try_icmp6_mut(&mut self) -> Option<&mut Icmp6> {
        match &mut self.transport {
            Some(Transport::Icmp6(header)) => Some(header),
            _ => None,
        }
    }
}

// Vxlan traits

pub trait WithVxlan {
    fn vxlan(&self) -> &Vxlan;
}

pub trait WithVxlanMut {
    fn vxlan_mut(&mut self) -> &mut Vxlan;
}

pub trait TryVxlan {
    fn try_vxlan(&self) -> Option<&Vxlan>;
}

pub trait TryVxlanMut {
    fn try_vxlan_mut(&mut self) -> Option<&mut Vxlan>;
}

impl TryVxlan for Headers {
    fn try_vxlan(&self) -> Option<&Vxlan> {
        match &self.udp_encap {
            Some(UdpEncap::Vxlan(vxlan)) => Some(vxlan),
            _ => None,
        }
    }
}

impl TryVxlanMut for Headers {
    fn try_vxlan_mut(&mut self) -> Option<&mut Vxlan> {
        match &mut self.udp_encap {
            Some(UdpEncap::Vxlan(vxlan)) => Some(vxlan),
            _ => None,
        }
    }
}

impl From<Eth> for Header {
    fn from(value: Eth) -> Self {
        Header::Eth(value)
    }
}

impl From<Vlan> for Header {
    fn from(value: Vlan) -> Self {
        Header::Vlan(value)
    }
}

impl From<Ipv4> for Header {
    fn from(value: Ipv4) -> Self {
        Header::Ipv4(value)
    }
}

impl From<Ipv6> for Header {
    fn from(value: Ipv6) -> Self {
        Header::Ipv6(value)
    }
}

impl From<Net> for Header {
    fn from(value: Net) -> Self {
        match value {
            Net::Ipv4(ip) => Header::from(ip),
            Net::Ipv6(ip) => Header::from(ip),
        }
    }
}

impl From<IpAuth> for Header {
    fn from(value: IpAuth) -> Self {
        Header::IpAuth(value)
    }
}

impl From<Ipv6Ext> for Header {
    fn from(value: Ipv6Ext) -> Self {
        Header::IpV6Ext(value)
    }
}

impl From<Udp> for Header {
    fn from(value: Udp) -> Self {
        Header::Udp(value)
    }
}

impl From<Tcp> for Header {
    fn from(value: Tcp) -> Self {
        Header::Tcp(value)
    }
}

impl From<Icmp4> for Header {
    fn from(value: Icmp4) -> Self {
        Header::Icmp4(value)
    }
}

impl From<Icmp6> for Header {
    fn from(value: Icmp6) -> Self {
        Header::Icmp6(value)
    }
}

impl From<Transport> for Header {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Tcp(x) => Header::from(x),
            Transport::Udp(x) => Header::from(x),
            Transport::Icmp4(x) => Header::from(x),
            Transport::Icmp6(x) => Header::from(x),
        }
    }
}

impl From<Vxlan> for Header {
    fn from(value: Vxlan) -> Self {
        Header::Encap(UdpEncap::Vxlan(value))
    }
}

impl From<UdpEncap> for Header {
    fn from(value: UdpEncap) -> Self {
        Header::Encap(value)
    }
}

pub trait AbstractHeaders:
    Debug + TryEth + TryIpv4 + TryIpv6 + TryTcp + TryUdp + TryIcmp + TryIcmp6 + TryVxlan
{
}

impl<T> AbstractHeaders for T where
    T: Debug + TryEth + TryIpv4 + TryIpv6 + TryTcp + TryUdp + TryIcmp + TryIcmp6 + TryVxlan
{
}

pub trait AbstractHeadersMut:
    TryEthMut + TryIpv4Mut + TryIpv6Mut + TryTcpMut + TryUdpMut + TryIcmpMut + TryIcmp6Mut + TryVxlanMut
{
}
impl<T> AbstractHeadersMut for T where
    T: TryEthMut
        + TryIpv4Mut
        + TryIpv6Mut
        + TryTcpMut
        + TryUdpMut
        + TryIcmpMut
        + TryIcmp6Mut
        + TryVxlanMut
{
}

pub trait TryHeaders {
    fn headers(&self) -> &impl AbstractHeaders;
}

pub trait TryHeadersMut {
    fn headers_mut(&mut self) -> &mut impl AbstractHeadersMut;
}

impl<T> TryEth for T
where
    T: TryHeaders,
{
    fn try_eth(&self) -> Option<&Eth> {
        self.headers().try_eth()
    }
}

impl<T> TryIpv4 for T
where
    T: TryHeaders,
{
    fn try_ipv4(&self) -> Option<&Ipv4> {
        self.headers().try_ipv4()
    }
}

impl<T> TryIpv6 for T
where
    T: TryHeaders,
{
    fn try_ipv6(&self) -> Option<&Ipv6> {
        self.headers().try_ipv6()
    }
}

impl<T> TryTcp for T
where
    T: TryHeaders,
{
    fn try_tcp(&self) -> Option<&Tcp> {
        self.headers().try_tcp()
    }
}

impl<T> TryUdp for T
where
    T: TryHeaders,
{
    fn try_udp(&self) -> Option<&Udp> {
        self.headers().try_udp()
    }
}

impl<T> TryIcmp for T
where
    T: TryHeaders,
{
    fn try_icmp(&self) -> Option<&Icmp4> {
        self.headers().try_icmp()
    }
}

impl<T> TryIcmp6 for T
where
    T: TryHeaders,
{
    fn try_icmp6(&self) -> Option<&Icmp6> {
        self.headers().try_icmp6()
    }
}

impl<T> TryVxlan for T
where
    T: TryHeaders,
{
    fn try_vxlan(&self) -> Option<&Vxlan> {
        self.headers().try_vxlan()
    }
}

impl<T> TryEthMut for T
where
    T: TryHeadersMut,
{
    fn try_eth_mut(&mut self) -> Option<&mut Eth> {
        self.headers_mut().try_eth_mut()
    }
}

impl<T> TryIpv4Mut for T
where
    T: TryHeadersMut,
{
    fn try_ipv4_mut(&mut self) -> Option<&mut Ipv4> {
        self.headers_mut().try_ipv4_mut()
    }
}

impl<T> TryIpv6Mut for T
where
    T: TryHeadersMut,
{
    fn try_ipv6_mut(&mut self) -> Option<&mut Ipv6> {
        self.headers_mut().try_ipv6_mut()
    }
}

impl<T> TryTcpMut for T
where
    T: TryHeadersMut,
{
    fn try_tcp_mut(&mut self) -> Option<&mut Tcp> {
        self.headers_mut().try_tcp_mut()
    }
}

impl<T> TryUdpMut for T
where
    T: TryHeadersMut,
{
    fn try_udp_mut(&mut self) -> Option<&mut Udp> {
        self.headers_mut().try_udp_mut()
    }
}

impl<T> TryIcmpMut for T
where
    T: TryHeadersMut,
{
    fn try_icmp_mut(&mut self) -> Option<&mut Icmp4> {
        self.headers_mut().try_icmp_mut()
    }
}

impl<T> TryIcmp6Mut for T
where
    T: TryHeadersMut,
{
    fn try_icmp6_mut(&mut self) -> Option<&mut Icmp6> {
        self.headers_mut().try_icmp6_mut()
    }
}

impl<T> TryVxlanMut for T
where
    T: TryHeadersMut,
{
    fn try_vxlan_mut(&mut self) -> Option<&mut Vxlan> {
        self.headers_mut().try_vxlan_mut()
    }
}
