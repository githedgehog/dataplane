// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared parsing dispatch for IPv6 extension header payloads.
//!
//! Every extension header carries a `next_header` field that identifies
//! the type following it.  The dispatch logic is the same for all of
//! `HopByHop`, `DestOpts`, `Routing`, `Fragment`, and `Ipv6Auth`.

use crate::headers::Header;
use crate::icmp6::Icmp6;
use crate::ip::NextHeader;
use crate::ip_auth::Ipv6Auth;
use crate::ipv6::dest_opts::DestOpts;
use crate::ipv6::fragment::Fragment;
use crate::ipv6::hop_by_hop::HopByHop;
use crate::ipv6::routing::Routing;
use crate::parse::{ParseHeader, Reader};
use crate::tcp::Tcp;
use crate::udp::Udp;
use etherparse::IpNumber;
use tracing::trace;

/// Dispatch the next header after an IPv6 extension header.
///
/// This is called by the `parse_payload` method on each extension header
/// type.  The `nh` parameter is the extension header's `next_header` field.
pub(crate) fn parse_ext_payload(nh: NextHeader, cursor: &mut Reader) -> Option<Header> {
    match nh.to_ip_number() {
        IpNumber::TCP => cursor.parse_header::<Tcp, Header>(),
        IpNumber::UDP => cursor.parse_header::<Udp, Header>(),
        IpNumber::IPV6_ICMP => cursor.parse_header::<Icmp6, Header>(),
        IpNumber::AUTHENTICATION_HEADER => cursor.parse_header::<Ipv6Auth, Header>(),
        IpNumber::IPV6_HEADER_HOP_BY_HOP => cursor.parse_header::<HopByHop, Header>(),
        IpNumber::IPV6_ROUTE_HEADER => cursor.parse_header::<Routing, Header>(),
        IpNumber::IPV6_FRAGMENTATION_HEADER => cursor.parse_header::<Fragment, Header>(),
        IpNumber::IPV6_DESTINATION_OPTIONS => cursor.parse_header::<DestOpts, Header>(),
        _ => {
            trace!("unsupported protocol: {:?}", nh);
            None
        }
    }
}

/// Embedded-payload variant for ICMP error messages.
pub(crate) fn parse_ext_embedded_payload(
    nh: NextHeader,
    cursor: &mut Reader,
) -> Option<crate::headers::EmbeddedHeader> {
    use crate::headers::EmbeddedHeader;
    use crate::icmp6::TruncatedIcmp6;
    use crate::tcp::TruncatedTcp;
    use crate::udp::TruncatedUdp;

    match nh.to_ip_number() {
        IpNumber::TCP => cursor.parse_header::<TruncatedTcp, EmbeddedHeader>(),
        IpNumber::UDP => cursor.parse_header::<TruncatedUdp, EmbeddedHeader>(),
        IpNumber::IPV6_ICMP => cursor.parse_header::<TruncatedIcmp6, EmbeddedHeader>(),
        IpNumber::AUTHENTICATION_HEADER => cursor.parse_header::<Ipv6Auth, EmbeddedHeader>(),
        IpNumber::IPV6_HEADER_HOP_BY_HOP => cursor.parse_header::<HopByHop, EmbeddedHeader>(),
        IpNumber::IPV6_ROUTE_HEADER => cursor.parse_header::<Routing, EmbeddedHeader>(),
        IpNumber::IPV6_FRAGMENTATION_HEADER => cursor.parse_header::<Fragment, EmbeddedHeader>(),
        IpNumber::IPV6_DESTINATION_OPTIONS => cursor.parse_header::<DestOpts, EmbeddedHeader>(),
        _ => {
            trace!("unsupported protocol: {:?}", nh);
            None
        }
    }
}
