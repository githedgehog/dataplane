// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! [LLDP][ieee8021ab] (Link Layer Discovery Protocol) types and parsing.
//!
//! LLDP is a one-hop announcement protocol: a station periodically emits a
//! frame describing itself and the port it emitted from, and neighbours cache
//! what they hear for as long as the sender's time to live allows.  The frame
//! is never forwarded and never acknowledged, so the whole protocol reduces to
//! building and reading one payload, the [`Lldpdu`].
//!
//! # Wire format
//!
//! An LLDPDU is a sequence of type-length-value records:
//!
//! ```text
//! +--------------+---------+-----+-----------+-----+---------------+
//! | chassis ID   | port ID | TTL | optional  | ... | end of LLDPDU |
//! +--------------+---------+-----+-----------+-----+---------------+
//! ```
//!
//! The first three records are mandatory and must appear in that order; the end
//! marker is mandatory and must come last.  [`Lldpdu`] holds the mandatory
//! records in named fields and emits the end marker itself, so those rules are
//! properties of the type rather than checks a caller has to remember.
//!
//! # Example
//!
//! ```
//! use dataplane_net::eth::mac::Mac;
//! use dataplane_net::lldp::{ChassisId, IdOctets, Lldpdu, PortId, TimeToLive};
//! use dataplane_net::parse::{DeParse, Parse};
//!
//! let pdu = Lldpdu::new(
//!     ChassisId::MacAddress(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])),
//!     PortId::InterfaceName(IdOctets::new(b"swp1")?),
//!     TimeToLive::new(120),
//! );
//!
//! let mut frame = vec![0u8; pdu.size().get() as usize];
//! pdu.deparse(&mut frame).expect("the buffer is exactly the right size");
//!
//! let (parsed, consumed) = Lldpdu::parse(&frame)?;
//! assert_eq!(parsed, pdu);
//! assert_eq!(consumed, pdu.size());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Scope
//!
//! Every TLV [IEEE Std 802.1AB][ieee8021ab] defines is modelled: the mandatory
//! three, the optional ones ([`OptionalTlv`]), and the IEEE 802.1 and IEEE
//! 802.3 extensions carried inside the organizationally specific TLV
//! ([`Dot1Tlv`], [`Dot3Tlv`]).  Within the 802.1 and 802.3 sets the subtypes
//! this dataplane has a use for are decoded and the rest are kept verbatim, as
//! is any TLV type or OUI the standard does not define.
//!
//! Nothing here is byte-lossy: a value parsed from a frame always deparses back
//! to the octets it came from, whether or not this library understands what
//! they mean.
//!
//! [ieee8021ab]: https://standards.ieee.org/ieee/802.1AB/6047/

mod address;
mod capabilities;
mod chassis_id;
mod management;
mod octets;
mod optional;
mod org;
mod pdu;
mod port_id;
mod tlv;
mod ttl;

pub use address::{
    AddressOctets, AmbiguousFamily, NetworkAddress, NetworkAddressError, OtherNetworkAddress,
};
pub use capabilities::{SystemCapabilities, SystemCapabilitiesError, SystemCapability};
pub use chassis_id::{
    ChassisId, ChassisIdError, ChassisIdSubtype, IdOctets, ReservedChassisIdSubtype,
};
pub use management::{
    AddressTooLong, InterfaceNumber, InterfaceNumbering, ManagementAddress, ManagementAddressError,
    ObjectIdentifier, ReservedInterfaceNumbering,
};
pub use octets::{Octets, OctetsError};
pub use optional::{OptionalTlv, OptionalTlvError, RecognizedTlvType, Text, UnrecognizedTlv};
pub use org::{
    Dot1Tlv, Dot3Tlv, LinkAggregationStatus, ModelledOrgTlv, OrgInfo, OrgTlvError,
    OrganizationallySpecific, Oui, VlanId, VlanNameOctets,
};
pub use pdu::{Lldpdu, LldpduError, LldpduTooLong};
pub use port_id::{PortId, PortIdError, PortIdSubtype, ReservedPortIdSubtype};
pub use tlv::{
    InvalidTlvType, RawTlv, TlvHeader, TlvType, TlvValue, TlvValueTooLong, UnexpectedTlvType,
};
pub use ttl::{EndOfLldpdu, EndOfLldpduError, TimeToLive, TimeToLiveError};

use crate::eth::ethtype::EthType;
use crate::eth::mac::Mac;

/// The [`EthType`] which identifies an LLDP frame.
pub const ETHTYPE: EthType = EthType::LLDP;

/// The group address which constrains an LLDPDU to the nearest bridge.
///
/// This is the address to use unless there is a specific reason not to: every
/// kind of bridge, including two-port MAC relays, terminates it.
pub const NEAREST_BRIDGE: Mac = Mac([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);

/// The group address which lets an LLDPDU pass through two-port MAC relays but
/// no other bridge.
pub const NEAREST_NON_TPMR_BRIDGE: Mac = Mac([0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);

/// The group address which lets an LLDPDU pass through provider bridges to the
/// nearest customer bridge.
pub const NEAREST_CUSTOMER_BRIDGE: Mac = Mac([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);

/// The group addresses an LLDP agent may send to, nearest first.
pub const GROUP_ADDRESSES: [Mac; 3] = [
    NEAREST_BRIDGE,
    NEAREST_NON_TPMR_BRIDGE,
    NEAREST_CUSTOMER_BRIDGE,
];

#[cfg(test)]
mod test {
    use super::{
        ChassisId, ETHTYPE, GROUP_ADDRESSES, IdOctets, Lldpdu, NEAREST_BRIDGE, OptionalTlv, PortId,
        Text, TimeToLive,
    };
    use crate::eth::Eth;
    use crate::eth::mac::{DestinationMac, Mac, SourceMac};
    use crate::headers::Headers;
    use crate::parse::{DeParse, Parse};

    #[test]
    fn ethtype_is_88cc() {
        assert_eq!(ETHTYPE.as_u16(), 0x88cc);
    }

    fn lldp_frame() -> (Eth, Lldpdu, Vec<u8>) {
        let eth = Eth::new(
            SourceMac::new(Mac([0x02, 0, 0, 0, 0, 1])).unwrap(),
            DestinationMac::new(NEAREST_BRIDGE).unwrap(),
            ETHTYPE,
        );
        let mut pdu = Lldpdu::new(
            ChassisId::MacAddress(Mac([0x02, 0, 0, 0, 0, 1])),
            PortId::InterfaceName(IdOctets::new(b"swp1").unwrap()),
            TimeToLive::new(120),
        );
        pdu.try_push(OptionalTlv::SystemName(Text::new(b"leaf-01").unwrap()))
            .unwrap();

        let mut frame = vec![0u8; (eth.size().get() + pdu.size().get()) as usize];
        let written = eth.deparse(&mut frame).unwrap();
        pdu.deparse(&mut frame[written.get() as usize..]).unwrap();
        (eth, pdu, frame)
    }

    /// The point of the [`Header`](crate::headers::Header) integration: a frame
    /// with ethertype 0x88cc comes out of the ordinary packet parser with its
    /// LLDPDU already decoded, so the punt path does not have to know how to
    /// find it.
    #[test]
    fn headers_parse_classifies_an_lldp_frame() {
        let (eth, pdu, frame) = lldp_frame();
        let (headers, consumed) = Headers::parse(&frame).unwrap();

        assert_eq!(headers.eth(), Some(&eth));
        assert_eq!(headers.lldp(), Some(&pdu));
        assert!(
            headers.net().is_none(),
            "LLDP frames carry no network header"
        );
        assert_eq!(consumed.get() as usize, frame.len());
        assert_eq!(headers.size(), consumed);
    }

    #[test]
    fn an_lldp_frame_round_trips_through_headers() {
        let (_, _, frame) = lldp_frame();
        let (headers, _) = Headers::parse(&frame).unwrap();
        let mut written = vec![0u8; headers.size().get() as usize];
        headers.deparse(&mut written).unwrap();
        assert_eq!(written, frame);
    }

    /// Ethernet pads short frames, and an LLDP frame is usually short.  The
    /// padding must not be mistaken for more LLDPDU.
    #[test]
    fn trailing_padding_is_not_consumed() {
        let (_, pdu, mut frame) = lldp_frame();
        let unpadded = frame.len();
        frame.resize(60, 0);
        let (headers, consumed) = Headers::parse(&frame).unwrap();
        assert_eq!(headers.lldp(), Some(&pdu));
        assert_eq!(consumed.get() as usize, unpadded);
    }

    /// A frame which claims to be LLDP but is not leaves the parser with the
    /// ethernet header and nothing else, rather than failing the whole parse.
    #[test]
    fn a_malformed_lldp_frame_stops_at_the_ethernet_header() {
        let (eth, _, mut frame) = lldp_frame();
        let eth_len = eth.size().get() as usize;
        frame[eth_len] = 0xff; // wreck the chassis ID TLV header
        let (headers, consumed) = Headers::parse(&frame).unwrap();
        assert_eq!(headers.eth(), Some(&eth));
        assert!(headers.lldp().is_none());
        assert_eq!(consumed.get() as usize, eth_len);
    }

    /// An LLDPDU is not a network header, so writing one alongside a network
    /// header would produce a frame that could never be parsed back.
    #[test]
    fn deparse_refuses_lldp_alongside_a_network_header() {
        let (_, _, frame) = lldp_frame();
        let (lldp_headers, _) = Headers::parse(&frame).unwrap();

        // Graft the LLDPDU onto a routable packet's headers, which the parser
        // could never have produced.
        bolero::check!()
            .with_generator(crate::headers::CommonHeaders)
            .for_each(|routable: &Headers| {
                let mut headers = routable.clone();
                if headers.net().is_none() {
                    return;
                }
                headers.lldp = lldp_headers.lldp.clone();
                let mut buf = vec![0u8; headers.size().get() as usize];
                assert!(
                    headers.deparse(&mut buf).is_err(),
                    "an LLDPDU alongside a network header must not serialize"
                );
            });
    }

    #[test]
    fn group_addresses_are_multicast() {
        for address in GROUP_ADDRESSES {
            assert!(address.is_multicast(), "{address} is not multicast");
        }
        assert_eq!(GROUP_ADDRESSES[0], NEAREST_BRIDGE);
    }
}
