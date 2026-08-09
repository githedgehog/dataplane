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
    use super::{ETHTYPE, GROUP_ADDRESSES, NEAREST_BRIDGE};

    #[test]
    fn ethtype_is_88cc() {
        assert_eq!(ETHTYPE.as_u16(), 0x88cc);
    }

    #[test]
    fn group_addresses_are_multicast() {
        for address in GROUP_ADDRESSES {
            assert!(address.is_multicast(), "{address} is not multicast");
        }
        assert_eq!(GROUP_ADDRESSES[0], NEAREST_BRIDGE);
    }
}
