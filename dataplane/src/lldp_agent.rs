// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Advertise this gateway with LLDP on every port.
//!
//! The dataplane owns its NICs, so nothing else can speak LLDP for them. Each port gets two tasks:
//! one composes what the port advertises from what the dataplane knows, and one ([`lldp::transmit`])
//! sends it on schedule through the port's control-plane injection queue.
//!
//! What each port advertises:
//!
//! | TLV | Value |
//! |---|---|
//! | Chassis ID | locally assigned: the gateway's name from its k8s config |
//! | Port ID | interface name: the name the port was configured with |
//! | Port Description | the device behind the port: bus address and driver |
//! | System Name | the gateway's name |
//! | System Description | this dataplane and its version |
//! | System Capabilities | router, enabled |
//! | Management Address | the host's address (see [`management_address`]) |
//! | 802.3 Maximum Frame Size | the port's MTU plus Ethernet header and FCS |
//!
//! Nothing is advertised until a config has named the gateway: the chassis ID must not change while
//! neighbours are listening, and the k8s name is the only one a person will recognise.

use crate::drivers::cpbridge::{BridgePort, PortIdentity};
use lifecycle::Subsystem;
use lldp::{Advertisement, Inputs, Timing, transmit};
use net::interface::InterfaceName;
use net::lldp::{
    ChassisId, Dot3Tlv, IdOctets, InterfaceNumber, InterfaceNumbering, ManagementAddress,
    NetworkAddress, ObjectIdentifier, OptionalTlv, OrganizationallySpecific, PortId,
    SystemCapabilities, SystemCapability, Text,
};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, warn};

/// What every port says this system is.
const SYSTEM_DESCRIPTION: &str = concat!("Hedgehog gateway dataplane ", env!("CARGO_PKG_VERSION"));

/// Octets an Ethernet frame adds around its payload: the header and the frame check sequence.
const ETHERNET_OVERHEAD: u16 = 14 + 4;

/// Start advertising on every port in `ports`.
pub(crate) fn start(
    handle: &tokio::runtime::Handle,
    mgmt: &Subsystem,
    ports: &[BridgePort],
    gateway_name: &watch::Receiver<Option<String>>,
    management: &watch::Receiver<Option<IpAddr>>,
) {
    for port in ports {
        let (advertisement, advertised) = watch::channel(None);
        mgmt.spawn_on(
            compose(
                port.name.clone(),
                port.identity.clone(),
                gateway_name.clone(),
                management.clone(),
                advertisement,
                mgmt.cancel_token(),
            ),
            handle,
        );
        mgmt.spawn_on(
            transmit(
                Inputs {
                    link: port.link.clone(),
                    advertisement: advertised,
                    sink: port.inject.clone(),
                    timing: Timing::default(),
                },
                mgmt.cancel_token(),
            ),
            handle,
        );
    }
    debug!("LLDP: advertising on {} port(s)", ports.len());
}

/// Keep one port's advertisement current until cancelled or an input goes away.
///
/// Returning drops `advertisement`, which tells the transmitter to retract it.
async fn compose(
    port: InterfaceName,
    mut identity: watch::Receiver<Option<PortIdentity>>,
    mut gateway_name: watch::Receiver<Option<String>>,
    mut management: watch::Receiver<Option<IpAddr>>,
    advertisement: watch::Sender<Option<Advertisement>>,
    cancel: lifecycle::CancellationToken,
) {
    loop {
        let now = advertise(
            &port,
            identity.borrow_and_update().as_ref(),
            gateway_name.borrow_and_update().as_deref(),
            *management.borrow_and_update(),
        );
        advertisement.send_if_modified(|current| {
            if *current == now {
                return false;
            }
            *current = now;
            true
        });
        let changed = tokio::select! {
            () = cancel.cancelled() => return,
            changed = identity.changed() => changed,
            changed = gateway_name.changed() => changed,
            changed = management.changed() => changed,
        };
        if changed.is_err() {
            return;
        }
    }
}

/// What `port` advertises, or `None` if there is not yet enough to say.
fn advertise(
    port: &InterfaceName,
    identity: Option<&PortIdentity>,
    gateway_name: Option<&str>,
    management: Option<IpAddr>,
) -> Option<Advertisement> {
    let identity = identity?;
    let gateway_name = gateway_name?;
    let Ok(chassis) = IdOctets::new(gateway_name.as_bytes()) else {
        warn!(
            "LLDP: the gateway name {gateway_name:?} is too long for a chassis ID; not advertising"
        );
        return None;
    };
    let Ok(port_id) = IdOctets::new(port.to_string().as_bytes()) else {
        unreachable!("an interface name is a valid port ID");
    };
    let source = identity.mac;

    let mut optional = vec![
        OptionalTlv::PortDescription(text(
            identity.hardware.as_deref().unwrap_or("unknown device"),
        )),
        OptionalTlv::SystemName(text(gateway_name)),
        OptionalTlv::SystemDescription(text(SYSTEM_DESCRIPTION)),
        OptionalTlv::SystemCapabilities(SystemCapabilities::new(
            SystemCapability::ROUTER,
            SystemCapability::ROUTER,
        )),
    ];
    if let Some(address) = management {
        let address = match address {
            IpAddr::V4(v4) => NetworkAddress::Ipv4(v4),
            IpAddr::V6(v6) => NetworkAddress::Ipv6(v6),
        };
        let Ok(identifier) = ObjectIdentifier::new(&[]) else {
            unreachable!("an empty object identifier is valid");
        };
        if let Ok(tlv) = ManagementAddress::new(
            address,
            InterfaceNumber::new(InterfaceNumbering::Unknown, 0),
            identifier,
        ) {
            optional.push(OptionalTlv::ManagementAddress(tlv));
        }
    }
    // Left out rather than guessed when the driver could not learn the port's MTU.
    if let Some(mtu) = identity.mtu {
        optional.push(OptionalTlv::OrganizationallySpecific(
            OrganizationallySpecific::Dot3(Dot3Tlv::MaximumFrameSize(
                mtu.saturating_add(ETHERNET_OVERHEAD),
            )),
        ));
    }

    match Advertisement::new(
        source,
        ChassisId::LocallyAssigned(chassis),
        PortId::InterfaceName(port_id),
        optional,
    ) {
        Ok(advertisement) => Some(advertisement),
        Err(e) => {
            warn!(
                "LLDP: what port {port} would advertise does not fit in a frame ({e}); not advertising"
            );
            None
        }
    }
}

/// `value` as TLV text, cut at a character boundary if it is longer than a TLV can carry.
fn text(value: &str) -> Text {
    let mut end = value.len().min(255);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    Text::new(&value.as_bytes()[..end]).unwrap_or_else(|_| unreachable!("at most 255 octets"))
}

/// How often to look for the host's management address again.
const MANAGEMENT_REFRESH: Duration = Duration::from_secs(60);

/// Publish the host's management address, refreshed every minute.
///
/// The management address is the source address the host would use to reach the outside world: the
/// one on its default route. Found by connecting a UDP socket, which sends nothing but makes the
/// kernel choose a source address, so this must run where the host's routes are: on the host runtime.
/// IPv4 is preferred; with no IPv4 default route, IPv6 is tried.
pub(crate) async fn management_address(
    publish: watch::Sender<Option<IpAddr>>,
    cancel: lifecycle::CancellationToken,
) {
    // Documentation addresses (RFC 5737, RFC 3849): routed by a default route, owned by nobody.
    const PROBES: [&str; 2] = ["192.0.2.1:9", "[2001:db8::1]:9"];
    loop {
        let mut found = None;
        for probe in PROBES {
            let unspecified = if probe.starts_with('[') {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let Ok(socket) = tokio::net::UdpSocket::bind(unspecified).await else {
                continue;
            };
            if socket.connect(probe).await.is_ok()
                && let Ok(local) = socket.local_addr()
            {
                found = Some(local.ip());
                break;
            }
        }
        publish.send_if_modified(|current| {
            if *current == found {
                return false;
            }
            if let Some(address) = found {
                debug!("LLDP: the host's management address is {address}");
            } else {
                warn!("LLDP: the host has no default route, so no management address to advertise");
            }
            *current = found;
            true
        });
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(MANAGEMENT_REFRESH) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{advertise, text};
    use crate::drivers::cpbridge::PortIdentity;
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::InterfaceName;
    use net::lldp::{ChassisId, IdOctets, OptionalTlv};

    fn identity() -> PortIdentity {
        PortIdentity {
            name: InterfaceName::try_from("eth1").unwrap(),
            mac: SourceMac::new(Mac([0x02, 0, 0, 0, 0, 1])).unwrap(),
            mtu: Some(9000),
            hardware: Some("0000:03:00.0 (mlx5_pci)".to_owned()),
        }
    }

    fn port() -> InterfaceName {
        InterfaceName::try_from("eth1").unwrap()
    }

    #[test]
    fn nothing_is_advertised_before_the_gateway_has_a_name() {
        assert_eq!(advertise(&port(), Some(&identity()), None, None), None);
        assert_eq!(advertise(&port(), None, Some("gw-1"), None), None);
    }

    #[test]
    fn a_long_text_is_cut_at_a_character_boundary() {
        let long = "é".repeat(200);
        assert_eq!(text(&long).len(), 254);
    }

    #[test]
    fn a_named_gateway_advertises_its_name_as_chassis() {
        let advertised = advertise(
            &port(),
            Some(&identity()),
            Some("gw-1"),
            Some("10.0.0.1".parse().unwrap()),
        )
        .expect("a named gateway advertises");
        let pdu = advertised.lldpdu();
        assert_eq!(
            *pdu.chassis_id(),
            ChassisId::LocallyAssigned(IdOctets::new(b"gw-1").unwrap())
        );
        assert!(
            pdu.optional()
                .iter()
                .any(|tlv| matches!(tlv, OptionalTlv::ManagementAddress(_)))
        );
    }
}
