// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::net::IpAddr;

use k8s_intf::gateway_agent_crd::GatewayAgentGatewayNeighbors;

use crate::converters::k8s::{FromK8sConversionError, ToK8sConversionError};
use crate::internal::routing::bgp::{BgpNeighType, BgpNeighbor, BgpUpdateSource};

impl TryFrom<&GatewayAgentGatewayNeighbors> for BgpNeighbor {
    type Error = FromK8sConversionError;

    /// Decode one CRD neighbor entry into the internal model.
    ///
    /// An entry with an address is a numbered peer whose `source` is the local
    /// update-source. An entry without one is BGP unnumbered, and `source` then
    /// names the interface to peer over instead. Whether that interface exists,
    /// and whether its addressing agrees with the neighbor's, is checked in
    /// `Underlay::validate` rather than here.
    ///
    /// # Errors
    ///
    /// Returns [`FromK8sConversionError`] if the remote ASN is missing, if the
    /// address is present but unparseable, or if an address-less entry names no
    /// source interface and so identifies no peer at all.
    fn try_from(neighbor: &GatewayAgentGatewayNeighbors) -> Result<Self, Self::Error> {
        // A neighbor with no address is BGP unnumbered. Pick source here
        let Some(ip) = neighbor.ip.as_ref() else {
            let ifname = neighbor.source.as_ref().ok_or_else(|| {
                FromK8sConversionError::MissingData(
                    "BGP neighbor has neither an address nor a source interface: an unnumbered \
                     neighbor must name the interface to peer over"
                        .to_string(),
                )
            })?;
            let remote_as = neighbor
                .asn
                .ok_or(FromK8sConversionError::MissingData(format!(
                    "Missing ASN in unnumbered BGP neighbor on interface {ifname}"
                )))?;
            return Ok(BgpNeighbor::new_interface(ifname).set_remote_as(remote_as));
        };

        let neighbor_addr = ip.parse::<IpAddr>().map_err(|e| {
            FromK8sConversionError::InvalidData(format!("neighbor address {ip}: {e}"))
        })?;

        // Parse remote ASN
        let remote_as = neighbor
            .asn
            .ok_or(FromK8sConversionError::MissingData(format!(
                "Missing ASN in BGP neighbor with ip {neighbor_addr}"
            )))?;

        // Create the neighbor config
        let mut neigh = BgpNeighbor::new_host(neighbor_addr).set_remote_as(remote_as);

        // set update source
        if let Some(update_source) = &neighbor.source {
            let upd_source = BgpUpdateSource::Interface(update_source.clone());
            neigh = neigh.set_update_source(Some(upd_source));
        }

        Ok(neigh)
    }
}

impl TryFrom<&BgpNeighbor> for GatewayAgentGatewayNeighbors {
    type Error = ToK8sConversionError;

    /// Encode an internal BGP neighbor back into a CRD entry.
    ///
    /// A numbered peer keeps its address, with `source` carrying an interface
    /// update-source if it has one. An unnumbered peer has no address and maps
    /// back to its interface name in `source`, mirroring the decode above.
    ///
    /// # Errors
    ///
    /// Returns [`ToK8sConversionError`] for neighbors the CRD cannot express:
    /// peer groups, a neighbor with no type set, an address-valued
    /// update-source, or a neighbor with no remote ASN.
    fn try_from(neighbor: &BgpNeighbor) -> Result<Self, Self::Error> {
        let (ip, source) = match &neighbor.ntype {
            BgpNeighType::Host(addr) => {
                let source = neighbor
                    .update_source
                    .as_ref()
                    .map(|source| match source {
                        BgpUpdateSource::Interface(intf) => Ok(intf.clone()),
                        BgpUpdateSource::Address(_) => Err(ToK8sConversionError::Unsupported(
                            "Unsupported BgpUpdateSource type".to_string(),
                        )),
                    })
                    .transpose()?;
                (Some(addr.to_string()), source)
            }
            BgpNeighType::Interface(ifname) => (None, Some(ifname.clone())),
            BgpNeighType::PeerGroup(name) => {
                return Err(ToK8sConversionError::Unsupported(format!(
                    "Peer group type not supported in CRD: {name}"
                )));
            }
            BgpNeighType::Unset => {
                return Err(ToK8sConversionError::Unsupported(
                    "Unset BGP neighbor type not supported in CRD".to_string(),
                ));
            }
        };

        // Get remote ASN safely
        let asn = neighbor.remote_as.as_ref().ok_or_else(|| {
            ToK8sConversionError::MissingData("Missing remote ASN for BGP neighbor".to_string())
        })?;

        Ok(GatewayAgentGatewayNeighbors {
            asn: Some(*asn),
            ip,
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use k8s_intf::bolero::{LegalValue, Normalize};

    #[test]
    fn test_neighbor_conversion() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgentGatewayNeighbors>>()
            .for_each(|neighbor| {
                let neighbor = neighbor.as_ref();
                let bgp_neighbor = BgpNeighbor::try_from(neighbor).unwrap();
                let converted_neighbor =
                    GatewayAgentGatewayNeighbors::try_from(&bgp_neighbor).unwrap();
                assert_eq!(neighbor.normalize(), converted_neighbor);
            });
    }

    /// A neighbor with no `ip` is the BGP-unnumbered case: it becomes an
    /// interface peer over `source`, and `source` is *not* reused as an
    /// update-source.
    #[test]
    fn test_unnumbered_neighbor_conversion() {
        let crd = GatewayAgentGatewayNeighbors {
            asn: Some(65100),
            ip: None,
            source: Some("enp2s1np0".to_string()),
        };

        let neigh = BgpNeighbor::try_from(&crd).expect("unnumbered neighbor should convert");
        assert!(matches!(&neigh.ntype, BgpNeighType::Interface(i) if i == "enp2s1np0"));
        assert_eq!(neigh.remote_as, Some(65100));
        assert!(neigh.update_source.is_none());

        // and it round-trips back to the same CRD shape
        let back = GatewayAgentGatewayNeighbors::try_from(&neigh).expect("should convert back");
        assert_eq!(back, crd);
    }

    /// A neighbor with an `ip` keeps the numbered behaviour: `source` is the
    /// update-source, not the peering interface.
    #[test]
    fn test_numbered_neighbor_keeps_update_source() {
        let crd = GatewayAgentGatewayNeighbors {
            asn: Some(65100),
            ip: Some("172.30.128.22".to_string()),
            source: Some("enp2s1np0".to_string()),
        };

        let neigh = BgpNeighbor::try_from(&crd).expect("numbered neighbor should convert");
        assert!(matches!(neigh.ntype, BgpNeighType::Host(_)));
        assert!(matches!(
            &neigh.update_source,
            Some(BgpUpdateSource::Interface(i)) if i == "enp2s1np0"
        ));
    }

    /// Neither an address nor a source interface leaves nothing to peer with.
    #[test]
    fn test_neighbor_without_ip_or_source_is_rejected() {
        let crd = GatewayAgentGatewayNeighbors {
            asn: Some(65100),
            ip: None,
            source: None,
        };
        assert!(BgpNeighbor::try_from(&crd).is_err());
    }
}
