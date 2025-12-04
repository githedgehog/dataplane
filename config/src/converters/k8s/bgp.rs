// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::net::IpAddr;

use k8s_intf::gateway_agent_crd::GatewayAgentGatewayNeighbors;

use crate::converters::k8s::{FromK8sConversionError, ToK8sConversionError};
use crate::internal::routing::bgp::{
    BgpNeighCapabilities, BgpNeighType, BgpNeighbor, BgpUpdateSource, NeighSendCommunities,
};

impl TryFrom<&GatewayAgentGatewayNeighbors> for BgpNeighbor {
    type Error = FromK8sConversionError;

    fn try_from(neighbor: &GatewayAgentGatewayNeighbors) -> Result<Self, Self::Error> {
        let neighbor_addr = match neighbor.ip.as_ref() {
            Some(ip) => ip.parse::<IpAddr>().map_err(|e| {
                FromK8sConversionError::ParseError(format!("Invalid neighbor address {ip}: {e}"))
            })?,
            None => {
                return Err(FromK8sConversionError::MissingData(format!(
                    "Missing neighbor address in BGP neighbor with ASN {}",
                    neighbor.asn.ok_or(FromK8sConversionError::MissingData(
                        "Missing neighbor address and ASN in BGP neighbor".to_string()
                    ))?
                )));
            }
        };

        // Parse remote ASN
        let remote_as = neighbor
            .asn
            .ok_or(FromK8sConversionError::MissingData(format!(
                "Missing ASN in BGP neighbor with ip {neighbor_addr}"
            )))?;

        let ipv4_unicast = true;
        let ipv6_unicast = false;
        let l2vpn_evpn = true;

        // Create the neighbor config
        let mut neigh = BgpNeighbor::new_host(neighbor_addr)
            .set_remote_as(remote_as)
            .set_capabilities(BgpNeighCapabilities::default())
            .set_send_community(NeighSendCommunities::Both)
            .ipv4_unicast_activate(ipv4_unicast)
            .ipv6_unicast_activate(ipv6_unicast)
            .l2vpn_evpn_activate(l2vpn_evpn);

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

    fn try_from(neighbor: &BgpNeighbor) -> Result<Self, Self::Error> {
        // Get neighbor address safely
        let ip = match &neighbor.ntype {
            BgpNeighType::Host(addr) => addr.to_string(),
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

        Ok(GatewayAgentGatewayNeighbors {
            asn: Some(*asn),
            ip: Some(ip),
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
}
