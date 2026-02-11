// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use hardware::pci::address::PciAddress;
use k8s_types::gateway_agent_crd::GatewayAgentGatewayInterfaces;
use net::interface::Mtu;

use crate::converters::k8s::{FromK8sConversionError, ToK8sConversionError};
use crate::internal::interfaces::interface::{
    IfEthConfig, InterfaceAddress, InterfaceConfig, InterfaceType,
};

impl TryFrom<(&str, &GatewayAgentGatewayInterfaces)> for InterfaceConfig {
    type Error = FromK8sConversionError;

    fn try_from(
        (name, iface): (&str, &GatewayAgentGatewayInterfaces),
    ) -> Result<Self, Self::Error> {
        // GatewayAgentGatewayInterfaces is only for Ethernet interfaces, loopback and vtep interface
        // is added explicitly by underlay construction.
        //
        // The Gateway agent CRD also does not support specifying the source mac
        // address.
        let iftype = InterfaceType::Ethernet(IfEthConfig { mac: None });

        let mut interface_config: InterfaceConfig = InterfaceConfig::new(name, iftype, false);

        if let Some(ips) = iface.ips.as_ref() {
            for ip in ips {
                let ifaddr = ip.parse::<InterfaceAddress>().map_err(|e| {
                    FromK8sConversionError::ParseError(format!(
                        "Invalid interface address \"{ip}\": {e}"
                    ))
                })?;
                interface_config = interface_config.add_address(ifaddr.address, ifaddr.mask_len);
            }
        }

        if let Some(iface_mtu) = iface.mtu {
            let mtu = Mtu::try_from(iface_mtu)
                .map_err(|e| FromK8sConversionError::ParseError(format!("Invalid MTU: {e}")))?;
            interface_config = interface_config.set_mtu(mtu);
        }

        if let Some(pci) = &iface.pci {
            let pci = PciAddress::try_from(pci.as_str()).map_err(|e| {
                FromK8sConversionError::ParseError(format!("Invalid PCI address: {e}"))
            })?;
            interface_config = interface_config.set_pci(pci);
        }

        Ok(interface_config)
    }
}

impl TryFrom<&InterfaceConfig> for GatewayAgentGatewayInterfaces {
    type Error = ToK8sConversionError;

    fn try_from(if_config: &InterfaceConfig) -> Result<Self, Self::Error> {
        if let InterfaceType::Ethernet(IfEthConfig { mac }) = if_config.iftype {
            if mac.is_some() {
                return Err(ToK8sConversionError::Unsupported(format!(
                    "Explicit mac addresses not supported by CRD {}",
                    if_config.name
                )));
            }
        } else {
            return Err(ToK8sConversionError::Unsupported(format!(
                "Unsupported interface type on interface {}, only Ethernet is supported in CRD",
                if_config.name
            )));
        }

        let mtu = if_config.mtu.map(|m| m.to_u32());
        let pci = if_config.pci.map(|p| p.to_string());

        let ips = if_config
            .addresses
            .iter()
            .map(InterfaceAddress::to_string)
            .collect::<Vec<String>>();

        Ok(GatewayAgentGatewayInterfaces {
            ips: if ips.is_empty() { None } else { Some(ips) },
            kernel: None,
            mtu,
            pci,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use k8s_intf::bolero::{LegalValue, Normalize};

    #[test]
    fn test_interface_conversion() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgentGatewayInterfaces>>()
            .for_each(|gw_if| {
                let gw_if = gw_if.as_ref();
                let if_config = InterfaceConfig::try_from(("test_if", gw_if)).unwrap();
                let converted_gw_if = GatewayAgentGatewayInterfaces::try_from(&if_config).unwrap();
                assert_eq!(gw_if.normalize(), converted_gw_if.normalize());
            });
    }
}
