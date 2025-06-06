// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: interfaces

use std::fmt::Display;
use std::net::IpAddr;

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render};

use crate::models::internal::interfaces::interface::InterfaceAddress;
use crate::models::internal::interfaces::interface::InterfaceConfig;
use crate::models::internal::interfaces::interface::InterfaceConfigTable;

fn ip_address_type_str(address: &IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ipv6",
    }
}

#[repr(transparent)]
pub struct RenderInterfaceAddress<'a>(pub &'a InterfaceAddress);

impl<'a> Display for RenderInterfaceAddress<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            " {} address {}/{}",
            ip_address_type_str(&self.0.address),
            &self.0.address,
            self.0.mask_len
        )
    }
}
impl Render for InterfaceConfig {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _ctx: &Self::Context) -> ConfigBuilder {
        let mut config = ConfigBuilder::new();
        config += MARKER;
        config += format!("interface {}", self.name);
        if let Some(description) = &self.description {
            config += format!(" description {description}");
        }
        self.addresses
            .iter()
            .for_each(|a| config += RenderInterfaceAddress(a).to_string());
        if let Some(ospf) = &self.ospf {
            config += ospf.render(&());
        }
        config += "exit";
        config += MARKER;
        config
    }
}
impl Render for InterfaceConfigTable {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _ctx: &Self::Context) -> Self::Output {
        let mut config = ConfigBuilder::new();
        // we only render config if interfaces are not marked internal
        self.values()
            .filter(|iface| !iface.internal)
            .for_each(|iface| config += iface.render(&()));
        config
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod tests {
    use super::*;
    use crate::models::internal::interfaces::interface::IfEthConfig;
    use crate::models::internal::interfaces::interface::InterfaceType;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_interface_render() {
        let mut iface_table = InterfaceConfigTable::new();

        /* eth0: Ethernet */
        let interface = InterfaceConfig::new(
            "eth0",
            InterfaceType::Ethernet(IfEthConfig { mac: None }),
            false,
        )
        .set_description("Intf to spine 2")
        .set_mtu(9000)
        .add_address(IpAddr::from_str("10.0.1.1").expect("Bad address"), 24)
        .add_address(IpAddr::from_str("2001:1:2:3::6").expect("Bad address"), 96)
        .set_vrf("default");

        iface_table.add_interface_config(interface);

        /* lo: Loopback */
        let interface = InterfaceConfig::new("lo", InterfaceType::Loopback, false)
            .set_description("Main loopback interface")
            .set_mtu(9000)
            .add_address(IpAddr::from_str("7.0.0.10").expect("Bad address"), 32)
            .set_vrf("default");
        iface_table.add_interface_config(interface);

        println!("{}", iface_table.render(&()));
    }
}
