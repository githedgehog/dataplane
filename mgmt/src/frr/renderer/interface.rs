// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: interfaces

use std::net::IpAddr;

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render, Rendered};

use config::internal::interfaces::interface::InterfaceAddress;
use config::internal::interfaces::interface::InterfaceConfig;
use config::internal::interfaces::interface::InterfaceConfigTable;

fn ip_address_type_str(address: &IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ipv6",
    }
}

impl Rendered for InterfaceAddress {
    fn rendered(&self) -> String {
        format!(
            " {} address {}/{}",
            ip_address_type_str(&self.address),
            &self.address,
            self.mask_len
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
        self.addresses.iter().for_each(|a| config += a.rendered());
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
    use config::internal::interfaces::interface::IfEthConfig;
    use config::internal::interfaces::interface::InterfaceType;
    use net::interface::Mtu;
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
        .set_mtu(Mtu::try_from(9000).expect("Bad MTU"))
        .add_address(IpAddr::from_str("10.0.1.1").expect("Bad address"), 24)
        .add_address(IpAddr::from_str("2001:1:2:3::6").expect("Bad address"), 96)
        .set_vrf("default");

        iface_table.add_interface_config(interface);

        /* lo: Loopback */
        let interface = InterfaceConfig::new("lo", InterfaceType::Loopback, false)
            .set_description("Main loopback interface")
            .set_mtu(Mtu::try_from(9000).expect("Bad MTU"))
            .add_address(IpAddr::from_str("7.0.0.10").expect("Bad address"), 32)
            .set_vrf("default");
        iface_table.add_interface_config(interface);

        println!("{}", iface_table.render(&()));
    }
}
