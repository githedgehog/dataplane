// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)] // Do not want to remove pub methods yet

mod bgp;
mod interface;
mod old_impl;
mod vpc;

pub use bgp::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use interface::*;
pub use old_impl::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use vpc::*;

#[cfg(test)]
mod test {
    use gateway_config::GatewayConfig;
    use pretty_assertions::assert_eq;

    use crate::grpc::converter::{convert_from_grpc_config, convert_to_grpc_config};

    fn normalize_order(config: &GatewayConfig) -> GatewayConfig {
        let mut config = config.clone();
        if let Some(overlay) = &mut config.overlay {
            overlay.vpcs.sort_by_key(|vpc| vpc.name.clone());
            overlay.vpcs.iter_mut().for_each(|vpc| {
                vpc.interfaces.sort_by_key(|iface| iface.name.clone());
                vpc.interfaces.iter_mut().for_each(|iface| {
                    iface.ipaddrs.sort_by_key(String::clone);
                });
            });
            overlay.peerings.sort_by_key(|peering| peering.name.clone());
            overlay.peerings.iter_mut().for_each(|peering| {
                peering.r#for.iter_mut().for_each(|peering_config| {
                    peering_config.expose.iter_mut().for_each(|expose| {
                        expose.ips.sort_by_key(|pip| format!("{pip:?}"));
                        expose
                            .r#as
                            .sort_by_key(|as_config| format!("{as_config:?}"));
                    });
                });
            });
        }

        if let Some(underlay) = &mut config.underlay {
            underlay.vrfs.sort_by_key(|vrf| vrf.name.clone());
            underlay.vrfs.iter_mut().for_each(|vrf| {
                vrf.interfaces.sort_by_key(|iface| iface.name.clone());
                vrf.interfaces.iter_mut().for_each(|iface| {
                    iface.ipaddrs.sort_by_key(String::clone);
                });
                if let Some(router) = &mut vrf.router {
                    router.neighbors.iter_mut().for_each(|neighbor| {
                        neighbor.af_activate.sort_by_key(|af| *af);
                    });
                }
            });
        }

        config
    }

    #[test]
    fn test_bolero_gateway_config_to_external() {
        bolero::check!()
            .with_type::<GatewayConfig>()
            .for_each(|config| {
                let external = convert_from_grpc_config(config).unwrap();
                let reserialized = convert_to_grpc_config(&external).unwrap();
                assert_eq!(normalize_order(config), normalize_order(&reserialized));
            });
    }
}
