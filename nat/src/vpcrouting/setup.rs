// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Overlay routing configuration

use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::VpcExposeNatConfig;
use config::{ConfigError, GenId};
use lpm::prefix::L4Protocol;
use lpm::prefix::Prefix;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::sync::Arc;
use tracing::debug;

use crate::vpcrouting::routing::{
    Action, EgressVpcPolicyMap, IngressMap, OvelayRoute, OverlayRouting,
};

fn nat_config_to_local_action(nat_config: Option<&VpcExposeNatConfig>) -> Action {
    match nat_config {
        Some(VpcExposeNatConfig::Stateful(_)) => Action::Masquerade,
        Some(VpcExposeNatConfig::Stateless(_)) => Action::StaticNat,
        Some(VpcExposeNatConfig::PortForwarding(_)) => Action::PortForward,
        None => Action::Forward,
    }
}
fn nat_config_to_remote_action(nat_config: Option<&VpcExposeNatConfig>) -> Action {
    match nat_config {
        Some(VpcExposeNatConfig::PortForwarding(_)) => Action::PortForward,
        Some(VpcExposeNatConfig::Stateless(_)) => Action::StaticNat,
        Some(VpcExposeNatConfig::Stateful(_)) => Action::Masquerade,
        None => Action::Forward,
    }
}
fn l4proto_to_proto(l4protocol: L4Protocol) -> Option<NextHeader> {
    match l4protocol {
        L4Protocol::Tcp => Some(NextHeader::TCP),
        L4Protocol::Udp => Some(NextHeader::UDP),
        L4Protocol::Any => None,
    }
}

fn build_default_overlay_route(dst_vpcd: VpcDiscriminant) -> OvelayRoute {
    OvelayRoute::new(dst_vpcd, Prefix::root_v4(), None, None, Action::Forward)
}

fn build_vpc_routing_table(
    vpc: &Vpc,
    vpc_table: &VpcTable,
    emap: &mut EgressVpcPolicyMap,
    imap: &mut IngressMap,
) -> Result<(), ConfigError> {
    debug!("Building overlay routing table for VPC {}", vpc.name);
    let src_vpcd = VpcDiscriminant::from_vni(vpc.vni);
    for peering in &vpc.peerings {
        let dst_vpcd = vpc_table.get_remote_vni(peering);

        // populate the outbound policy for the VPC
        for expose in &peering.local.exposes {
            let action = nat_config_to_local_action(expose.nat_config());
            if action == Action::PortForward {
                continue;
            }
            for prefix in expose.local_prefixes() {
                emap.insert(src_vpcd, prefix, dst_vpcd.into(), action);
            }
            for not in expose.local_nots() {
                emap.insert(src_vpcd, not, dst_vpcd.into(), Action::Drop);
            }
            if expose.default {
                emap.insert(
                    src_vpcd,
                    Prefix::root_v4(),
                    dst_vpcd.into(),
                    Action::Forward,
                );
            }
        }

        // populate routing table for the vpc
        for expose in &peering.remote.exposes {
            let action = nat_config_to_remote_action(expose.nat_config());
            if action == Action::Masquerade {
                continue;
            }
            if expose.default {
                let route = build_default_overlay_route(dst_vpcd.into());
                imap.set_default(src_vpcd, route)
                    .map_err(|e| ConfigError::OverlayRoutingError(e.to_string()))?;
                continue;
            }

            let proto = expose
                .nat
                .as_ref()
                .and_then(|expose_nat| l4proto_to_proto(expose_nat.proto));

            for ext_prefix in expose.remote_prefixes() {
                let prefix = ext_prefix.prefix();
                let portrange = ext_prefix.ports().and_then(|ports| {
                    crate::portfw::PortRange::new(ports.start(), ports.end()).ok()
                });

                let route = OvelayRoute::new(dst_vpcd.into(), prefix, proto, portrange, action);
                imap.insert_route(src_vpcd, &Arc::from(route))
                    .map_err(|e| ConfigError::OverlayRoutingError(e.to_string()))?;
            }

            for not in expose.remote_nots() {
                emap.insert(src_vpcd, not.prefix(), dst_vpcd.into(), Action::Drop);
            }
        }
    }

    debug!("Successfully built overlay config for VPC {}", vpc.name);
    Ok(())
}

pub fn build_overlay_routing_configuration(
    genid: GenId,
    vpc_table: &VpcTable,
) -> Result<OverlayRouting, ConfigError> {
    let mut emap = EgressVpcPolicyMap::new();
    let mut imap = IngressMap::new();
    for vpc in vpc_table.values() {
        build_vpc_routing_table(vpc, vpc_table, &mut emap, &mut imap)?;
    }
    debug!("Successfully built overlay routing configuration:\n{imap}\n{emap}");
    Ok(OverlayRouting::new(genid, imap, emap))
}
