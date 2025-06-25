// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Functions to build router configurations

use netdev::Interface as NetDevInterface;
use netdev::get_interfaces;
use netdev::interface::InterfaceType;

use std::collections::HashMap;
use tracing::{debug, error};

use net::interface::{Interface, InterfaceName, Mtu};
use routing::interfaces::interface::{AttachConfig, IfDataEthernet, IfState, IfType};

use crate::models::external::ConfigError;
use crate::models::external::gwconfig::GwConfig;

use crate::models::internal::InternalConfig;
use crate::models::internal::interfaces::interface::InterfaceConfig;
use crate::models::internal::routing::vrf::VrfConfig;

use routing::evpn::Vtep;
use routing::rib::vrf::{RouterVrfConfig, VrfId};
use routing::{config::RouterConfig, interfaces::interface::RouterInterfaceConfig};

fn generate_router_vrf_config(
    internal: &InternalConfig,
    kernel_vrfs: &HashMap<InterfaceName, Interface>,
    router_config: &mut RouterConfig,
) {
    /* access VRFs from internal config and build the vrf configs using the ifindex from kernel */
    for vrf in internal.vrfs.vpc_vrfs() {
        let vpcid = vrf.vpc_id.as_ref().unwrap_or_else(|| unreachable!());
        let kvrf = kernel_vrfs
            .get(&vpcid.vrf_name())
            .unwrap_or_else(|| unreachable!());
        let tableid = kvrf
            .get_vrf_properties()
            .map(|p| p.route_table_id)
            .unwrap_or_else(|| unreachable!());
        let vrfconfig = RouterVrfConfig::new(kvrf.index.into(), kvrf.name.as_ref())
            .set_vni(vrf.vni)
            .set_description(&vrf.description.clone().unwrap_or_else(|| "--".to_string()))
            .set_tableid(tableid);
        router_config.add_vrf(vrfconfig);
    }
}
fn generate_router_vtep_config(internal: &InternalConfig, router_config: &mut RouterConfig) {
    if let Some(vconfig) = internal.get_vtep() {
        let vtep = Vtep::with_ip_and_mac(vconfig.address.into(), vconfig.mac.into());
        router_config.set_vtep(vtep);
    }
}

/// Build an interface config for the router from the kernel interface and the interface configuration
fn build_router_interface_config(
    _if_config: &InterfaceConfig,
    kiface: &NetDevInterface,
    vrfid: VrfId,
) -> Result<RouterInterfaceConfig, ConfigError> {
    let name = kiface.name.as_str();
    let mut new = RouterInterfaceConfig::new(name, kiface.index);

    // set admin status -- currently from oper
    let status = if kiface.is_up() {
        IfState::Up
    } else {
        IfState::Down
    };
    new.set_admin_state(status);

    // set mtu -- this is informational
    if let Some(mtu) = kiface.mtu {
        if let Ok(mtu) = Mtu::try_from(mtu) {
            new.set_mtu(Some(mtu));
        }
    }

    // set properties -- this is needed for us to know macs
    match kiface.if_type {
        InterfaceType::Loopback => new.set_iftype(IfType::Loopback),
        InterfaceType::Ethernet => {
            let Some(mac) = &kiface.mac_addr else {
                let msg = format!("Failed to get mac for Ethernet interface '{name}': {kiface:#?}");
                error!("{msg}");
                return Err(ConfigError::InternalFailure(msg));
            };
            new.set_iftype(IfType::Ethernet(IfDataEthernet {
                mac: mac.octets().into(),
            }));
        }
        _ => {
            let msg = format!("Unsupported type of interface: {kiface:#?}");
            error!("{msg}");
            return Err(ConfigError::InternalFailure(msg));
        }
    }

    // attach to the indicated VRF
    new.set_attach_cfg(Some(AttachConfig::VRF(vrfid)));

    Ok(new)
}

fn generate_router_interface_config_per_vrf(
    vrf_cfg: &VrfConfig,
    kernel_vrfs: &HashMap<InterfaceName, Interface>,
    kernel_interfaces: &HashMap<String, NetDevInterface>,
    router_config: &mut RouterConfig,
) -> Result<(), ConfigError> {
    // lookup the ifindex of the vrf again since we don't store it in the config
    let vrfid = if vrf_cfg.default {
        0
    } else {
        let vpcid = vrf_cfg.vpc_id.as_ref().unwrap_or_else(|| unreachable!());
        kernel_vrfs
            .get(&vpcid.vrf_name())
            .unwrap_or_else(|| unreachable!())
            .index
            .into()
    };

    // loop over all of the interface configurations in the VRF. Skip VTEPs as our vtep is mapped to multiple kernel interfaces
    for if_config in vrf_cfg.interfaces.values().filter(|ifc| !ifc.is_vtep()) {
        // lookup kernel interface in cached hash map
        let name = &if_config.name;
        let kiface = kernel_interfaces.get(name).ok_or_else(|| {
            let msg = format!("Unable to find kernel interface '{name}'");
            error!("{msg}");
            ConfigError::InternalFailure(msg)
        })?;
        // Build interface config using the interface configuration and the kernel interface
        let rtr_ifconfig = build_router_interface_config(if_config, kiface, vrfid)?;
        router_config.add_interface(rtr_ifconfig);
    }
    Ok(())
}

// For each interface listed in the vrf configuration, we need to know its ifindex in order to build
// an interface config. Atm the interface should just exist. When the interface manager will manage those interfaces,
// they shall exist too, but we may not need to use netdev to look them up here and instead get a list as it happens
// with kernel vrf interfaces. We look these up once and pass a hashmap keyed by name so that we don't need to
// look them up for each vrf.
fn get_kernel_interfaces() -> HashMap<String, NetDevInterface> {
    debug!("Retrieving kernel interfaces");
    let interfaces = get_interfaces();
    let interfaces: HashMap<String, NetDevInterface> = interfaces
        .into_iter()
        .map(|interface| (interface.name.clone(), interface))
        .collect();

    debug!("Collected {} kernel interfaces", interfaces.len());
    for intf in interfaces.values() {
        debug!(
            "name: {} ifindex: {} type: {:?}",
            intf.name, intf.index, intf.if_type
        );
    }
    interfaces
}

fn generate_router_interfaces_config(
    internal: &InternalConfig,
    kernel_vrfs: &HashMap<InterfaceName, Interface>,
    router_config: &mut RouterConfig,
) -> Result<(), ConfigError> {
    let kernel_interfaces = get_kernel_interfaces();
    for vrf_cfg in internal.vrfs.all_vrfs() {
        generate_router_interface_config_per_vrf(
            vrf_cfg,
            kernel_vrfs,
            &kernel_interfaces,
            router_config,
        )?;
    }
    Ok(())
}
pub(crate) fn generate_router_config(
    kernel_vrfs: &HashMap<InterfaceName, Interface>,
    config: &GwConfig,
) -> Result<RouterConfig, ConfigError> {
    let genid = config.genid();
    debug!("Generating router config for genid {genid}...");

    /* get internal config -- should not fail by construction */
    let internal = config.internal.as_ref().unwrap_or_else(|| unreachable!());

    /* create a new, empty RouterConfig and populate it with vrf, vtep and interface configs */
    let mut router_config = RouterConfig::new(genid);
    generate_router_vrf_config(internal, kernel_vrfs, &mut router_config);
    generate_router_vtep_config(internal, &mut router_config);

    #[cfg(test)]
    let gen_intf_cfg = false;
    #[cfg(not(test))]
    let gen_intf_cfg = true;
    if gen_intf_cfg {
        generate_router_interfaces_config(internal, kernel_vrfs, &mut router_config)?;
    }
    Ok(router_config)
}
