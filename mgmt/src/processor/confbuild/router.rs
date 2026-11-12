// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Functions to build router configurations

use crate::processor::confbuild::namegen::VpcInterfacesNames;
use concurrency::sync::Arc;

use tracing::{debug, error};

use config::internal::interfaces::interface::{InterfaceConfig, InterfaceType};
use config::internal::routing::vrf::VrfConfig;
use config::{ConfigError, InternalConfig, ValidatedGwConfig};
use net::interface::{Interface, InterfaceProperties, MultiIndexInterfaceMap};

use routing::{AttachConfig, IfDataEthernet, IfState, IfType};
use routing::{Render, RouterConfig, RouterInterfaceConfig, RouterVrfConfig, VrfId, Vtep};

// Add the config for the VTEP for the router
fn generate_router_vtep_config(internal: &InternalConfig, router_config: &mut RouterConfig) {
    if let Some(vconfig) = internal.get_vtep() {
        let vtep = Vtep::new(vconfig.address, vconfig.mac);
        router_config.set_vtep(vtep);
    }
}

// Add the config for a VRF for the router
fn generate_router_vrf_config(
    internal: &InternalConfig,
    kernel_ifaces: &MultiIndexInterfaceMap,
    router_config: &mut RouterConfig,
) {
    // get VRFs from internal config and build the vrf configs for the router, using their ifindex
    for vrf in internal.vrfs.vpc_vrfs() {
        let vpcid = vrf.vpc_id.as_ref().unwrap_or_else(|| unreachable!());
        let name = vpcid.vrf_name();
        let Some(kvrf) = kernel_ifaces.get_by_name(&name) else {
            error!("Failed to find kernel vrf {name}. This is a bug");
            continue;
        };
        let Some(tableid) = kvrf.get_vrf_properties().map(|p| p.route_table_id) else {
            error!("Kernel interface {name} is not a vrf. This is a bug");
            continue;
        };
        let ifindex = kvrf.index;
        let vni = vrf.vni.unwrap_or_else(|| unreachable!()); // VPC must have vni

        debug!("Building cfg for vrf:{name} id:{vpcid} tblid:{tableid} index:{ifindex} vni:{vni}");
        let vrfconfig = RouterVrfConfig::new(kvrf.index.into(), kvrf.name.as_ref())
            .set_vni(vrf.vni)
            .set_vpcname(&vrf.vpcname.clone().unwrap_or_else(|| "--".to_string()))
            .set_tableid(tableid);

        router_config.add_vrf(vrfconfig);
    }
}

/// Build an interface config for the router from the kernel interface and the interface configuration
fn build_router_interface_config(
    if_config: &InterfaceConfig,
    kiface: &Interface,
    vrfid: VrfId,
) -> Result<RouterInterfaceConfig, ConfigError> {
    let name = &kiface.name;
    let mut new = RouterInterfaceConfig::new(name.clone(), kiface.index);
    // we don't expose a way to set admin state interface atm.
    // therefore, it is always up
    new.set_admin_state(IfState::Up);

    // set mtu -- this is informational
    if let Some(mtu) = kiface.mtu {
        new.set_mtu(mtu);
    }

    // set description
    if let Some(description) = &if_config.description {
        new.set_description(description);
    }

    // set properties -- this is needed for us to know macs.
    // The configured type must agree with what the kernel reports.
    let cfg_lo = matches!(if_config.iftype, InterfaceType::Loopback);
    let kern_lo = matches!(kiface.properties, InterfaceProperties::Loopback);
    match (cfg_lo, kern_lo) {
        (true, true) => new.set_iftype(IfType::Loopback),
        (true, false) | (false, true) => {
            let msg = format!(
                "Type mismatch for interface '{name}': config {:?}, kernel {}",
                if_config.iftype, kiface.properties
            );
            error!("{msg}");
            return Err(ConfigError::InternalFailure(msg));
        }
        (false, false) => {
            let Some(mac) = kiface.mac else {
                let msg = format!("Failed to get mac for interface '{name}': {kiface:#?}");
                error!("{msg}");
                return Err(ConfigError::InternalFailure(msg));
            };
            new.set_iftype(IfType::Ethernet(IfDataEthernet::new(mac)));
        }
    }

    // attach to the indicated VRF
    new.set_attach_cfg(Some(AttachConfig::Vrf(vrfid)));

    Ok(new)
}

fn get_vrf_ifindex(
    vrf_cfg: &VrfConfig,
    router_config: &RouterConfig,
) -> Result<VrfId, ConfigError> {
    if vrf_cfg.default {
        Ok(0)
    } else {
        let name = &vrf_cfg.name;
        router_config
            .get_vrfid(name)
            .ok_or(ConfigError::InternalFailure(format!(
                "Unable to determine ifindex for vrf {name}"
            )))
    }
}

fn generate_router_interface_config_per_vrf(
    kernel_ifaces: &MultiIndexInterfaceMap,
    vrf_cfg: &VrfConfig,
    router_config: &mut RouterConfig,
) -> Result<(), ConfigError> {
    debug!("Building interface config for vrf {}", vrf_cfg.name);
    let vrfid = get_vrf_ifindex(vrf_cfg, router_config)?;

    // loop over all of the interface configurations in the VRF. Skip VTEPs as our vtep is mapped to multiple kernel interfaces
    for if_config in vrf_cfg.interfaces.values().filter(|ifc| !ifc.is_vtep()) {
        // lookup kernel interface in the snapshot
        let name = &if_config.name;
        let kiface = kernel_ifaces.get_by_name(name).ok_or_else(|| {
            let msg = format!("Unable to find kernel interface '{name}'");
            error!("{msg}");
            ConfigError::InternalFailure(msg)
        })?;

        // Build interface config using the interface configuration and the kernel interface
        let rtr_ifconfig = build_router_interface_config(if_config, kiface, vrfid)?;

        // Add the configuration
        router_config.add_interface(rtr_ifconfig);
    }
    Ok(())
}

fn generate_router_interfaces_config(
    kernel_ifaces: &MultiIndexInterfaceMap,
    internal: &InternalConfig,
    router_config: &mut RouterConfig,
) -> Result<(), ConfigError> {
    for vrf_cfg in internal.vrfs.all_vrfs() {
        generate_router_interface_config_per_vrf(kernel_ifaces, vrf_cfg, router_config)?;
    }
    Ok(())
}
pub(crate) fn generate_router_config(
    kernel_ifaces: &MultiIndexInterfaceMap,
    config: Arc<ValidatedGwConfig>,
) -> Result<RouterConfig, ConfigError> {
    let genid = config.genid();
    debug!("Generating router config for genid {genid}...");

    /* get internal config -- should not fail by construction */
    let internal = config.internal().unwrap_or_else(|| unreachable!());

    /* create a new, empty RouterConfig and populate it with vrf, vtep and interface configs */
    let mut router_config = RouterConfig::new(genid);
    generate_router_vrf_config(internal, kernel_ifaces, &mut router_config);
    generate_router_vtep_config(internal, &mut router_config);

    #[cfg(test)]
    let gen_intf_cfg = false;
    #[cfg(not(test))]
    let gen_intf_cfg = true;
    if gen_intf_cfg {
        generate_router_interfaces_config(kernel_ifaces, internal, &mut router_config)?;
    }

    /* set frr config as part of the router config */
    let frr_cfg = internal.render(&genid);
    router_config.set_frr_config(frr_cfg.to_string());

    Ok(router_config)
}
