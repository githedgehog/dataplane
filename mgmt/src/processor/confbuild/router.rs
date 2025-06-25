// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Functions to build router configurations

use std::collections::HashMap;
use tracing::debug;

use net::interface::{Interface, InterfaceName};

use crate::models::external::ConfigError;
use crate::models::external::gwconfig::GwConfig;
use crate::models::internal::InternalConfig;

use routing::config::RouterConfig;
use routing::evpn::Vtep;
use routing::rib::vrf::RouterVrfConfig;

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
fn generate_router_interface_config(_internal: &InternalConfig, _router_config: &mut RouterConfig) {
    // TODO(fredi): need the internal wiring for this
}
pub(crate) fn generate_router_config(
    kernel_vrfs: &HashMap<InterfaceName, Interface>,
    config: &GwConfig,
) -> Result<RouterConfig, ConfigError> {
    let genid = config.genid();
    debug!("Generating router config for genid {genid}...");

    /* get internal config -- should not fail by construction */
    let internal = config.internal.as_ref().unwrap_or_else(|| unreachable!());

    /* create a new, empty RouterConfig */
    let mut router_config = RouterConfig::new(genid);

    /* populate vrf config */
    generate_router_vrf_config(internal, &kernel_vrfs, &mut router_config);
    generate_router_vtep_config(internal, &mut router_config);
    generate_router_interface_config(internal, &mut router_config);
    Ok(router_config)
}
