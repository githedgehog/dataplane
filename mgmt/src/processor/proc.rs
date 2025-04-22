// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(dead_code)]

use crate::models::external::{ApiResult, configdb::gwconfig::GwConfig};
use crate::models::internal::InternalConfig;
use crate::processor::confbuild::build_internal_overlay_config;
use tracing::{debug, info};

/// Entry point for new configurations, [`GwConfig`]
pub fn new_gw_config(mut config: GwConfig) -> ApiResult {
    debug!("Processing new configuration '{}'..", config.genid());
    /* validate the config */
    config.validate()?;

    /* build internal config for this config */
    config.build_internal_config()?;

    /* add to config database */

    /* apply it */
    config.apply()?;

    Ok(())
}

/// Top-level function to build internal config from external config
pub(crate) fn build_internal_config(config: &GwConfig) -> InternalConfig {
    debug!("Building internal config for gen {}", config.genid());
    let external = &config.external;

    /* Build internal config object: device and underlay configs are copied as received */
    let mut internal = InternalConfig::new(external.device.clone());
    internal.add_vrf_config(external.underlay.vrf.clone());

    if let Some(bgp) = &external.underlay.vrf.bgp {
        let asn = bgp.asn;
        let router_id = bgp.router_id;

        // Build internal config for overlay config
        build_internal_overlay_config(&external.overlay, asn, router_id, &mut internal);
    } else {
        // TODO: we should reject this config
    }
    debug!("Built internal config for gen {}", config.genid());
    internal
}

/// Main logic to apply a [`GwConfig`]. This is called from GwConfig::apply()
pub(crate) fn apply_gw_config(config: &mut GwConfig) -> ApiResult {
    /* apply in frr: need to render and call frr-reload */

    /* apply in interface manager - async */

    info!("Successfully applied config {}", config.genid());
    Ok(())
}
