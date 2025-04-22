// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(dead_code)]

use crate::frr::renderer::builder::Render;
use crate::models::external::{ApiResult, configdb::gwconfig::GwConfig};
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

/// Main logic to apply a [`GwConfig`]. This is called from GwConfig::apply()
pub(crate) fn apply_gw_config(config: &mut GwConfig) -> ApiResult {
    /* apply in frr: need to render and call frr-reload */
    if let Some(internal) = &config.internal {
        debug!("FRR configuration is:\n{}", internal.render(config))
    }

    /* apply in interface manager - async */

    info!("Successfully applied config {}", config.genid());
    Ok(())
}
