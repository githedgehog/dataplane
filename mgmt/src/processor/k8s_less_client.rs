// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use config::{ExternalConfig, GwConfig};
use futures::TryFutureExt;
use k8s_less::kubeless_watch_gateway_agent_crd;
use std::sync::Arc;
use tracing::{error, info};

use crate::processor::mgmt_client::{ConfigClient, ConfigProcessorError};

#[derive(Debug, thiserror::Error)]
pub enum K8sLessError {
    #[error("K8sless exited early")]
    EarlyTermination,
    #[error("Watching error: {0}")]
    WatchError(String),
}

pub struct K8sLess {
    pathdir: String,
    client: ConfigClient,
}

impl K8sLess {
    pub fn new(pathdir: &str, client: ConfigClient) -> Self {
        Self {
            pathdir: pathdir.to_string(),
            client,
        }
    }

    pub async fn start_config_watch(k8sless: Arc<Self>) -> Result<(), K8sLessError> {
        info!("Starting config watcher for directory {}", k8sless.pathdir);

        kubeless_watch_gateway_agent_crd(&k8sless.pathdir.clone(), async move |ga| {
            info!("Attempting to deserialize new gateway CRD ...");

            let external_config = ExternalConfig::try_from(ga);
            match external_config {
                Err(e) => error!("Failed to convert K8sGatewayAgent to ExternalConfig: {e}"),
                Ok(external_config) => {
                    let genid = external_config.genid;
                    let applied_genid = match k8sless.client.get_generation().await {
                        Ok(genid) => genid,
                        Err(ConfigProcessorError::NoConfigApplied) => 0,
                        Err(e) => {
                            error!("Failed to get current config generation: {e}");
                            return;
                        }
                    };
                    info!("Current configuration is {applied_genid}");

                    let gwconfig = GwConfig::new(external_config);

                    // request the config processor to apply the config and update status on success
                    match k8sless.client.apply_config(gwconfig).await {
                        Ok(()) => info!("Config for generation {genid} was successfully applied"),
                        Err(e) => error!("Failed to apply the config for generation {genid}: {e}"),
                    }
                }
            }
        })
        .map_err(K8sLessError::WatchError)
        .await?;

        Err(K8sLessError::EarlyTermination)
    }
}
