// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! "Kubeless" client that learns configs from a directory and requests
//! the configuration processor to apply them.

use config::{ExternalConfig, GwConfig};
use futures::TryFutureExt;
use k8s_less::kubeless_watch_gateway_agent_crd;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::create_dir_all;
use tracing::{error, info};

use crate::processor::k8s_client::build_gateway_status;
use crate::processor::mgmt_client::{ConfigClient, ConfigProcessorError};
use k8s_intf::utils::save;

#[derive(Debug, thiserror::Error)]
pub enum K8sLessError {
    #[error("K8sless exited early")]
    EarlyTermination,
    #[error("Watching error: {0}")]
    WatchError(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

pub struct K8sLess {
    name: String,
    pathdir: String,
    statedir: String,
    client: ConfigClient,
}

impl K8sLess {
    pub fn new(name: &str, pathdir: &str, client: ConfigClient) -> Self {
        Self {
            name: name.to_owned(),
            pathdir: pathdir.to_string(),
            statedir: pathdir.to_string() + "/state",
            client,
        }
    }

    async fn update_gateway_status(&self) {
        let Some(k8s_status) = build_gateway_status(&self.client).await else {
            return;
        };
        let mut state_dir = PathBuf::from(&self.statedir);
        state_dir.push("gwstatus");

        let state_file = state_dir.to_str().unwrap_or_else(|| unreachable!());
        if let Err(e) = save(state_file, &k8s_status) {
            error!("Failed to save state: {e}");
        }
    }

    pub async fn start_config_watch(k8sless: Arc<Self>) -> Result<(), K8sLessError> {
        // create directory to store status updates
        create_dir_all(&k8sless.statedir).await.map_err(|e| {
            K8sLessError::Internal(format!(
                "Failed to create directory '{}': {e}",
                k8sless.statedir
            ))
        })?;

        info!("Starting config watcher for directory {}", k8sless.pathdir);

        kubeless_watch_gateway_agent_crd(&k8sless.name.clone(), &k8sless.pathdir.clone(), async move |ga| {
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

                    let gwconfig = GwConfig::new(&k8sless.name, external_config);

                    // request the config processor to apply the config and update status on success
                    match k8sless.client.apply_config(gwconfig).await {
                        Ok(()) => {
                            info!("Config for generation {genid} was successfully applied. Updating status...");
                            k8sless.update_gateway_status().await;
                        },
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
