// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::time::SystemTime;

use chrono::{TimeZone, Utc};
use config::converters::k8s::ToK8sConversionError;

use config::converters::k8s::status::dataplane_status::DataplaneStatusForK8sConversion;
use config::{ExternalConfig, GwConfig};
use k8s_intf::client::{
    ReplaceStatusError, WatchError, replace_gateway_status, watch_gateway_agent_crd,
};
use k8s_intf::gateway_agent_crd::{
    GatewayAgentStatus, GatewayAgentStatusState, GatewayAgentStatusStateDataplane,
};
use tracing::{debug, error, info};

use crate::processor::mgmt_client::{ConfigClient, ConfigProcessorError};

#[derive(Debug, thiserror::Error)]
pub enum K8sClientError {
    #[error("K8s client exited early")]
    EarlyTermination,
    #[error("K8s watch failed: {0}")]
    WatchError(#[from] WatchError),
    #[error("Failed to convert dataplane status to k8s format: {0}")]
    StatusConversionError(#[from] ToK8sConversionError),
    #[error("Failed to patch k8s gateway status: {0}")]
    ReplaceStatusError(#[from] ReplaceStatusError),
}

fn to_datetime(opt_time: Option<&SystemTime>) -> chrono::DateTime<Utc> {
    match opt_time {
        Some(time) => chrono::DateTime::<Utc>::from(*time),
        None => Utc.timestamp_opt(0, 0).unwrap(),
    }
}

async fn update_gateway_status(hostname: &str, client: &ConfigClient) -> () {
    let status = client.get_status().await;
    let status = match status {
        Ok(status) => status,
        Err(err) => {
            error!(
                "Failed to fetch dataplane status, skipping status update: {}",
                err
            );
            return;
        }
    };

    let (last_applied_gen, last_applied_time) = match client.get_current_config().await {
        Ok(config) => (config.genid(), to_datetime(config.meta.apply_t.as_ref())),
        Err(e) => {
            error!("Failed to get current config, skipping status update: {e}");
            return;
        }
    };

    let k8s_status = match GatewayAgentStatus::try_from(&DataplaneStatusForK8sConversion {
        last_applied_gen: Some(last_applied_gen),
        last_applied_time: Some(&last_applied_time),
        last_collected_time: Some(&chrono::Utc::now()),
        last_heartbeat: Some(&chrono::Utc::now()),
        status: Some(&status),
    }) {
        Ok(status) => status,
        Err(err) => {
            error!("Failed to convert status to GatewayAgentStatus: {err}");
            return;
        }
    };

    match replace_gateway_status(hostname, &k8s_status).await {
        Ok(()) => (),
        Err(err) => {
            error!("Failed to update gateway status: {err}");
        }
    }
}

pub struct K8sClient {
    hostname: String,
}

impl K8sClient {
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
        }
    }

    pub async fn init(&self) -> Result<(), K8sClientError> {
        // Reset the config generation and applied time in K8s
        replace_gateway_status(
            &self.hostname,
            &GatewayAgentStatus {
                agent_version: None,
                last_applied_gen: Some(0),
                last_applied_time: Some(
                    Utc.timestamp_opt(0, 0)
                        .unwrap()
                        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                ),
                last_heartbeat: Some(
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                ),
                state: Some(GatewayAgentStatusState {
                    dataplane: Some(GatewayAgentStatusStateDataplane {
                        version: Some(option_env!("VERSION").unwrap_or("dev").to_string()),
                    }),
                    frr: None,
                    last_collected_time: None,
                    peerings: None,
                    vpcs: None,
                }),
            },
        )
        .await?;
        Ok(())
    }

    pub async fn k8s_start_config_watch(&self, client: ConfigClient) -> Result<(), K8sClientError> {
        // Clone this here so that the closure does not try to borrow self
        // and cause K8sClient to not be Send for 'static but only a specific
        // lifetime
        let hostname = self.hostname.clone();
        watch_gateway_agent_crd(&hostname.clone(), async move |ga| {
            let external_config = ExternalConfig::try_from(ga);
            match external_config {
                Err(e) => error!("Failed to convert K8sGatewayAgent to ExternalConfig: {e}"),
                Ok(external_config) => {
                    let genid = external_config.genid;
                    let applied_genid = match client.get_generation().await {
                        Ok(genid) => genid,
                        Err(ConfigProcessorError::NoConfigApplied) => 0,
                        Err(e) => {
                            error!("Failed to get current config generation: {e}");
                            return;
                        }
                    };
                    if applied_genid == genid {
                        debug!("Not applying config, configuration generation unchanged (old={applied_genid}, new={genid})");
                        return;
                    }

                    let gwconfig = GwConfig::new(external_config);

                    // request the config processor to apply the config and update status on success
                    match client.apply_config(gwconfig).await {
                        Ok(()) => {
                            info!("Config for generation {genid} was successfully applied. Updating status...");
                            update_gateway_status(&hostname, &client).await;
                        },
                        Err(e) => error!("Failed to apply the config for generation {genid}: {e}"),
                    }
                }
            }
        })
        .await?;
        Err(K8sClientError::EarlyTermination)
    }

    pub async fn k8s_start_status_update(
        &self,
        client: ConfigClient,
        status_update_interval: &std::time::Duration,
    ) -> Result<(), K8sClientError> {
        loop {
            update_gateway_status(&self.hostname, &client).await;
            tokio::time::sleep(*status_update_interval).await;
        }
    }
}
