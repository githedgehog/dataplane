// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use chrono::{TimeZone, Utc};
use config::GenId;
use config::converters::k8s::ToK8sConversionError;
use tokio::sync::mpsc::Sender;

use config::converters::k8s::status::dataplane_status::DataplaneStatusForK8sConversion;
use config::{ExternalConfig, GwConfig, internal::status::DataplaneStatus};
use k8s_intf::client::{PatchError, WatchError, patch_gateway_status, watch_gateway_agent_crd};
use k8s_intf::gateway_agent_crd::GatewayAgentStatus;
use tracing::{debug, error};

use crate::processor::proc::{ConfigChannelRequest, ConfigRequest, ConfigResponse};

#[derive(Debug, thiserror::Error)]
pub enum K8sClientError {
    #[error("K8s client exited early")]
    EarlyTermination,
    #[error("K8s watch failed: {0}")]
    WatchError(#[from] WatchError),
    #[error("Failed to convert dataplane status to k8s format: {0}")]
    StatusConversionError(#[from] ToK8sConversionError),
    #[error("Failed to patch k8s gateway status: {0}")]
    PatchStatusError(#[from] PatchError),
}

async fn get_dataplane_status(
    tx: &Sender<ConfigChannelRequest>,
) -> Result<DataplaneStatus, MgmtStatusError> {
    let (req, rx) = ConfigChannelRequest::new(ConfigRequest::GetDataplaneStatus);
    tx.send(req).await.map_err(|_| {
        MgmtStatusError::FetchStatusError("Failure relaying status fetch request".to_string())
    })?;
    let response = rx.await.map_err(|_| {
        MgmtStatusError::FetchStatusError(
            "Failure receiving status from config processor".to_string(),
        )
    })?;

    match response {
        ConfigResponse::GetDataplaneStatus(status) => Ok(*status),
        _ => unreachable!(),
    }
}

async fn get_current_config_generation(
    tx: &Sender<ConfigChannelRequest>,
) -> Result<GenId, MgmtStatusError> {
    let (req, rx) = ConfigChannelRequest::new(ConfigRequest::GetGeneration);
    tx.send(req).await.map_err(|_| {
        MgmtStatusError::FetchStatusError("Failure relaying get generation request".to_string())
    })?;
    let response = rx.await.map_err(|_| {
        MgmtStatusError::FetchStatusError(
            "Failure receiving config generation from processor".to_string(),
        )
    })?;
    match response {
        ConfigResponse::GetGeneration(opt_genid) => {
            opt_genid.ok_or(MgmtStatusError::NoConfigApplied)
        }
        _ => unreachable!(),
    }
}

#[derive(Debug, thiserror::Error)]
enum MgmtStatusError {
    #[error("Failed to fetch dataplane status: {0}")]
    FetchStatusError(String),
    #[error("No config is currently applied")]
    NoConfigApplied,
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
        patch_gateway_status(
            &self.hostname,
            &GatewayAgentStatus {
                agent_version: Some("(none: agentless)".to_string()),
                last_applied_gen: Some(0),
                last_applied_time: Some(
                    Utc.timestamp_opt(0, 0)
                        .unwrap()
                        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                ),
                state: None,
            },
        )
        .await?;
        Ok(())
    }

    pub async fn k8s_start_config_watch(
        &self,
        tx: Sender<ConfigChannelRequest>,
    ) -> Result<(), K8sClientError> {
        // Clone this here so that the closure does not try to borrow self
        // and cause K8sClient to not be Send for 'static but only a specific
        // lifetime
        let hostname = self.hostname.clone();
        watch_gateway_agent_crd(&hostname.clone(), async move |ga| {
            let external_config = ExternalConfig::try_from(ga);
            match external_config {
                Ok(external_config) => {
                    let genid = external_config.genid;
                    let current_genid = match get_current_config_generation(&tx).await {
                        Ok(id) => id,
                        Err(e) => match e {
                            MgmtStatusError::NoConfigApplied => 0,
                            _ => {
                                error!("Failed to get current config generation: {e}");
                                return;
                            }
                        }
                    };
                    if current_genid == genid {
                        debug!("Not applying config, configuration generation unchanged (old={current_genid}, new={genid})");
                        return;
                    }

                    let gw_config = Box::new(GwConfig::new(external_config));

                    let (req, rx) =
                        ConfigChannelRequest::new(ConfigRequest::ApplyConfig(gw_config));
                    let tx_result = tx.send(req).await;
                    if let Err(e) = tx_result {
                        error!("Failure sending request to config processor: {e}");
                    }
                    match rx.await {
                        Err(e) => error!("Failure receiving from config processor: {e}"),
                        Ok(response) => match response {
                            ConfigResponse::ApplyConfig(Err(e)) => {
                                error!("Failed to apply config: {e}");
                            }
                            ConfigResponse::ApplyConfig(Ok(())) => {
                                let last_applied_time = Some(chrono::Utc::now());
                                let k8s_status = match GatewayAgentStatus::try_from(
                                    &DataplaneStatusForK8sConversion {
                                        last_applied_gen: Some(genid),
                                        last_applied_time: last_applied_time.as_ref(),
                                        last_collected_time: None,
                                        status: None,
                                    },
                                ) {
                                    Ok(v) => Some(v),
                                    Err(e) => {
                                        error!("Unable to build object to patch k8s status with applied generation: {e}");
                                        None
                                    }
                                };

                                if let Some(k8s_status) = k8s_status {
                                    match patch_gateway_status(&hostname, &k8s_status).await {
                                        Ok(()) => {},
                                        Err(e) => {error!("Unable to patch k8s last_applied_gen and timestamp: {e}"); }
                                    }
                                }
                            }
                            _ => unreachable!(),
                        },
                    };
                }
                Err(e) => {
                    error!("Failed to convert K8sGatewayAgent to ExternalConfig: {e}");
                }
            }
        })
        .await?;
        Err(K8sClientError::EarlyTermination)
    }

    pub async fn k8s_start_status_update(
        &self,
        tx: Sender<ConfigChannelRequest>,
        status_update_interval: &std::time::Duration,
    ) -> Result<(), K8sClientError> {
        // Clone this here so that the closure does not try to borrow self
        // and cause K8sClient to not be Send for 'static but only a specific
        // lifetime
        let hostname = self.hostname.clone();
        loop {
            let status = get_dataplane_status(&tx).await;

            let status = match status {
                Ok(status) => status,
                Err(err) => {
                    error!("Failed to fetch dataplane status: {}", err);
                    continue;
                }
            };

            let k8s_status = GatewayAgentStatus::try_from(&DataplaneStatusForK8sConversion {
                last_applied_gen: None,
                last_applied_time: None,
                last_collected_time: Some(&chrono::Utc::now()),
                status: Some(&status),
            })?;
            patch_gateway_status(&hostname, &k8s_status).await?;

            // Process status update
            tokio::time::sleep(*status_update_interval).await;
        }
    }
}
