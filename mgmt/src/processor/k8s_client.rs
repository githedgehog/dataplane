// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use tokio::sync::mpsc::Sender;

use config::{ExternalConfig, GwConfig};
use k8s_intf::client::WatchError;
use k8s_intf::watch_gateway_agent_crd;
use tracing::error;

use crate::processor::proc::{ConfigChannelRequest, ConfigRequest, ConfigResponse};

#[derive(Debug, thiserror::Error)]
pub enum K8sClientError {
    #[error("K8s client exited early")]
    EarlyTermination,
    #[error("K8s client could not get hostname: {0}")]
    HostnameError(#[from] std::io::Error),
    #[error("K8s watch failed: {0}")]
    WatchError(#[from] WatchError),
}

pub async fn k8s_start_client(
    hostname: &str,
    tx: Sender<ConfigChannelRequest>,
) -> Result<(), K8sClientError> {
    watch_gateway_agent_crd(hostname, async move |ga| {
        let external_config = ExternalConfig::try_from(ga);
        match external_config {
            Ok(external_config) => {
                let gw_config = Box::new(GwConfig::new(external_config));

                let (req, rx) = ConfigChannelRequest::new(ConfigRequest::ApplyConfig(gw_config));
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
                        ConfigResponse::ApplyConfig(Ok(())) => {}
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
