// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The configuration processor

use crate::processor::k8s_client::{K8sClient, K8sClientError};
use crate::processor::k8s_less_client::{K8sLess, K8sLessError};
use crate::processor::proc::ConfigProcessor;

use crate::processor::proc::ConfigProcessorParams;
use concurrency::sync::Arc;
use tracing::{debug, error, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("IO error: {0}")]
    IoError(std::io::Error),
    #[error("Error in K8s client task: {0}")]
    K8sClientError(K8sClientError),
    #[error("Error starting/waiting for K8s client task: {0}")]
    K8sClientJoinError(tokio::task::JoinError),
    #[error("K8s client exited prematurely")]
    PrematureK8sClientExit,
    #[error("Config processor exited prematurely")]
    PrematureProcessorExit,

    #[error("Error in Config Processor task: {0}")]
    ProcessorError(std::io::Error),
    #[error("Error starting/waiting for Config Processor task: {0}")]
    ProcessorJoinError(tokio::task::JoinError),

    #[error("Error in k8s-less mode: {0}")]
    K8LessError(#[from] K8sLessError),
}

pub struct MgmtParams {
    pub config_dir: Option<String>,
    pub hostname: String,
    pub processor_params: ConfigProcessorParams,
}

use std::time::Duration;
const K8S_STATUS_UPD: Duration = Duration::from_secs(15);
const K8S_INIT_RETRY_TIME: Duration = Duration::from_secs(5);
const K8S_INIT_MAX_ATTEMPTS: u8 = 10;

async fn k8s_mgmt_init(k8s_client: &K8sClient) -> Result<(), K8sClientError> {
    let mut retries = K8S_INIT_MAX_ATTEMPTS;

    debug!("Initializing k8s client...");
    while let Err(e) = k8s_client.init().await {
        warn!("Could not initialize k8s state. Will retry {retries} more times");
        tokio::time::sleep(K8S_INIT_RETRY_TIME).await;
        if retries == 0 {
            error!("Maximum k8s initialization attempts reached. Giving up...");
            return Err(e);
        }
        retries -= 1;
    }
    info!("K8s initialization succeeded");
    Ok(())
}

/// Start the mgmt service. If the k8s interface is not ready, this may take up to
/// K8S_INIT_RETRY_TIME * K8S_INIT_MAX_ATTEMPTS seconds to complete.
pub fn start_mgmt(params: MgmtParams) -> Result<std::thread::JoinHandle<()>, LaunchError> {
    let (tx, rx) = tokio::sync::oneshot::channel();

    let handle = std::thread::Builder::new()
        .name("mgmt".to_string())
        .spawn(move || {
            debug!("Starting dataplane management thread");

            /* create tokio runtime */
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Tokio runtime creation failed");

            if let Some(config_dir) = &params.config_dir {
                warn!("Running in k8s-less mode....");
                rt.block_on(async {
                    let (processor, client) = ConfigProcessor::new(params.processor_params);
                    let k8sless =
                        Arc::new(K8sLess::new(params.hostname.as_str(), config_dir, client));
                    let k8sless1 = k8sless.clone();

                    let init_result = k8sless.init().await.map_err(LaunchError::K8LessError);
                    let init_failed = init_result.is_err();
                    tx.send(init_result).expect("Main thread gone");
                    if init_failed {
                        return;
                    }

                    tokio::spawn(async { processor.run().await });
                    tokio::spawn(async move { k8sless.start_status_update(&K8S_STATUS_UPD).await });
                    let _ = K8sLess::start_config_watch(k8sless1).await;
                })
            } else {
                debug!("Will start watching k8s for configuration changes");
                rt.block_on(async {
                    let (processor, client) = ConfigProcessor::new(params.processor_params);
                    let k8s_client = Arc::new(K8sClient::new(params.hostname.as_str(), client));
                    let k8s_client1 = k8s_client.clone();

                    let init_result = k8s_mgmt_init(&k8s_client)
                        .await
                        .map_err(LaunchError::K8sClientError);

                    let init_failed = init_result.is_err();
                    tx.send(init_result).expect("Main thread gone");
                    if init_failed {
                        return;
                    }

                    tokio::spawn(async { processor.run().await });
                    tokio::spawn(async move {
                        k8s_client1.k8s_start_status_update(&K8S_STATUS_UPD).await
                    });
                    let _ =
                        tokio::spawn(async { K8sClient::k8s_start_config_watch(k8s_client).await })
                            .await;
                })
            }
            unreachable!()
        })
        .map_err(LaunchError::IoError)?;

    match rx
        .blocking_recv()
        .map_err(|_| LaunchError::PrematureProcessorExit)?
    {
        Ok(()) => Ok(handle),
        Err(e) => Err(e),
    }
}
