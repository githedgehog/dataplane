// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The configuration processor

use crate::processor::k8s_client::{K8sClient, K8sClientError};
use crate::processor::k8s_less_client::{K8sLess, K8sLessError};
use crate::processor::proc::ConfigProcessor;

use concurrency::sync::Arc;
use futures::future::OptionFuture;
use tracing::{debug, error, warn};

use crate::processor::proc::ConfigProcessorParams;

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

const STATUS_UPDATE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Start the mgmt service with either type of socket
pub fn start_mgmt(
    params: MgmtParams,
) -> Result<std::thread::JoinHandle<Result<(), LaunchError>>, std::io::Error> {
    std::thread::Builder::new()
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
                    let k8sless = Arc::new(K8sLess::new(config_dir, client));
                    tokio::spawn(async { processor.run().await });
                    K8sLess::start_config_watch(k8sless).await
                })?;
                Ok(())
            }
            else {
                debug!("Will start watching k8s for configuration changes");
                rt.block_on(async {
                    let (processor, client) = ConfigProcessor::new(params.processor_params);
                    let k8s_client = Arc::new(K8sClient::new(params.hostname.as_str(), client));
                    let k8s_client1 = k8s_client.clone();

                    k8s_client.init().await.map_err(|e| {
                        error!("Failed to initialize k8s state: {}", e);
                        LaunchError::K8sClientError(e)
                    })?;
                    let mut processor_handle = Some(tokio::spawn(async { processor.run().await }));
                    let mut k8s_config_handle = Some(tokio::spawn(async move { K8sClient::k8s_start_config_watch(k8s_client).await }));
                    let mut k8s_status_handle = Some(tokio::spawn(async move {
                        k8s_client1.k8s_start_status_update(&STATUS_UPDATE_INTERVAL).await
                    }));
                    loop {
                        tokio::select! {
                            Some(result) = OptionFuture::from(processor_handle.as_mut()) => {
                                match result {
                                    Ok(_) => {
                                        error!("Configuration processor task exited unexpectedly");
                                        Err(LaunchError::PrematureProcessorExit)?
                                    }
                                    Err(e) => { Err::<(), LaunchError>(LaunchError::ProcessorJoinError(e)) }
                                }
                            }
                            Some(result) = OptionFuture::from(k8s_config_handle.as_mut()) => {
                                match result {
                                    Ok(result) => { result.inspect_err(|e| error!("K8s config watch task failed: {e}")).map_err(LaunchError::K8sClientError)?;
                                        error!("Kubernetes config watch task exited unexpectedly");
                                        Err(LaunchError::PrematureK8sClientExit)?
                                    }
                                    Err(e) => { Err(LaunchError::K8sClientJoinError(e))? }
                                }
                            }
                            Some(result) = OptionFuture::from(k8s_status_handle.as_mut()) => {
                                k8s_status_handle = None;
                                match result {
                                    Ok(result) => { result.inspect_err(|e| error!("K8s status update task failed: {e}")).map_err(LaunchError::K8sClientError)?;
                                        error!("Kubernetes status update task exited unexpectedly");
                                        Err(LaunchError::PrematureK8sClientExit)?
                                    }
                                    Err(e) => { Err(LaunchError::K8sClientJoinError(e))? }
                                }
                            }
                        }?;

                        if processor_handle.is_none() && k8s_config_handle.is_none() && k8s_status_handle.is_none() {
                            break;
                        }
                    }
                    Ok(())
                })
            }
        })
}
