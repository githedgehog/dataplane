// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use futures::{StreamExt, TryStreamExt};
use kube::api::PostParams;
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client};

use tracectl::trace_target;
use tracing::{error, info};

use crate::gateway_agent_crd::{GW_API_VERSION, GatewayAgent, GatewayAgentStatus};

trace_target!("k8s-client", LevelFilter::INFO, &["management"]);

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("Client error: {0}")]
    ClientError(#[from] kube::Error),
    #[error("Watcher error: {0}")]
    WatcherError(#[from] kube::runtime::watcher::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ReplaceStatusError {
    #[error("Client error: {0}")]
    ClientError(#[from] kube::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Max conflict retries exceeded")]
    MaxConflictRetriesExceeded,
}

/// Watch `GatewayAgent` CRD and call callback for all changes
///
/// # Errors
/// Returns an error if the watch fails to start
pub async fn watch_gateway_agent_crd(
    gateway_object_name: &str,
    callback: impl AsyncFn(&GatewayAgent),
) -> Result<(), WatchError> {
    let client = Client::try_default().await?;
    // Relevant gateway agent objects are in the "fab" namespace
    let gws: Api<GatewayAgent> = Api::namespaced(client.clone(), "fab");

    info!(
        "Starting K8s GatewayAgent watcher. GW_API_VERSION = {}",
        GW_API_VERSION.unwrap_or("EXPERIMENTAL")
    );

    let watch_config = watcher::Config {
        // The service account for this gateway only has access to its corresponding
        // gateway agent object, so specifically filter for that to avoid an auth error
        // and to not apply incorrect configurations intended for other gateways
        field_selector: Some(format!("metadata.name={gateway_object_name}")),
        // The default initial list strategy attempts to list all gateway objects via the k8s
        // api and then filters them locally.  But, the service account for this gateway does
        // not have permission to list all gateway objects.  Instead, we use the streaming list
        // initial list strategy which directly calls the k8s watch api with the appropriate
        // watch config that includes the field selector.
        initial_list_strategy: watcher::InitialListStrategy::StreamingList,
        ..Default::default()
    };
    let mut stream = watcher(gws, watch_config)
        .default_backoff()
        .applied_objects()
        .boxed();

    loop {
        match stream.try_next().await {
            Ok(Some(ga)) => callback(&ga).await,
            Ok(None) => {}
            // Should we check for retriable vs non-retriable errors here?
            Err(err) => {
                error!("Watcher error: {err}");
            }
        }
    }
}

const NUM_CONFLICT_RETRIES: usize = 3;

/// Patch `GatewayAgent` object with current status
///
/// # Errors
/// Returns an error if the patch request fails.
pub async fn replace_gateway_status(
    gateway_object_name: &str,
    status: &GatewayAgentStatus,
) -> Result<(), ReplaceStatusError> {
    let client = Client::try_default().await?;
    let api: Api<GatewayAgent> = Api::namespaced(client.clone(), "fab");

    for attempt_num in 0..NUM_CONFLICT_RETRIES {
        let mut status_obj = api.get_status(gateway_object_name).await?;
        status_obj.status = Some(status.clone());

        match api
            .replace_status(gateway_object_name, &PostParams::default(), &status_obj)
            .await
        {
            Ok(_) => break,
            Err(kube::Error::Api(api_error)) => {
                if api_error.code == 409 {
                    if attempt_num < NUM_CONFLICT_RETRIES - 1 {
                        continue; // Try again, resource version conflict
                    }
                    return Err(ReplaceStatusError::MaxConflictRetriesExceeded);
                }
                return Err(kube::Error::Api(api_error).into());
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    Ok(())
}
