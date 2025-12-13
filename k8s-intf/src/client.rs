// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use futures::{StreamExt, TryStreamExt};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client};

use tracectl::trace_target;
use tracing::{error, info};

use crate::gateway_agent_crd::GatewayAgent;

trace_target!("k8s-client", LevelFilter::INFO, &["management"]);

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("Client error: {0}")]
    ClientError(#[from] kube::Error),
    #[error("Watcher error: {0}")]
    WatcherError(#[from] kube::runtime::watcher::Error),
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

    info!("Starting K8s GatewayAgent watcher...");

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
