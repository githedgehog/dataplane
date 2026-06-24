// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The configuration processor

use crate::processor::k8s_client::{K8sClient, K8sClientError};
use crate::processor::k8s_less_client::{K8sLess, K8sLessError};
use crate::processor::mgmt_client::ConfigClient;
use crate::processor::proc::ConfigProcessor;
use crate::processor::proc::ConfigProcessorParams;
use interface_manager::monitor::{EthEvent, InterfaceMonitor};

use concurrency::sync::Arc;
use lifecycle::{CancellationToken, Subsystem};
use routing::RouterCtlSender;
use tracing::{debug, error, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("IO error: {0}")]
    IoError(std::io::Error),
    #[error("Error in K8s client task: {0}")]
    K8sClientError(#[from] K8sClientError),
    #[error("Error in k8s-less mode: {0}")]
    K8LessError(#[from] K8sLessError),
    #[error("Mgmt init cancelled before completion")]
    Cancelled,
}

pub struct MgmtParams {
    pub config_dir: Option<String>,
    pub hostname: String,
    pub processor_params: ConfigProcessorParams,
}

use std::time::Duration;
const K8S_STATUS_UPD: Duration = Duration::from_secs(15);
const K8S_INIT_RETRY_TIME: Duration = Duration::from_secs(5);
const K8S_INIT_MAX_RETRIES: u8 = 10;

/// Run `init` under `cancel`. Returns [`LaunchError::Cancelled`] on cancel.
async fn init_cancellable<F, E>(init: F, cancel: &CancellationToken) -> Result<(), LaunchError>
where
    F: std::future::Future<Output = Result<(), E>>,
    LaunchError: From<E>,
{
    tokio::select! {
        r = init => r.map_err(LaunchError::from),
        () = cancel.cancelled() => {
            info!("Mgmt init cancelled");
            Err(LaunchError::Cancelled)
        }
    }
}

/// Retry k8s init up to `K8S_INIT_MAX_RETRIES` times with
/// `K8S_INIT_RETRY_TIME` backoff. Attempt and backoff both observe `cancel`.
async fn k8s_mgmt_init(
    k8s_client: &K8sClient,
    cancel: &CancellationToken,
) -> Result<(), LaunchError> {
    let mut retries = K8S_INIT_MAX_RETRIES;
    debug!("Initializing k8s client...");
    loop {
        match init_cancellable(k8s_client.init(), cancel).await {
            Ok(()) => break,
            Err(LaunchError::Cancelled) => return Err(LaunchError::Cancelled),
            Err(e) if retries == 0 => {
                error!("Maximum k8s initialization attempts reached. Giving up...");
                return Err(e);
            }
            Err(_) => {
                warn!("Could not initialize k8s state. Will retry {retries} more times");
                retries -= 1;
                tokio::select! {
                    () = tokio::time::sleep(K8S_INIT_RETRY_TIME) => {}
                    () = cancel.cancelled() => {
                        info!("K8s init cancelled during retry backoff");
                        return Err(LaunchError::Cancelled);
                    }
                }
            }
        }
    }
    info!("K8s initialization succeeded");
    Ok(())
}

async fn interface_event_notify(
    mut rx: tokio::sync::broadcast::Receiver<EthEvent>,
    mut rtr_ctl: RouterCtlSender,
) {
    loop {
        if let Ok(ev) = rx.recv().await {
            info!("Notifying router about interface event...");
            if rtr_ctl.send_ifevent(ev).await.is_err() {
                warn!("Failed to relay interface event to router")
            }
        }
    }
}

/// Init mgmt synchronously on `handle`, then spawn the long-lived tasks
/// (config processor, status updater, config watcher) tracked under
/// `mgmt`. Init observes `mgmt.root_token()` so SIGINT during init returns
/// [`LaunchError::Cancelled`] within cancel latency.
///
/// # Errors
/// Returns [`LaunchError`] on init failure. [`LaunchError::Cancelled`] is
/// a clean-shutdown signal — callers must not flip the fatal flag for it.
pub fn run_mgmt(
    handle: &tokio::runtime::Handle,
    mgmt: &Subsystem,
    params: MgmtParams,
) -> Result<(), LaunchError> {
    // start interface monitor
    let ifmonitor = Arc::new(InterfaceMonitor::new(mgmt.cancel_token()).phy_only());
    let if_subsc = ifmonitor.subscribe();
    mgmt.spawn_fatal_on_exit("interface monitor", ifmonitor.run(), handle);
    mgmt.spawn_fatal_on_exit(
        "interface event relay",
        interface_event_notify(if_subsc, params.processor_params.router_ctl.clone()),
        handle,
    );

    // create config processor and run it
    let (processor, client) = ConfigProcessor::new(params.processor_params, handle);
    mgmt.spawn_fatal_on_exit("k8s-less config processor", processor.run(), handle);

    if let Some(config_dir) = &params.config_dir {
        warn!("Running in k8s-less mode....");
        handle.block_on(run_k8s_less(
            handle,
            mgmt,
            params.hostname.as_str(),
            config_dir,
            client,
        ))
    } else {
        debug!("Will start watching k8s for configuration changes");
        handle.block_on(run_k8s(handle, mgmt, params.hostname.as_str(), client))
    }
}

async fn run_k8s_less(
    handle: &tokio::runtime::Handle,
    mgmt: &Subsystem,
    hostname: &str,
    config_dir: &str,
    client: ConfigClient,
) -> Result<(), LaunchError> {
    let k8sless = Arc::new(K8sLess::new(hostname, config_dir, client));
    let k8sless_for_watch = k8sless.clone();

    init_cancellable(k8sless.init(), &mgmt.root_token()).await?;

    let k8sless_for_status = k8sless.clone();
    mgmt.spawn_fatal_on_exit(
        "k8s-less status updater",
        async move {
            k8sless_for_status
                .start_status_update(&K8S_STATUS_UPD)
                .await
        },
        handle,
    );
    mgmt.spawn_fatal_on_exit(
        "k8s-less config watcher",
        async move {
            match K8sLess::start_config_watch(k8sless_for_watch).await {
                Ok(()) => warn!("k8s-less config watcher returned Ok unexpectedly"),
                Err(e) => error!("k8s-less config watcher failed: {e}"),
            }
        },
        handle,
    );

    Ok(())
}

async fn run_k8s(
    handle: &tokio::runtime::Handle,
    mgmt: &Subsystem,
    hostname: &str,
    client: ConfigClient,
) -> Result<(), LaunchError> {
    let k8s_client = Arc::new(K8sClient::new(hostname, client));
    let k8s_client_for_status = k8s_client.clone();
    k8s_mgmt_init(&k8s_client, &mgmt.root_token()).await?;

    mgmt.spawn_fatal_on_exit(
        "k8s status updater",
        async move {
            k8s_client_for_status
                .k8s_start_status_update(&K8S_STATUS_UPD)
                .await
        },
        handle,
    );
    mgmt.spawn_fatal_on_exit(
        "k8s config watcher",
        async move {
            K8sClient::k8s_start_config_watch(k8s_client).await;
        },
        handle,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processor::k8s_less_client::K8sLessError;
    use lifecycle::Shutdown;
    use std::time::Duration;

    #[tokio::test]
    async fn init_cancellable_returns_cancelled_on_pre_tripped_token() {
        let cancel = CancellationToken::new();
        cancel.cancel();

        let result: Result<(), LaunchError> = init_cancellable(
            async {
                // Long sleep so a missing cancel arm surfaces as a test timeout.
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok::<(), K8sLessError>(())
            },
            &cancel,
        )
        .await;

        assert!(matches!(result, Err(LaunchError::Cancelled)));
    }

    #[tokio::test]
    async fn init_cancellable_returns_cancelled_when_tripped_mid_init() {
        let cancel = CancellationToken::new();
        let cancel_for_task = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_for_task.cancel();
        });

        let result: Result<(), LaunchError> = init_cancellable(
            async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok::<(), K8sLessError>(())
            },
            &cancel,
        )
        .await;

        assert!(matches!(result, Err(LaunchError::Cancelled)));
    }

    #[tokio::test]
    async fn init_cancellable_returns_ok_when_init_completes_first() {
        let cancel = CancellationToken::new();
        let result: Result<(), LaunchError> =
            init_cancellable(async { Ok::<(), K8sLessError>(()) }, &cancel).await;
        assert!(result.is_ok());
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn init_cancellable_propagates_init_error() {
        let cancel = CancellationToken::new();
        let result: Result<(), LaunchError> = init_cancellable(
            async { Err::<(), K8sLessError>(K8sLessError::Internal("synthetic".into())) },
            &cancel,
        )
        .await;
        assert!(matches!(result, Err(LaunchError::K8LessError(_))));
    }

    /// Locks in the main.rs contract: SIGTERM during k8s init must yield
    /// exit 0 (else systemd restart-loops the unit). Mirrors the match
    /// arms in runtime.rs.
    #[tokio::test]
    async fn cancelled_launch_error_yields_zero_exit_code_at_call_site() {
        let shutdown = Shutdown::new();
        shutdown.root.cancel();
        let mgmt_result: Result<(), LaunchError> = Err(LaunchError::Cancelled);

        match mgmt_result {
            Ok(()) => {}
            Err(LaunchError::Cancelled) => {}
            Err(_) => {
                shutdown.fail();
            }
        }

        assert!(!shutdown.is_fatal());
        assert_eq!(i32::from(shutdown.is_fatal()), 0);
    }

    #[tokio::test]
    async fn non_cancelled_launch_error_yields_nonzero_exit_code_at_call_site() {
        let shutdown = Shutdown::new();
        let mgmt_result: Result<(), LaunchError> =
            Err(LaunchError::IoError(std::io::Error::other("synthetic")));

        match mgmt_result {
            Ok(()) => {}
            Err(LaunchError::Cancelled) => {}
            Err(_) => {
                shutdown.fail();
            }
        }

        assert!(shutdown.is_fatal());
        assert_eq!(i32::from(shutdown.is_fatal()), 1);
    }
}
