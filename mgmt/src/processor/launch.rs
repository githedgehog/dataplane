// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::processor::k8s_client::{K8sClient, K8sClientError};
use crate::processor::proc::ConfigProcessor;

use std::fmt::Display;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io;
use tokio::net::UnixListener;
use tokio_stream::Stream;
use tonic::transport::Server;

use futures::future::OptionFuture;

use args::GrpcAddress;
use concurrency::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::grpc::server::create_config_service;
use crate::processor::mgmt_client::ConfigClient;
use crate::processor::proc::ConfigProcessorParams;

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("GRPC server error: {0}")]
    GrpcServerError(tonic::transport::Error),
    #[error("IO error: {0}")]
    IoError(std::io::Error),
    #[error("Error in K8s client task: {0}")]
    K8sClientError(K8sClientError),
    #[error("Error starting/waiting for K8s client task: {0}")]
    K8sClientJoinError(tokio::task::JoinError),
    #[error("K8s client exited prematurely")]
    PrematureK8sClientExit,
    #[error("Grpc server exited prematurely")]
    PrematureGrpcExit,
    #[error("Config processor exited prematurely")]
    PrematureProcessorExit,

    #[error("Error in Config Processor task: {0}")]
    ProcessorError(std::io::Error),
    #[error("Error starting/waiting for Config Processor task: {0}")]
    ProcessorJoinError(tokio::task::JoinError),
}

/// Start the gRPC server on TCP
async fn start_grpc_server_tcp(addr: SocketAddr, client: ConfigClient) -> Result<(), LaunchError> {
    info!("Starting gRPC server on TCP address: {addr}");
    let config_service = create_config_service(client);

    Server::builder()
        .add_service(config_service)
        .serve(addr)
        .await
        .map_err(|e| {
            error!("Failed to start gRPC server");
            LaunchError::GrpcServerError(e)
        })
}

/// UnixListener wrapper type to implement tokyo Stream trait
/// This is only used/needed when we bind gRPC to a Unix socket
struct UnixAcceptor {
    listener: UnixListener,
}

// Implementation of the Stream trait for UnixAcceptor
impl Stream for UnixAcceptor {
    type Item = Result<tokio::net::UnixStream, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = unsafe { self.get_unchecked_mut() };
        match this.listener.poll_accept(cx) {
            Poll::Ready(Ok((stream, addr))) => {
                debug!("Accepted connection on gRPC unix socket from {addr:?}");
                Poll::Ready(Some(Ok(stream)))
            }
            Poll::Ready(Err(e)) => {
                warn!("Error accepting connection on gRPC unix sock: {e}");
                Poll::Ready(Some(Err(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Start the gRPC server on UNIX socket
async fn start_grpc_server_unix(
    socket_path: &Path,
    client: ConfigClient,
) -> Result<(), LaunchError> {
    info!(
        "Starting gRPC server on UNIX socket: {}",
        socket_path.display()
    );

    // Remove existing socket file if present
    #[allow(clippy::collapsible_if)]
    if socket_path.exists() {
        if let Err(e) = std::fs::remove_file(socket_path) {
            warn!("Failed to remove existing socket file: {e}");
        }
    }

    // Create parent directory if it doesn't exist
    #[allow(clippy::collapsible_if)]
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                error!("Failed to create parent directory: {e}");
                return Err(LaunchError::IoError(e));
            }
        }
    }

    // Create the UNIX socket listener
    let listener = match UnixListener::bind(socket_path) {
        Ok(listener) => {
            debug!("Bound unix sock to {}", socket_path.display());
            listener
        }
        Err(e) => {
            error!("Failed to bind UNIX socket: {e}");
            return Err(LaunchError::IoError(e));
        }
    };

    // Set socket permissions if needed
    match std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666)) {
        Ok(_) => debug!("Socket permissions set to 0666"),
        Err(e) => error!("Failed to set socket permissions: {e}"),
    }

    // Build Unix acceptor wrapper to asynchronously accept connections inside the server
    let acceptor = UnixAcceptor { listener };

    // Create the gRPC service
    let config_service = create_config_service(client);

    // Start the server with UNIX domain socket
    Server::builder()
        .add_service(config_service)
        .serve_with_incoming(acceptor)
        .await
        .map_err(|e| {
            error!("Failed to start gRPC server");
            LaunchError::GrpcServerError(e)
        })?;

    // Clean up the socket file after server shutdown
    #[allow(clippy::collapsible_if)]
    if socket_path.exists() {
        if let Err(e) = std::fs::remove_file(socket_path) {
            error!("Failed to remove socket file: {e}");
        }
    }
    Ok(())
}

/// Enum for the different types of server addresses
#[derive(Debug)]
enum ServerAddress {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Display for ServerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerAddress::Tcp(addr) => write!(f, "tcp:{addr}"),
            ServerAddress::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

pub struct MgmtParams {
    pub grpc_addr: Option<GrpcAddress>,
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

            if let Some(grpc_addr) = params.grpc_addr {
                /* build server address from provided grpc address */
                let server_address = match grpc_addr {
                    GrpcAddress::Tcp(addr) => ServerAddress::Tcp(addr),
                    GrpcAddress::UnixSocket(path) => ServerAddress::Unix(path.into()),
                };
                debug!("Will start gRPC listening on {server_address}");

                /* block thread to run gRPC and configuration processor */
                rt.block_on(async {
                    let (processor, client) = ConfigProcessor::new(params.processor_params);
                    tokio::spawn(async { processor.run().await });

                    // Start the appropriate server based on address type
                    let result = match server_address {
                        ServerAddress::Tcp(sock_addr) => start_grpc_server_tcp(sock_addr, client).await,
                        ServerAddress::Unix(path) => start_grpc_server_unix(&path, client).await,
                    };
                    if let Err(e) = result {
                        error!("Failed to start gRPC server: {e}");
                        Err(e)
                    } else {
                        error!("GRPC server exited prematurely");
                        Err(LaunchError::PrematureGrpcExit)
                    }
                })
            } else {
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
