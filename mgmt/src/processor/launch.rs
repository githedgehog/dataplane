// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::processor::proc::ConfigChannelRequest;
use crate::processor::proc::ConfigProcessor;

use std::fmt::Display;
use std::io::Error;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::UnixListener;
use tokio::sync::mpsc::Sender;
use tokio::{io, spawn};
use tokio_stream::Stream;

use nat::stateless::NatTablesWriter;
use pkt_meta::dst_vni_lookup::VniTablesWriter;
use routing::ctl::RouterCtlSender;

use crate::grpc::server::create_config_service;
use tonic::transport::Server;

use stats::VpcMapName;
use tracing::{debug, error, info, warn};
use vpcmap::map::VpcMapWriter;

/// Start the gRPC server on TCP
async fn start_grpc_server_tcp(
    addr: SocketAddr,
    channel_tx: Sender<ConfigChannelRequest>,
) -> Result<(), Error> {
    info!("Starting gRPC server on TCP address: {addr}");
    let config_service = create_config_service(channel_tx);

    Server::builder()
        .add_service(config_service)
        .serve(addr)
        .await
        .map_err(|e| {
            error!("Failed to start gRPC server");
            Error::other(e.to_string())
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
    channel_tx: Sender<ConfigChannelRequest>,
) -> Result<(), Error> {
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
                return Err(e);
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
            return Err(e);
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
    let config_service = create_config_service(channel_tx);

    // Start the server with UNIX domain socket
    Server::builder()
        .add_service(config_service)
        .serve_with_incoming(acceptor)
        .await
        .map_err(|e| {
            error!("Failed to start gRPC server");
            Error::other(e.to_string())
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

/// Enum to represent either a TCP socket address or a UNIX socket path
#[derive(Debug, Clone)]
pub enum GrpcAddress {
    Tcp(SocketAddr),
    UnixSocket(PathBuf),
}

/// Start the mgmt service with either type of socket
pub fn start_mgmt(
    grpc_addr: GrpcAddress,
    router_ctl: RouterCtlSender,
    nattablew: NatTablesWriter,
    vnitablesw: VniTablesWriter,
    vpcmapw: VpcMapWriter<VpcMapName>,
) -> Result<std::thread::JoinHandle<()>, Error> {
    /* build server address from provided grpc address */
    let server_address = match grpc_addr {
        GrpcAddress::Tcp(addr) => ServerAddress::Tcp(addr),
        GrpcAddress::UnixSocket(path) => ServerAddress::Unix(path.to_path_buf()),
    };
    debug!("Will start gRPC listening on {server_address}");

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

            /* block thread to run gRPC and configuration processor */
            rt.block_on(async {
                let (processor, tx) =
                    ConfigProcessor::new(router_ctl, vpcmapw, nattablew, vnitablesw);
                spawn(async { processor.run().await });

                // Start the appropriate server based on address type
                let result = match server_address {
                    ServerAddress::Tcp(sock_addr) => start_grpc_server_tcp(sock_addr, tx).await,
                    ServerAddress::Unix(path) => start_grpc_server_unix(&path, tx).await,
                };
                if let Err(e) = result {
                    error!("Failed to start gRPC server: {e}");
                }
            });
        })
}
