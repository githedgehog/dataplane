// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::fmt::Display;
use std::io::Error;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io;
use tokio::net::UnixListener;
use tokio::spawn;

use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
use tokio_stream::Stream;

use tonic::transport::Server;

use hyper::server::accept::Accept;

use crate::grpc::server::create_config_service;
use crate::models::external::gwconfig::{ExternalConfig, GwConfig};
use crate::models::external::{ConfigError, ConfigResult, stringify};

use crate::models::internal::InternalConfig;

use crate::frr::frrmi::FrrMi;
use crate::processor::gwconfigdb::GwConfigDatabase;
use crate::{frr::renderer::builder::Render, models::external::gwconfig::GenId};

use crate::vpc_manager::{RequiredInformationBase, VpcManager};
use rekon::{Observe, Reconcile};
use tracing::{debug, error, info, warn};

/// A request type to the [`ConfigProcessor`]
#[derive(Debug)]
pub enum ConfigRequest {
    ApplyConfig(Box<GwConfig>),
    GetCurrentConfig,
    GetGeneration,
}

/// A response from the [`ConfigProcessor`]
#[derive(Debug)]
pub enum ConfigResponse {
    ApplyConfig(ConfigResult),
    GetCurrentConfig(Box<Option<GwConfig>>),
    GetGeneration(Option<GenId>),
}
type ConfigResponseChannel = oneshot::Sender<ConfigResponse>;

/// A type that includes a request to the [`ConfigProcessor`] and a channel to
/// issue the response back
pub struct ConfigChannelRequest {
    request: ConfigRequest,          /* a request to the mgmt processor */
    reply_tx: ConfigResponseChannel, /* the one-shot channel to respond */
}
impl ConfigChannelRequest {
    #[must_use]
    pub fn new(request: ConfigRequest) -> (Self, Receiver<ConfigResponse>) {
        let (reply_tx, reply_rx) = oneshot::channel();
        let request = Self { request, reply_tx };
        (request, reply_rx)
    }
}

/// A configuration processor entity. This is the RPC-independent entity responsible for
/// accepting/rejecting configurations, storing them in the configuration database and
/// applying them.
pub(crate) struct ConfigProcessor {
    config_db: GwConfigDatabase,
    rx: mpsc::Receiver<ConfigChannelRequest>,
    frrmi: FrrMi,
    netlink: Arc<rtnetlink::Handle>,
}

impl ConfigProcessor {
    const CHANNEL_SIZE: usize = 1; // process one at a time

    /// Create a [`ConfigProcessor`]
    pub(crate) fn new(frrmi: FrrMi) -> (Self, Sender<ConfigChannelRequest>) {
        debug!("Creating config processor...");
        let (tx, rx) = mpsc::channel(Self::CHANNEL_SIZE);

        let Ok((connection, netlink, _)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        spawn(connection);
        let netlink = Arc::new(netlink);

        let processor = Self {
            config_db: GwConfigDatabase::new(),
            rx,
            frrmi,
            netlink,
        };
        (processor, tx)
    }

    /// Main entry point for new configurations. When invoked, this method:
    ///   * forbids the addition of a config if a config with same id exists
    ///   * validates the incoming config
    ///   * builds an internal config for it
    ///   * stores the config in the config database
    ///   * applies the config
    pub(crate) async fn process_incoming_config(&mut self, mut config: GwConfig) -> ConfigResult {
        /* get id of incoming config */
        let genid = config.genid();

        /* reject config if it uses id of existing one */
        if genid != ExternalConfig::BLANK_GENID && self.config_db.contains(genid) {
            error!("Rejecting config request: a config with id {genid} exists");
            return Err(ConfigError::ConfigAlreadyExists(genid));
        }

        /* validate the config */
        config.validate()?;

        /* build internal config for this config */
        config.build_internal_config()?;

        /* add to config database */
        self.config_db.add(config);

        /* apply the configuration just stored */
        self.config_db
            .apply(genid, &mut self.frrmi, self.netlink.clone())
            .await?;

        Ok(())
    }

    /// Method to apply a blank configuration
    async fn apply_blank_config(&mut self) -> ConfigResult {
        self.config_db
            .apply(
                ExternalConfig::BLANK_GENID,
                &mut self.frrmi,
                self.netlink.clone(),
            )
            .await
    }

    /// RPC handler to apply a config
    async fn handle_apply_config(&mut self, config: GwConfig) -> ConfigResponse {
        let genid = config.genid();
        debug!("━━━━━━ Handling apply configuration request. Genid {genid} ━━━━━━");
        let result = self.process_incoming_config(config).await;
        debug!(
            "━━━━━━ Completed configuration for Genid {genid}: {} ━━━━━━",
            stringify(&result)
        );
        ConfigResponse::ApplyConfig(result)
    }

    /// RPC handler to get current config generation id
    fn handle_get_generation(&self) -> ConfigResponse {
        debug!("Handling get generation request");
        ConfigResponse::GetGeneration(self.config_db.get_current_gen())
    }

    /// RPC handler to get the currently applied config
    fn handle_get_config(&self) -> ConfigResponse {
        debug!("Handling get running configuration request");
        let cfg = Box::new(self.config_db.get_current_config().cloned());
        ConfigResponse::GetCurrentConfig(cfg)
    }

    /// Run the configuration processor
    #[allow(unreachable_code)]
    async fn run(mut self) {
        info!("Starting config processor...");

        // apply initial blank config: we may want to remove this to handle the case
        // where dataplane is restarted and we don't want to flush the state of the system.
        if let Err(e) = self.apply_blank_config().await {
            warn!("Failed to apply blank config!: {e}");
        }

        loop {
            // receive config requests over channel
            match self.rx.recv().await {
                Some(req) => {
                    let response = match req.request {
                        ConfigRequest::ApplyConfig(config) => {
                            self.handle_apply_config(*config).await
                        }
                        ConfigRequest::GetCurrentConfig => self.handle_get_config(),
                        ConfigRequest::GetGeneration => self.handle_get_generation(),
                    };
                    if req.reply_tx.send(response).is_err() {
                        warn!("Failed to send reply from config processor: receiver dropped?");
                    }
                }
                None => {
                    warn!("Channel to config processor was closed!");
                }
            }
        }
    }
}

/// Apply config using VPC manager
async fn apply_config_vpc_manager(
    netlink: Arc<rtnetlink::Handle>,
    internal: &InternalConfig,
    genid: GenId,
) -> ConfigResult {
    let mut rib: RequiredInformationBase = match internal.try_into() {
        Ok(rib) => rib,
        Err(err) => {
            let msg = format!("Couldn't build required information base: {err}");
            error!("{msg}");
            return Err(ConfigError::FailureApply(msg));
        }
    };

    debug!("Required information base for genid {genid} is:\n{rib:?}");

    let manager = VpcManager::<RequiredInformationBase>::new(netlink);
    let mut required_passes = 0;
    while !manager
        .reconcile(&mut rib, &manager.observe().await.unwrap())
        .await
    {
        required_passes += 1;
        if required_passes >= 300 {
            let msg = "Interface reconciliation not achieved after 300 passes".to_string();
            error!("{msg}");
            return Err(ConfigError::FailureApply(msg));
        }
    }
    debug!("VPC-manager successfully applied config for genid {genid}");
    Ok(())
}

/// Apply config over frrmi with frr-agent
async fn apply_config_frr(
    frrmi: &mut FrrMi,
    config: &GwConfig,
    internal: &InternalConfig,
) -> ConfigResult {
    let genid = config.genid();

    debug!("Generating FRR config for genid {genid}...");

    let rendered = internal.render(config);
    debug!("FRR configuration is:\n{}", rendered.to_string());

    frrmi
        .apply_config(config.genid(), &rendered)
        .await
        .map_err(|e| ConfigError::FailureApply(format!("Error applying FRR config: {e}")))?;

    debug!("FRR config for genid {genid} successfully applied");
    Ok(())
}

pub async fn apply_gw_config(
    config: &mut GwConfig,
    frrmi: &mut FrrMi,
    netlink: Arc<rtnetlink::Handle>,
) -> ConfigResult {
    let genid = config.genid();

    /* probe the FRR agent. If unreachable, there's no point in trying to apply
    a configuration, either in interface manager or frr */
    frrmi
        .probe()
        .await
        .map_err(|_| ConfigError::FrrAgentUnreachable)?;

    let Some(internal) = &config.internal else {
        error!("Config for genid {genid} does not have internal config");
        return Err(ConfigError::InternalFailure("No internal config was built"));
    };

    /* apply config with VPC manager */
    apply_config_vpc_manager(netlink, internal, genid).await?;

    /* apply config with frrmi to frr-agent */
    apply_config_frr(frrmi, config, internal).await?;

    info!("Successfully applied config for genid {genid}");
    Ok(())
}

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

/// UnixListener wrapper type to implement Accept and hyper Stream traits
/// This is only used/needed when we bind gRPC to a Unix socket
struct UnixAcceptor {
    listener: UnixListener,
}

// Implementation of the Accept trait for UnixListener
impl Accept for UnixAcceptor {
    type Conn = tokio::net::UnixStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
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

// Implementation of hyper Stream trait for UnixAcceptor
impl Stream for UnixAcceptor {
    type Item = Result<tokio::net::UnixStream, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_accept(cx)
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
            warn!("Failed to remove existing socket file: {}", e);
        }
    }

    // Create parent directory if it doesn't exist
    #[allow(clippy::collapsible_if)]
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                error!("Failed to create parent directory: {}", e);
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
            error!("Failed to bind UNIX socket: {}", e);
            return Err(e);
        }
    };

    // Set socket permissions if needed
    match std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666)) {
        Ok(_) => debug!("Socket permissions set to 0666"),
        Err(e) => error!("Failed to set socket permissions: {}", e),
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
            error!("Failed to remove socket file: {}", e);
        }
    }
    Ok(())
}

async fn start_frrmi() -> Result<FrrMi, Error> {
    /* create frrmi to talk to frr-agent */
    let Ok(frrmi) = FrrMi::new("/var/run/frr/frr-agent.sock").await else {
        error!("Failed to start frrmi");
        return Err(Error::other("Failed to start frrmi"));
    };
    Ok(frrmi)
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
pub fn start_mgmt(grpc_addr: GrpcAddress) -> Result<std::thread::JoinHandle<()>, Error> {
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
                let frrmi = start_frrmi().await.unwrap();
                let (processor, tx) = ConfigProcessor::new(frrmi);
                spawn(async { processor.run().await });

                // Start the appropriate server based on address type
                let result = match server_address {
                    ServerAddress::Tcp(sock_addr) => start_grpc_server_tcp(sock_addr, tx).await,
                    ServerAddress::Unix(path) => start_grpc_server_unix(&path, tx).await,
                };
                if let Err(e) = result {
                    error!("Failed to start gRPC server: {}", e);
                }
            });
        })
}
