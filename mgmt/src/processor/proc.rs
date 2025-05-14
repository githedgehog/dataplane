// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::io::Error;
use std::net::SocketAddr;

use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot::Receiver;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;

use crate::grpc::server::create_config_service;
use crate::models::external::gwconfig::{ExternalConfig, GwConfig};
use crate::models::external::{ConfigResult, stringify};

use crate::processor::gwconfigdb::GwConfigDatabase;
use crate::{frr::frrmi::FrrMi, models::external::ConfigError};
use crate::{frr::renderer::builder::Render, models::external::gwconfig::GenId};

use tracing::{debug, error, info, warn};

/// A request type to the [`ConfigProcessor`]
#[derive(Debug)]
pub(crate) enum ConfigRequest {
    ApplyConfig(Box<GwConfig>),
    GetCurrentConfig,
    GetGeneration,
}

/// A response from the [`ConfigProcessor`]
#[derive(Debug)]
pub(crate) enum ConfigResponse {
    ApplyConfig(ConfigResult),
    GetCurrentConfig(Box<Option<GwConfig>>),
    GetGeneration(Option<GenId>),
}
type ConfigResponseChannel = oneshot::Sender<ConfigResponse>;

/// A type that includes a request to the [`ConfigProcessor`] and a channel to
/// issue the response back
#[derive(Debug)]
pub(crate) struct ConfigChannelRequest {
    request: ConfigRequest,          /* a request to the mgmt processor */
    reply_tx: ConfigResponseChannel, /* the one-shot channel to respond */
}
impl ConfigChannelRequest {
    #[must_use]
    #[tracing::instrument(level = "debug")]
    pub fn new(request: ConfigRequest) -> (Self, Receiver<ConfigResponse>) {
        let (reply_tx, reply_rx) = oneshot::channel();
        let request = Self { request, reply_tx };
        (request, reply_rx)
    }
}

/// A configuration processor entity. This is the RPC-independent entity responsible for
/// accepting/rejecting configurations, storing them in the configuration database and
/// applying them.
#[derive(Debug)]
pub(crate) struct ConfigProcessor {
    config_db: GwConfigDatabase,
    rx: mpsc::Receiver<ConfigChannelRequest>,
    frrmi: FrrMi,
    cancellation_token: CancellationToken,
    netlink: rtnetlink::Handle,
}

impl ConfigProcessor {
    // TODO: i'm not sure 1 is a good limit in an async context.  Is there something wrong with a
    // queue of them?
    const CHANNEL_SIZE: usize = 1; // process one at a time

    /// Create a [`ConfigProcessor`]
    #[tracing::instrument(level = "info")]
    pub(crate) fn new(
        frrmi: FrrMi,
        cancellation_token: CancellationToken,
    ) -> (Self, Sender<ConfigChannelRequest>) {
        debug!("Creating config processor...");
        let (tx, rx) = mpsc::channel(Self::CHANNEL_SIZE);

        let Ok((connection, netlink, _)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        tokio::spawn(connection);

        let processor = Self {
            config_db: GwConfigDatabase::new(),
            rx,
            frrmi,
            netlink,
            cancellation_token,
        };
        (processor, tx)
    }

    /// Main entry point for new configurations. When invoked, this method:
    ///   * forbids the addition of a config if a config with same id exists
    ///   * validates the incoming config
    ///   * builds an internal config for it
    ///   * stores the config in the config database
    ///   * applies the config
    #[tracing::instrument(level = "info")]
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

        /* add to a config database */
        self.config_db.add(config);

        /* apply the configuration just stored */
        self.config_db
            .apply(genid, &mut self.frrmi, &mut self.netlink)
            .await?;

        Ok(())
    }

    /// Method to apply a blank configuration
    #[tracing::instrument(level = "info")]
    async fn apply_blank_config(&mut self) -> ConfigResult {
        self.config_db
            .apply(
                ExternalConfig::BLANK_GENID,
                &mut self.frrmi,
                &mut self.netlink,
            )
            .await
    }

    /// RPC handler to apply a config
    #[tracing::instrument(level = "debug")]
    async fn handle_apply_config(&mut self, config: GwConfig) -> ConfigResponse {
        let genid = config.genid();
        debug!("handling apply configuration request. Genid {genid}");
        let result = self.process_incoming_config(config).await;
        debug!(
            "completed configuration for Genid {genid}: {}",
            stringify(&result)
        );
        ConfigResponse::ApplyConfig(result)
    }

    /// RPC handler to get current config generation id
    #[tracing::instrument(level = "debug")]
    fn handle_get_generation(&self) -> ConfigResponse {
        debug!("Handling get generation request");
        ConfigResponse::GetGeneration(self.config_db.get_current_gen())
    }

    /// RPC handler to get the currently applied config
    #[tracing::instrument(level = "info")]
    fn handle_get_config(&self) -> ConfigResponse {
        debug!("Handling get running configuration request");
        let cfg = Box::new(self.config_db.get_current_config().cloned());
        ConfigResponse::GetCurrentConfig(cfg)
    }

    /// Run the configuration processor
    #[tracing::instrument(level = "info")]
    async fn run(mut self) {
        info!("Starting config processor...");

        // apply initial blank config: we may want to remove this to handle the case
        // where dataplane is restarted and we don't want to flush the state of the system.
        if let Err(e) = self.apply_blank_config().await {
            warn!("Failed to apply blank config!: {e}");
        }

        loop {
            tokio::select! {
                // receive config requests over channel
                request = self.rx.recv() => {match request {
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
                        info!("channel to config processor was closed!");
                        break;
                    },
                }}
                _ = self.cancellation_token.cancelled() => {
                    info!("configuration processor task canceled");
                    self.rx.close();
                }
            }
        }
    }
}

#[tracing::instrument(level = "info")]
pub async fn apply_gw_config(
    config: &mut GwConfig,
    frrmi: &mut FrrMi,
    netlink: &mut rtnetlink::Handle,
) -> ConfigResult {
    /* probe the FRR agent. If unreachable, there's no point in trying to apply
    a configuration, either in interface manager or frr */
    frrmi
        .probe()
        .await
        .map_err(|_| ConfigError::FrrAgentUnreachable)?;

    /* apply in interface manager - async (TODO) */
    // TODO: need to pipe rtnetlink socket here

    /* apply in frr: need to render and call frr-reload */
    if let Some(internal) = &config.internal {
        debug!("Generating FRR config for genid {}...", config.genid());
        let rendered = internal.render(config);
        debug!("FRR configuration is:\n{}", rendered.to_string());

        frrmi
            .apply_config(config.genid(), &rendered)
            .await
            .map_err(|e| ConfigError::FrrApplyError(e.to_string()))?;
    }

    // TODO: I think this log message is incorrect
    info!("Successfully applied config with genid {}", config.genid());
    Ok(())
}

/// Start the gRPC server
#[tracing::instrument(level = "info")]
async fn start_grpc_server(addr: SocketAddr, channel_tx: Sender<ConfigChannelRequest>) {
    info!("Starting gRPC server on {:?}", addr);
    let config_service = create_config_service(channel_tx);

    match Server::builder()
        .add_service(config_service)
        .serve(addr)
        .await
    {
        Ok(()) => {}
        Err(err) => {
            error!("Failed to start gRPC server: {err}");
            panic!("Failed to start gRPC server: {err}");
        }
    }
}

#[tracing::instrument(level = "info")]
async fn start_frrmi() -> Result<FrrMi, Error> {
    /* create frrmi to talk to frr-agent */
    let Ok(frrmi) = FrrMi::new("/var/run/frr/frr-agent.sock").await else {
        error!("Failed to start frrmi");
        return Err(Error::other("Failed to start frrmi"));
    };
    Ok(frrmi)
}

// TODO: implement shutdown logic
/// Start the mgmt service
#[tracing::instrument(level = "info")]
pub fn start_mgmt<'scope, 'env: 'scope>(
    grpc_address: SocketAddr,
    cancellation_token: CancellationToken,
    scope: &'scope std::thread::Scope<'scope, 'env>,
) -> Result<std::thread::ScopedJoinHandle<'scope, ()>, Error> {
    debug!("Initializing management...");

    std::thread::Builder::new()
        .name("mgmt".to_string())
        .spawn_scoped(scope, move || {
            debug!("Starting dataplane management thread");

            /* create tokio runtime */
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Tokio runtime creation failed");

            let _guard = rt.enter();

            /* block thread to run gRPC and configuration processor */
            rt.block_on(async {
                let frrmi = start_frrmi().await.unwrap();
                let (processor, tx) = ConfigProcessor::new(frrmi, cancellation_token.clone());
                let config_processor = tokio::spawn(processor.run());
                let grpc_server = tokio::spawn(start_grpc_server(grpc_address, tx));
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        info!("shutting down management thread");
                    }
                    config_processor = config_processor => {
                        match config_processor {
                            Ok(()) => {
                                info!("configuration processor has shut down");
                            },
                            Err(err) => {
                                error!("{err}");
                                panic!("{err}");
                            }
                        }
                    }
                    grpc_server = grpc_server => {
                        match grpc_server {
                            Ok(()) => {
                                info!("grpc_server has shut down");
                            }
                            Err(err) => {
                                error!("{err}");
                                panic!("{err}");
                            }
                        }
                    }
                }
                info!("management thread async runtime has shutdown");
            });
        })
}
