// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unreachable_code)]

use std::io::Error;
use std::net::SocketAddr;
use std::thread;

use tokio::sync::oneshot::Receiver;
use tokio::sync::{mpsc, oneshot};
use tokio::{spawn, sync::mpsc::Sender};
use tonic::transport::Server;

use crate::models::external::gwconfig::ExternalConfig;
use crate::models::external::{ConfigResult, gwconfig::GwConfig};
use crate::processor::gwconfigdb::GwConfigDatabase;
use crate::{frr::frrmi::FrrMi, models::external::ConfigError};
use crate::{frr::renderer::builder::Render, models::external::gwconfig::GenId};
use tracing::{debug, error, info, warn};

use crate::grpc::server::create_config_service;

/// Build an empty config and apply it
#[allow(unused)]
async fn blank_config_apply(configdb: &mut GwConfigDatabase, frrmi: &FrrMi) {
    debug!("Applying empty configuration...");
    let external = ExternalConfig::new();
    let blank = GwConfig::new(external);
    let _ = new_gw_config(configdb, blank, frrmi).await;
}

/// Entry point for new configurations, [`GwConfig`]
pub(crate) async fn new_gw_config(
    configdb: &mut GwConfigDatabase,
    mut config: GwConfig,
    frrmi: &FrrMi,
) -> ConfigResult {
    /* get id of incoming config */
    let genid = config.genid();
    debug!("Processing config with id:'{genid}'..");

    /* reject config if it uses id of existing one */
    if configdb.contains(genid) {
        error!("Rejecting config request: a config with id {genid} exists");
        return Err(ConfigError::ConfigAlreadyExists(genid));
    }

    /* validate the config */
    config.validate()?;

    /* build internal config for this config */
    config.build_internal_config()?;

    /* add to config database */
    configdb.add(config);

    /* apply the configuration just stored */
    configdb.apply(genid, frrmi).await?;

    Ok(())
}

/// A request type to the [`ConfigProcessor`]
pub enum ConfigRequest {
    ApplyConfig(Box<GwConfig>),
    GetCurrentConfig,
    GetGeneration,
}

/// A response from the [`ConfigProcessor`]
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
struct ConfigProcessor {
    config_db: GwConfigDatabase,
    rx: mpsc::Receiver<ConfigChannelRequest>,
    frrmi: FrrMi,
}

impl ConfigProcessor {
    const CHANNEL_SIZE: usize = 1; // process one at a time

    fn new(frrmi: FrrMi) -> (Self, Sender<ConfigChannelRequest>) {
        debug!("Creating config processor...");
        let (tx, rx) = mpsc::channel(Self::CHANNEL_SIZE);
        let processor = Self {
            config_db: GwConfigDatabase::new(),
            rx,
            frrmi,
        };
        (processor, tx)
    }
    async fn handle_apply_config(&mut self, config: GwConfig) -> ConfigResponse {
        debug!("Handling apply configuration request...");
        ConfigResponse::ApplyConfig(new_gw_config(&mut self.config_db, config, &self.frrmi).await)
    }
    fn handle_get_generation(&self) -> ConfigResponse {
        debug!("Handling get generation request...");
        ConfigResponse::GetGeneration(self.config_db.get_current_gen())
    }
    fn handle_get_config(&self) -> ConfigResponse {
        debug!("Handling get running configuration request...");
        let cfg = Box::new(self.config_db.get_current_config().cloned());
        ConfigResponse::GetCurrentConfig(cfg)
    }
    /// Run the configuration processor
    #[allow(unreachable_code)]
    async fn run(mut self) {
        info!("Running config processor...");
        loop {
            match self.rx.recv().await {
                Some(req) => {
                    let response = match req.request {
                        ConfigRequest::ApplyConfig(config) => {
                            self.handle_apply_config(*config).await
                        }
                        ConfigRequest::GetCurrentConfig => self.handle_get_config(),
                        ConfigRequest::GetGeneration => self.handle_get_generation(),
                    };
                    // check error
                    let _ = req.reply_tx.send(response);
                }
                None => {
                    warn!("Channel to config processor was closed!");
                }
            }
        }
    }
}

pub async fn apply_gw_config(config: &mut GwConfig, frrmi: &FrrMi) -> ConfigResult {
    /* apply in interface manager - async (TODO) */

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

    info!("Successfully applied config with genid {}", config.genid());
    Ok(())
}

/// Start the gRPC server
async fn start_grpc_server(addr: SocketAddr, channel_tx: Sender<ConfigChannelRequest>) {
    info!("Starting gRPC server on {:?}", addr);
    let config_service = create_config_service(channel_tx);

    let _ = Server::builder()
        .add_service(config_service)
        .serve(addr)
        .await;
}

async fn start_frrmi() -> Result<FrrMi, Error> {
    /* create frrmi to talk to frr-agent */
    let Ok(frrmi) = FrrMi::new("/var/run/frr/frrmi.sock", "/var/run/frr/frr-agent.sock").await
    else {
        error!("Failed to start frrmi");
        return Err(Error::other("Failed to start frrmi"));
    };
    Ok(frrmi)
}

/// Start the mgmt service
pub fn start_mgmt(grpc_address: SocketAddr) -> Result<std::thread::JoinHandle<()>, Error> {
    debug!("Initializing management...");

    thread::Builder::new()
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
                start_grpc_server(grpc_address, tx).await; /* must be last */
            });
        })
}
