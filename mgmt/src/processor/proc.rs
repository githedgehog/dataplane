// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused)] // TEMPORARY

use std::io::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use tokio::sync::RwLock;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, oneshot};
use tonic::transport::Server;

use crate::models::external::gwconfig::ExternalConfig;
use crate::models::external::{ApiResult, gwconfig::GwConfig};
use crate::processor::gwconfigdb::GwConfigDatabase;
use crate::{frr::frrmi::FrrMi, models::external::ApiError};
use crate::{frr::renderer::builder::Render, models::external::gwconfig::GenId};
use tracing::{debug, error, info, warn};

use crate::grpc::server::create_config_service;


/// Build an empty config and apply it
async fn blank_config_apply(configdb: &mut GwConfigDatabase, frrmi: &FrrMi) {
    let external = ExternalConfig::new();
    let blank = GwConfig::new(external);
    let _ = new_gw_config(configdb, blank, frrmi).await;
}

/// Entry point for new configurations, [`GwConfig`]
pub async fn new_gw_config(
    configdb: &mut GwConfigDatabase,
    mut config: GwConfig,
    frrmi: &FrrMi,
) -> ApiResult {

    /* get id of incoming config */
    let genid = config.genid();
    debug!("Processing config with id:'{genid}'..");

    /* reject config if it uses id of existing one */
    if configdb.contains(genid) {
        error!("Rejecting config request: a config with id {genid} exists");
        return Err(ApiError::ConfigAlreadyExists(genid));
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
pub(crate) enum ConfigRequest {
    ApplyConfig(GwConfig),
    GetCurrentConfig,
    GetGeneration,
}

/// A response from the [`ConfigProcessor`]
pub(crate) enum ConfigResponse {
    ApplyConfig(ApiResult),
    GetCurrentConfig(Option<GwConfig>),
    GetGeneration(Option<GenId>),
}
type ConfigResponseChannel = oneshot::Sender<ConfigResponse>;

/// A type that includes a request to the [`ConfigProcessor`] and a channel to
/// issue the response back
struct ConfigChannelRequest {
    request: ConfigRequest,          /* a request to the mgmt processor */
    reply_tx: ConfigResponseChannel, /* the one-shot channel to respond */
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
    fn new(frrmi: FrrMi) -> (Self, Sender<ConfigChannelRequest>) {
        let (tx, rx) = mpsc::channel(1);
        let processor = Self {
            config_db: GwConfigDatabase::new(),
            rx,
            frrmi,
        };
        (processor, tx)
    }
    async fn handle_apply_config(&mut self, config: GwConfig) -> ConfigResponse {
        ConfigResponse::ApplyConfig(new_gw_config(&mut self.config_db, config, &self.frrmi).await)
    }
    fn handle_get_generation(&self) -> ConfigResponse {
        ConfigResponse::GetGeneration(self.config_db.get_current_gen())
    }
    fn handle_get_config(&self) -> ConfigResponse {
        if let Some(current) = self.config_db.get_current_config() {
            ConfigResponse::GetCurrentConfig(Some(current.clone()))
        } else {
            ConfigResponse::GetCurrentConfig(None)
        }
    }
    /// Run the configuration processor
    async fn run(&mut self) {
        debug!("Starting config processor...");
        loop {
            match self.rx.recv().await {
                Some(req) => {
                    let response = match req.request {
                        ConfigRequest::ApplyConfig(config) => self.handle_apply_config(config).await,
                        ConfigRequest::GetCurrentConfig => self.handle_get_config(),
                        ConfigRequest::GetGeneration => self.handle_get_generation(),
                    };
                    // check error
                    req.reply_tx.send(response);
                }
                None => {
                    warn!("Channel to config processor was closed!");
                }
            }
        }
    }
}

/// Main logic to apply a [`GwConfig`]. This is called from GwConfig::apply()
pub async fn apply_gw_config(config: &mut GwConfig, frrmi: &FrrMi) -> ApiResult {
    /* apply in interface manager - async (TODO) */

    /* apply in frr: need to render and call frr-reload */
    if let Some(internal) = &config.internal {
        debug!("Generating FRR config for genid {}...", config.genid());
        let rendered = internal.render(config);
        debug!("FRR configuration is:\n{}", rendered.to_string());

        frrmi
            .apply_config(config.genid(), &rendered)
            .await
            .map_err(|e| ApiError::FrrApplyError(e.to_string()))?;
    }

    info!("Successfully applied config with genid {}", config.genid());
    Ok(())
}

/// Start the gRPC server
async fn start_grpc_server(
    config_db: Arc<RwLock<GwConfigDatabase>>,
    frrmi: FrrMi,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting gRPC server on {:?}", addr);

    let config_service = create_config_service(config_db, frrmi);

    Server::builder()
        .add_service(config_service)
        .serve(addr)
        .await?;

    Ok(())
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
    debug!("Starting management. gRPC address is {grpc_address:?}");

    /* create runtime */
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Tokio runtime creation failed");

    /* create config database */
    let config_db = Arc::new(RwLock::new(GwConfigDatabase::new()));

    /* start management thread and move all context: the management thread will own the frrmi and the config db. */
    thread::Builder::new()
        .name("mgmt".to_string())
        .spawn(move || {
            debug!("Starting dataplane management thread");

            let frrmi = rt.block_on(async { start_frrmi().await.unwrap() });

            /* start gRPC server with the config DB and frrmi */
            rt.block_on(async move {
                start_grpc_server(config_db, frrmi, grpc_address)
                    .await
                    .unwrap();
            });
        })
}
