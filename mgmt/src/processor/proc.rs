// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::io::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use tokio::sync::RwLock;
use tonic::transport::Server;

use crate::frr::renderer::builder::Render;
use crate::models::external::configdb::gwconfig::ExternalConfig;
use crate::models::external::configdb::gwconfigdb::GwConfigDatabase;
use crate::models::external::{ApiResult, configdb::gwconfig::GwConfig};
use crate::{frr::frrmi::FrrMi, models::external::ApiError};
use tracing::{debug, error, info};

use crate::grpc::server::create_config_service;

#[allow(unused)]
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
    debug!(
        "Processing received configuration. Genid:'{}'..",
        config.genid()
    );

    /* get id of incoming config */
    let genid = config.genid();

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
