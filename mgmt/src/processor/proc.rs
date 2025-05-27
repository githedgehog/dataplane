// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::sync::Arc;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;

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
    pub async fn run(mut self) {
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

/// Main function to apply a config
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
