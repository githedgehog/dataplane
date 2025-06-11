// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// !Configuration processor

use std::sync::Arc;

use futures::TryFutureExt;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;

use crate::models::external::gwconfig::{ExternalConfig, GwConfig};
use crate::models::external::{ConfigError, ConfigResult, stringify};
use crate::models::internal::InternalConfig;

use crate::frr::frrmi::FrrMi;
use crate::processor::display::GwConfigDatabaseSummary;
use crate::processor::gwconfigdb::GwConfigDatabase;
use crate::{frr::renderer::builder::Render, models::external::gwconfig::GenId};

use crate::vpc_manager::{RequiredInformationBase, VpcManager};
use rekon::{Observe, Reconcile};
use tracing::{debug, error, info, warn};

use net::interface::Interface;
use net::interface::display::MultiIndexInterfaceMapView;
use routing::ctl::RouterCtlSender;
use routing::evpn::Vtep;

/// A request type to the `ConfigProcessor`
#[derive(Debug)]
pub enum ConfigRequest {
    ApplyConfig(Box<GwConfig>),
    GetCurrentConfig,
    GetGeneration,
}

/// A response from the `ConfigProcessor`
#[derive(Debug)]
pub enum ConfigResponse {
    ApplyConfig(ConfigResult),
    GetCurrentConfig(Box<Option<GwConfig>>),
    GetGeneration(Option<GenId>),
}
type ConfigResponseChannel = oneshot::Sender<ConfigResponse>;

/// A type that includes a request to the `ConfigProcessor` and a channel to
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
    router_ctl: RouterCtlSender,
    vpc_mgr: VpcManager<RequiredInformationBase>,
}

impl ConfigProcessor {
    const CHANNEL_SIZE: usize = 1; // This should not be changed

    /// Create a [`ConfigProcessor`]
    pub(crate) fn new(
        frrmi: FrrMi,
        router_ctl: RouterCtlSender,
    ) -> (Self, Sender<ConfigChannelRequest>) {
        debug!("Creating config processor...");
        let (tx, rx) = mpsc::channel(Self::CHANNEL_SIZE);

        let Ok((connection, netlink, _)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        spawn(connection);

        let netlink = Arc::new(netlink);
        let vpc_mgr = VpcManager::<RequiredInformationBase>::new(netlink);

        let processor = Self {
            config_db: GwConfigDatabase::new(),
            rx,
            frrmi,
            router_ctl,
            vpc_mgr,
        };
        (processor, tx)
    }

    /// Main entry point for new configurations
    pub(crate) async fn process_incoming_config(&mut self, mut config: GwConfig) -> ConfigResult {
        let genid = config.genid();
        /* reject config if it uses the id of an existing one */
        if genid != ExternalConfig::BLANK_GENID && self.config_db.contains(genid) {
            error!("Rejecting config request: a config with id {genid} exists");
            return Err(ConfigError::ConfigAlreadyExists(genid));
        }
        config.validate()?;
        config.build_internal_config()?;
        let e = match self.apply(config).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.rollback().await;
                Err(e)
            }
        };

        let summary = GwConfigDatabaseSummary(&self.config_db);
        debug!("The config DB is:\n{summary}");
        e
    }

    /// Apply a blank configuration
    async fn apply_blank_config(&mut self) -> ConfigResult {
        let mut blank = GwConfig::blank();
        let _ = blank.build_internal_config();
        self.apply(blank).await
    }

    /// Apply the provided configuration. On success, store it and update its meta-data.
    async fn apply(&mut self, mut config: GwConfig) -> ConfigResult {
        let genid = config.genid();
        debug!("Applying config with genid '{genid}'...");

        let current = self.config_db.get_current_config_mut();
        if let Some(current) = &current {
            debug!("The current config is {}", current.genid());
        }

        apply_gw_config(
            &self.vpc_mgr,
            &mut config,
            current.as_deref(),
            &mut self.frrmi,
            &mut self.router_ctl,
        )
        .await?;

        if let Some(current) = current {
            current.set_state(false, Some(genid));
        }
        config.set_state(true, None);
        self.config_db.set_current_gen(genid);
        if !self.config_db.contains(genid) {
            self.config_db.add(config);
        }
        Ok(())
    }

    /// Attempt to apply the previously applied config
    async fn rollback(&mut self) {
        let current = self.config_db.get_current_gen();
        let rollback_cfg = current.unwrap_or(ExternalConfig::BLANK_GENID);
        info!("Rolling back to config '{rollback_cfg}'...");
        if let Some(prior) = self.config_db.get_mut(rollback_cfg) {
            let _ = apply_gw_config(
                &self.vpc_mgr,
                prior,
                None,
                &mut self.frrmi,
                &mut self.router_ctl,
            )
            .await;
        }
    }

    /// RPC handler: store and apply the provided config
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

    /// RPC handler: get current config generation id
    fn handle_get_generation(&self) -> ConfigResponse {
        debug!("Handling get generation request");
        ConfigResponse::GetGeneration(self.config_db.get_current_gen())
    }

    /// RPC handler: get the currently applied config
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
            // receive config requests over channel from gRPC server
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

impl VpcManager<RequiredInformationBase> {
    /// Apply the provided [`InternalConfig`]
    async fn apply_config(&self, internal: &InternalConfig, genid: GenId) -> ConfigResult {
        /* build required information base from internal config */
        let mut rib: RequiredInformationBase = match internal.try_into() {
            Ok(rib) => rib,
            Err(err) => {
                let msg = format!("Couldn't build required information base: {err}");
                error!("{msg}");
                return Err(ConfigError::FailureApply(msg));
            }
        };

        debug!("Required information base for genid {genid} is:\n{rib:?}");

        let mut required_passes = 0;
        while !self
            .reconcile(&mut rib, &self.observe().await.unwrap())
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

        let obs_rib = self.observe().await.map_err(|_| {
            ConfigError::InternalFailure("Failed to observe interface state".to_string())
        })?;

        debug!(
            "The current kernel interfaces are:\n{}",
            &obs_rib.interfaces
        );

        let vrfs = MultiIndexInterfaceMapView {
            map: &obs_rib.interfaces,
            filter: &|iface: &Interface| iface.is_vrf(),
        };
        debug!("The current VRF interfaces are:\n{vrfs}");

        Ok(())
    }
}

/// Apply config over frrmi with frr-agent
async fn apply_config_frr(
    frrmi: &mut FrrMi,
    genid: GenId,
    internal: &InternalConfig,
) -> ConfigResult {
    debug!("Generating FRR config for genid {genid}...");

    let rendered = internal.render(&genid);

    frrmi
        .apply_config(genid, &rendered)
        .await
        .map_err(|e| ConfigError::FailureApply(format!("Error applying FRR config: {e}")))?;

    Ok(())
}

/// Main function to apply a config
async fn apply_gw_config(
    vpc_mgr: &VpcManager<RequiredInformationBase>,
    config: &mut GwConfig,
    _current: Option<&GwConfig>,
    frrmi: &mut FrrMi,
    router_ctl: &mut RouterCtlSender,
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
        return Err(ConfigError::InternalFailure(
            "No internal config was built".to_string(),
        ));
    };

    /* lock the CPI to prevent updates on the routing db. No explicit unlocking is
    required. The CPI will be automatically unlocked when this guard goes out of scope */
    let _guard = router_ctl
        .lock()
        .map_err(|_| ConfigError::InternalFailure("Could not lock the CPI".to_string()))
        .await?;

    /* apply config with VPC manager */
    vpc_mgr.apply_config(internal, genid).await?;

    /* apply config with frrmi to frr-agent */
    apply_config_frr(frrmi, genid, internal).await?;

    /* tell router about vtep as it won't learn it from frr */
    if let Some(vconfig) = internal.get_vtep() {
        let vtep = Vtep::with_ip_and_mac(vconfig.address.into(), vconfig.mac.into());
        router_ctl.set_vtep(vtep).await;
    }
    info!("Successfully applied config for genid {genid}");
    Ok(())
}
