// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// !Configuration processor

use std::sync::Arc;
use std::time::SystemTime;

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

        /* reject config if it uses id of existing one */
        if genid != ExternalConfig::BLANK_GENID && self.config_db.contains(genid) {
            error!("Rejecting config request: a config with id {genid} exists");
            return Err(ConfigError::ConfigAlreadyExists(genid));
        }
        config.validate()?;
        config.build_internal_config()?;
        self.config_db.add(config);
        self.apply(genid).await?;
        Ok(())
    }

    /// Apply blank configuration
    async fn apply_blank_config(&mut self) -> ConfigResult {
        self.apply(ExternalConfig::BLANK_GENID).await
    }

    /// Apply the configuration with the given id
    async fn do_apply_config(&mut self, genid: GenId) -> ConfigResult {
        if let Some(config) = self.config_db.get_mut(genid) {
            apply_gw_config(&self.vpc_mgr, config, &mut self.frrmi, &mut self.router_ctl).await?;
            config.meta.applied = Some(SystemTime::now());
            config.meta.is_applied = true;
            Ok(())
        } else {
            error!("Can't apply config {genid}: not found");
            Err(ConfigError::NoSuchConfig(genid))
        }
    }

    /// Apply the configuration with the given id provided that it is not already applied
    /// and roll-back to the previously applied config in case of failure.
    async fn apply(&mut self, genid: GenId) -> ConfigResult {
        debug!("Applying config with genid '{genid}'...");

        // get the generation (id) of the currently applied config, if any
        // and abort if the requested config is already applied
        let last = self.config_db.get_current_gen();
        if let Some(last) = last {
            if last == genid {
                info!("Config {last} is already applied");
                return Ok(());
            }
            debug!("The current config is {last}");
        } else {
            debug!("There is no config applied");
        }

        /* Apply this gw config */
        let res = self.do_apply_config(genid).await;
        match res {
            Ok(()) => {
                self.config_db.unmark_current();
                self.config_db.set_current_gen(genid);
            }
            Err(ref _e) => {
                // delete the config we wanted to apply (blank can't be deleted)
                debug!("Deleting config with id {genid}..");
                let _ = self.config_db.remove(genid);

                // roll-back to a previous config (if there) or the blank config (to wipe out),
                // except if the failed config is the blank itself or the failure.
                // TODO: FIXME(fredi) if we fail to apply a config because we can't reach the frr-agent, we
                // may only need to roll-back the kernel state. However, rollback will fail too
                // if frr-agent can't be reached. This will leave us with an inconsitent kernel-frr
                // config.
                if genid != ExternalConfig::BLANK_GENID {
                    let previous = last.unwrap_or(ExternalConfig::BLANK_GENID);
                    info!("Rolling back to config '{previous}'...",);
                    if let Err(e) = self.do_apply_config(previous).await {
                        error!("Fatal: could not roll-back to previous config: {e}");
                    }
                }
            }
        }
        debug!(
            "The current config DB is:\n{}",
            GwConfigDatabaseSummary(&self.config_db)
        );
        res
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

        let obs_rib = self
            .observe()
            .await
            .map_err(|_| ConfigError::InternalFailure("Failed to observe interface state".to_string()))?;

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
    config: &GwConfig,
    internal: &InternalConfig,
) -> ConfigResult {
    let genid = config.genid();

    debug!("Generating FRR config for genid {genid}...");

    let rendered = internal.render(config);

    frrmi
        .apply_config(config.genid(), &rendered)
        .await
        .map_err(|e| ConfigError::FailureApply(format!("Error applying FRR config: {e}")))?;

    debug!("FRR config for genid {genid} successfully applied");
    Ok(())
}

/// Main function to apply a config
async fn apply_gw_config(
    vpc_mgr: &VpcManager<RequiredInformationBase>,
    config: &mut GwConfig,
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

    /* apply config with VPC manager */
    vpc_mgr.apply_config(internal, genid).await?;

    /* apply config with frrmi to frr-agent */
    apply_config_frr(frrmi, config, internal).await?;

    /* tell router about vtep as it won't learn it from frr */
    if let Some(vconfig) = internal.get_vtep() {
        let vtep = Vtep::with_ip_and_mac(vconfig.address.into(), vconfig.mac.into());
        router_ctl.set_vtep(vtep).await;
    }
    info!("Successfully applied config for genid {genid}");
    Ok(())
}
