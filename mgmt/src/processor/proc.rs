// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// !Configuration processor

use std::collections::HashMap;
use std::sync::Arc;

use futures::TryFutureExt;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;

use config::external::overlay::Overlay;
use config::{ConfigError, ConfigResult, stringify};
use config::{ExternalConfig, GenId, GwConfig, InternalConfig};

use crate::processor::confbuild::internal::build_internal_config;
use crate::processor::confbuild::router::generate_router_config;
use nat::stateless::NatTablesWriter;
use nat::stateless::setup::{build_nat_configuration, validate_nat_configuration};
use pkt_meta::dst_vpcd_lookup::VpcDiscTablesWriter;
use pkt_meta::dst_vpcd_lookup::setup::build_dst_vni_lookup_configuration;

use crate::processor::display::GwConfigDatabaseSummary;
use crate::processor::gwconfigdb::GwConfigDatabase;

use crate::vpc_manager::{RequiredInformationBase, VpcManager};
use rekon::{Observe, Reconcile};
use tracing::{debug, error, info, warn};

use net::interface::display::MultiIndexInterfaceMapView;
use net::interface::{Interface, InterfaceName};
use routing::ctl::RouterCtlSender;

use stats::VpcMapName;
use vpcmap::VpcDiscriminant;
use vpcmap::map::{VpcMap, VpcMapWriter};

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
    router_ctl: RouterCtlSender,
    vpc_mgr: VpcManager<RequiredInformationBase>,
    vpcmapw: VpcMapWriter<VpcMapName>,
    nattablew: NatTablesWriter,
    vnitablesw: VpcDiscTablesWriter,
}

impl ConfigProcessor {
    const CHANNEL_SIZE: usize = 1; // This should not be changed

    /////////////////////////////////////////////////////////////////////////////////
    /// Create a [`ConfigProcessor`]
    /////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn new(
        router_ctl: RouterCtlSender,
        vpcmapw: VpcMapWriter<VpcMapName>,
        nattablew: NatTablesWriter,
        vnitablesw: VpcDiscTablesWriter,
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
            router_ctl,
            vpc_mgr,
            vpcmapw,
            nattablew,
            vnitablesw,
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
        let internal = build_internal_config(&config)?;
        config.set_internal_config(internal);
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
    #[allow(unused)]
    async fn apply_blank_config(&mut self) -> ConfigResult {
        let mut blank = GwConfig::blank();
        let internal = build_internal_config(&blank)?;
        blank.set_internal_config(internal);
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
            &mut self.router_ctl,
            &mut self.vpcmapw,
            &mut self.nattablew,
            &mut self.vnitablesw,
        )
        .await?;

        if let Some(current) = current {
            current.meta.set_state(current.genid(), false, Some(genid));
        }
        config.meta.set_state(genid, true, None);
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
                &mut self.router_ctl,
                &mut self.vpcmapw,
                &mut self.nattablew,
                &mut self.vnitablesw,
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

    /// Get the current set of kernel interfaces of type VRF keyed by name
    async fn get_kernel_vrfs(&self) -> Result<HashMap<InterfaceName, Interface>, ConfigError> {
        let obs_rib = self.observe().await.map_err(|_| {
            ConfigError::InternalFailure("Failed to retrieve kernel interfaces".to_string())
        })?;

        let vrfs: HashMap<InterfaceName, Interface> = obs_rib
            .interfaces
            .iter_by_name()
            .filter(|intf| intf.is_vrf())
            .cloned()
            .map(|intf| (intf.name.clone(), intf))
            .collect();

        Ok(vrfs)
    }
}

/// Build router config and apply it over the router control channel
async fn apply_router_config(
    kernel_vrfs: &HashMap<InterfaceName, Interface>,
    config: &GwConfig,
    router_ctl: &mut RouterCtlSender,
) -> ConfigResult {
    // build the router config
    let router_config = generate_router_config(kernel_vrfs, config)?;

    // request router to apply it
    router_ctl
        .configure(router_config)
        .map_err(|e| ConfigError::InternalFailure(format!("Router config error: {e}")))
        .await?;

    info!(
        "Router config for gen {} was successfully applied",
        config.genid()
    );
    Ok(())
}

/// refresh mappings for per vpc statistics
fn update_stats_vpc_mappings(config: &GwConfig, vpcmapw: &mut VpcMapWriter<VpcMapName>) {
    // create a mapping table frome the vpc table in the config
    // FIXME(fredi): visibility
    // FIXME(fredi): generalize the vpcmapName table
    let vpc_table = &config.external.overlay.vpc_table;
    let mut vpcmap = VpcMap::<VpcMapName>::new();
    for vpc in vpc_table.values() {
        let disc = VpcDiscriminant::VNI(vpc.vni);
        let map = VpcMapName::new(disc, &vpc.name);
        vpcmap
            .add(VpcDiscriminant::VNI(vpc.vni), map)
            .unwrap_or_else(|_| unreachable!());
    }
    vpcmapw.set_map(vpcmap);
}

/// Update the Nat tables for stateless NAT
fn apply_nat_config(overlay: &Overlay, nattablesw: &mut NatTablesWriter) -> ConfigResult {
    validate_nat_configuration(&overlay.vpc_table)?;
    let nat_table = build_nat_configuration(&overlay.vpc_table)?;
    nattablesw.update_nat_tables(nat_table);
    Ok(())
}

/// Update the VNI tables for dst_vni_lookup
fn apply_dst_vpcd_lookup_config(
    overlay: &Overlay,
    vpcdtablesw: &mut VpcDiscTablesWriter,
) -> ConfigResult {
    let vpcd_tables = build_dst_vni_lookup_configuration(overlay)?;
    vpcdtablesw.update_vpcd_tables(vpcd_tables);
    Ok(())
}
/// Main function to apply a config
async fn apply_gw_config(
    vpc_mgr: &VpcManager<RequiredInformationBase>,
    config: &mut GwConfig,
    _current: Option<&GwConfig>,
    router_ctl: &mut RouterCtlSender,
    vpcmapw: &mut VpcMapWriter<VpcMapName>,
    nattablesw: &mut NatTablesWriter,
    vpcdtablesw: &mut VpcDiscTablesWriter,
) -> ConfigResult {
    let genid = config.genid();

    /* make sure we built internal config */
    let Some(internal) = &config.internal else {
        error!("Config for genid {genid} does not have internal config");
        return Err(ConfigError::InternalFailure(
            "No internal config was built".to_string(),
        ));
    };

    if genid == ExternalConfig::BLANK_GENID {
        /* apply config with VPC manager */
        vpc_mgr.apply_config(internal, genid).await?;
        info!("Successfully applied config for genid {genid}");
        return Ok(());
    }

    /* lock the CPI to prevent updates on the routing db. No explicit unlocking is
    required. The CPI will be automatically unlocked when this guard goes out of scope */
    let _guard = router_ctl
        .lock()
        .map_err(|_| ConfigError::InternalFailure("Could not lock the CPI".to_string()))
        .await?;

    /* apply config with VPC manager */
    vpc_mgr.apply_config(internal, genid).await?;

    /* get vrf interfaces from kernel and build a hashmap keyed by name */
    let kernel_vrfs = vpc_mgr.get_kernel_vrfs().await?;

    /* apply nat config */
    apply_nat_config(&config.external.overlay, nattablesw)?;

    /* apply dst_vpcd_lookup config */
    apply_dst_vpcd_lookup_config(&config.external.overlay, vpcdtablesw)?;

    /* update stats mappings */
    update_stats_vpc_mappings(config, vpcmapw);

    /* apply config in router */
    apply_router_config(&kernel_vrfs, config, router_ctl).await?;

    info!("Successfully applied config for genid {genid}");
    Ok(())
}
