// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// !Configuration processor

use concurrency::sync::Arc;
use std::collections::HashMap;

use tokio::spawn;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;

use config::external::overlay::vpc::VpcTable;
use config::internal::status::{DataplaneStatus, FrrStatus, VpcPeeringCounters, VpcStatus};
use config::{ConfigError, ConfigResult, stringify};
use config::{DeviceConfig, ExternalConfig, GenId, GwConfig, InternalConfig};
use config::{external::overlay::Overlay, internal::device::tracecfg::TracingConfig};

use crate::processor::confbuild::internal::build_internal_config;
use crate::processor::confbuild::router::generate_router_config;
use nat::stateful::NatAllocatorWriter;
use nat::stateless::NatTablesWriter;
use nat::stateless::setup::{build_nat_configuration, validate_nat_configuration};
use pkt_meta::dst_vpcd_lookup::VpcDiscTablesWriter;
use pkt_meta::dst_vpcd_lookup::setup::build_dst_vni_lookup_configuration;
use routing::frr::FrrAppliedConfig;

use crate::processor::display::GwConfigDatabaseSummary;
use crate::processor::gwconfigdb::GwConfigDatabase;

use crate::vpc_manager::{RequiredInformationBase, VpcManager};
use rekon::{Observe, Reconcile};
use tracectl::get_trace_ctl;
use tracing::{debug, error, info, warn};

use net::interface::display::MultiIndexInterfaceMapView;
use net::interface::{Interface, InterfaceName};
use routing::ctl::RouterCtlSender;

use stats::VpcMapName;
use stats::VpcStatsStore;
use vpcmap::VpcDiscriminant;
use vpcmap::map::{VpcMap, VpcMapWriter};

/// A request type to the `ConfigProcessor`
#[derive(Debug)]
pub enum ConfigRequest {
    ApplyConfig(Box<GwConfig>),
    GetCurrentConfig,
    GetGeneration,
    GetDataplaneStatus,
}

/// A response from the `ConfigProcessor`
#[derive(Debug)]
pub enum ConfigResponse {
    ApplyConfig(ConfigResult),
    GetCurrentConfig(Box<Option<GwConfig>>),
    GetGeneration(Option<GenId>),
    GetDataplaneStatus(Box<DataplaneStatus>),
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
    natallocatorw: NatAllocatorWriter,
    vnitablesw: VpcDiscTablesWriter,
    vpc_stats_store: Arc<VpcStatsStore>,
}
/// Populate FRR status into the dataplane status structure
pub async fn populate_status_with_frr(
    status: &mut DataplaneStatus,
    router_ctl: &mut RouterCtlSender,
) {
    let mut frr = FrrStatus::new();

    if let Ok(Some(FrrAppliedConfig { genid, .. })) = router_ctl.get_frr_applied_config().await {
        frr = frr.set_applied_config_gen(genid);
    }

    status.set_frr_status(frr);
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
        natallocatorw: NatAllocatorWriter,
        vnitablesw: VpcDiscTablesWriter,
        vpc_stats_store: Arc<stats::VpcStatsStore>,
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
            natallocatorw,
            vnitablesw,
            vpc_stats_store,
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
            &mut self.natallocatorw,
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
                &mut self.natallocatorw,
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

    /// RPC handler: get dataplane status
    async fn handle_get_dataplane_status(&mut self) -> ConfigResponse {
        let mut status = DataplaneStatus::new();

        let names = self.vpc_stats_store.snapshot_names().await;
        let pair_snap = self.vpc_stats_store.snapshot_pairs().await;
        let vpc_snap = self.vpc_stats_store.snapshot_vpcs().await;

        // Build name/id/vni maps. Name map starts from store, then we ensure coverage.
        let mut name_of: HashMap<VpcDiscriminant, String> = names;
        let mut id_of: HashMap<VpcDiscriminant, String> = HashMap::new();
        let mut vni_of: HashMap<VpcDiscriminant, u32> = HashMap::new();

        // Ensure we have names for anything seen only in stats.
        for (disc, _) in &vpc_snap {
            name_of.entry(*disc).or_insert_with(|| format!("{disc:?}"));
        }
        for ((s, d), _) in &pair_snap {
            name_of.entry(*s).or_insert_with(|| format!("{s:?}"));
            name_of.entry(*d).or_insert_with(|| format!("{d:?}"));
        }

        // Build id_of and vni_of using only the discriminant
        for disc in name_of.keys().copied() {
            id_of.insert(disc, format!("{disc:?}"));
            let vni = match disc {
                vpcmap::VpcDiscriminant::VNI(v) => v.as_u32(),
            };
            vni_of.insert(disc, vni);
        }

        // Per-VPC section
        for (disc, _) in vpc_snap {
            let name = name_of
                .get(&disc)
                .cloned()
                .unwrap_or_else(|| format!("{disc:?}"));
            let id = id_of
                .get(&disc)
                .cloned()
                .unwrap_or_else(|| format!("{disc:?}"));
            let vni = *vni_of.get(&disc).unwrap_or(&0);

            let v = VpcStatus {
                id,
                name: name.clone(),
                vni,
                route_count: 0,
                interfaces: Default::default(),
            };
            status.add_vpc(name, v);
        }

        // VPC-to-VPC peering counters
        for ((src, dst), fs) in pair_snap {
            let src_name = name_of
                .get(&src)
                .cloned()
                .unwrap_or_else(|| format!("{src:?}"));
            let dst_name = name_of
                .get(&dst)
                .cloned()
                .unwrap_or_else(|| format!("{dst:?}"));
            let key = format!("{src_name}->{dst_name}");

            status.add_peering(
                key.clone(),
                VpcPeeringCounters {
                    name: key,
                    src_vpc: src_name,
                    dst_vpc: dst_name,
                    packets: fs.ctr.packets,
                    bytes: fs.ctr.bytes,
                    drops: 0,
                    pps: fs.rate.pps,
                },
            );
        }

        // FRR minimal info
        populate_status_with_frr(&mut status, &mut self.router_ctl).await;

        ConfigResponse::GetDataplaneStatus(Box::new(status))
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
                        ConfigRequest::GetDataplaneStatus => {
                            self.handle_get_dataplane_status().await
                        }
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
        .await
        .map_err(|e| ConfigError::InternalFailure(format!("Router config error: {e}")))?;

    info!(
        "Router config for gen {} was successfully applied",
        config.genid()
    );
    Ok(())
}

/// refresh mappings for per vpc statistics
///
/// Returns the list of `(VpcDiscriminant, name)` so the caller can seed the stats store.
fn update_stats_vpc_mappings(
    config: &GwConfig,
    vpcmapw: &mut VpcMapWriter<VpcMapName>,
) -> Vec<(VpcDiscriminant, String)> {
    // create a mapping table from the vpc table in the config
    // FIXME(fredi): visibility
    // FIXME(fredi): generalize the vpcmapName table
    let vpc_table = &config.external.overlay.vpc_table;
    let mut vpcmap = VpcMap::<VpcMapName>::new();
    let mut pairs: Vec<(VpcDiscriminant, String)> = Vec::with_capacity(vpc_table.len());

    for vpc in vpc_table.values() {
        let disc = VpcDiscriminant::VNI(vpc.vni);
        let name = vpc.name.clone();
        let map = VpcMapName::new(disc, &name);
        vpcmap.add(disc, map).unwrap_or_else(|_| unreachable!());
        pairs.push((disc, name));
    }

    vpcmapw.set_map(vpcmap);
    pairs
}

/// Update the Nat tables for stateless NAT
fn apply_stateless_nat_config(
    vpc_table: &VpcTable,
    nattablesw: &mut NatTablesWriter,
) -> ConfigResult {
    validate_nat_configuration(vpc_table)?;
    let nat_table = build_nat_configuration(vpc_table)?;
    nattablesw.update_nat_tables(nat_table);
    Ok(())
}

/// Update the config for stateful NAT
fn apply_stateful_nat_config(
    vpc_table: &VpcTable,
    natallocatorw: &mut NatAllocatorWriter,
) -> ConfigResult {
    natallocatorw.update_allocator(vpc_table)?;
    // TODO: Update session table
    //
    // Long-term, we want to keep at least the sessions that remain valid under the new
    // configuration. But this requires reporting the internal state from the old allocator to the
    // new one, or we risk allocating again some IPs and ports that are already in use for existing
    // sessions. We don't support this yet.
    //
    // Short-term, we want to drop all existing sessions from the table and start fresh. This first
    // requires the NAT code to move to the new session table implementation, which has not been
    // done as of this writing.
    //
    // Side note: session table and allocator may need to be updated at the same time, so we might
    // need a lock around them in the StatefulNat stage and we may need to update them both from
    // .update_allocator().
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

fn apply_tracing_config(tracing: &Option<TracingConfig>) -> ConfigResult {
    // Apply tracing config if provided. Otherwise, apply an empty/default config.
    let default = TracingConfig::default();
    let tracing = tracing.as_ref().unwrap_or(&default);
    get_trace_ctl().reconfigure(
        Some(tracing.default),
        tracing
            .tags
            .iter()
            .map(|(tag, level)| (tag.as_str(), *level)),
    )?;
    Ok(())
}

fn apply_device_config(device: &DeviceConfig) -> ConfigResult {
    apply_tracing_config(&device.tracing)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Main function to apply a config
async fn apply_gw_config(
    vpc_mgr: &VpcManager<RequiredInformationBase>,
    config: &mut GwConfig,
    _current: Option<&GwConfig>,
    router_ctl: &mut RouterCtlSender,
    vpcmapw: &mut VpcMapWriter<VpcMapName>,
    nattablesw: &mut NatTablesWriter,
    natallocatorw: &mut NatAllocatorWriter,
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

    /* apply device config */
    apply_device_config(&config.external.device)?;

    if genid == ExternalConfig::BLANK_GENID {
        /* apply config with VPC manager */
        vpc_mgr.apply_config(internal, genid).await?;
        info!("Successfully applied config for genid {genid}");
        return Ok(());
    }

    /* lock the CPI to prevent updates on the routing db */
    let _guard = router_ctl
        .lock()
        .await
        .map_err(|_| ConfigError::InternalFailure("Could not lock the CPI".to_string()))?;

    /* apply config with VPC manager */
    vpc_mgr.apply_config(internal, genid).await?;

    /* get vrf interfaces from kernel and build a hashmap keyed by name */
    let kernel_vrfs = vpc_mgr.get_kernel_vrfs().await?;

    /* apply stateless NAT config */
    apply_stateless_nat_config(&config.external.overlay.vpc_table, nattablesw)?;

    /* apply stateful NAT config */
    apply_stateful_nat_config(&config.external.overlay.vpc_table, natallocatorw)?;

    /* apply dst_vpcd_lookup config */
    apply_dst_vpcd_lookup_config(&config.external.overlay, vpcdtablesw)?;

    /* update stats mappings and seed names to the stats store */
    let pairs = update_stats_vpc_mappings(config, vpcmapw);
    drop(pairs); // pairs used by caller

    /* apply config in router */
    apply_router_config(&kernel_vrfs, config, router_ctl).await?;

    info!("Successfully applied config for genid {genid}");
    Ok(())
}
