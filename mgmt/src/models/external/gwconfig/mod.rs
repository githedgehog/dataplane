// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gateway configuration (external)
//! The external config contains the intended configuration externally received (e.g. via gRPC)

use crate::models::external::ConfigResult;
use crate::models::internal::InternalConfig;
use crate::models::internal::device::DeviceConfig;
use crate::models::internal::routing::vrf::VrfConfig;
use crate::models::{external::overlay::Overlay, internal::device::settings::DeviceSettings};
use derive_builder::Builder;
use interface_manager::interface::{
    BridgePropertiesSpec, BridgePropertiesSpecBuilder, InterfaceAssociationSpec,
    InterfaceAssociationSpecBuilder, InterfacePropertiesSpec, InterfaceSpecBuilder,
    MultiIndexInterfaceAssociationSpecMap, MultiIndexInterfaceSpecMap,
    MultiIndexVrfPropertiesSpecMap, MultiIndexVtepPropertiesSpecMap, VrfPropertiesSpecBuilder,
    VtepPropertiesSpecBuilder,
};
use net::eth::mac::SourceMac;
use net::interface::{
    AdminState, BridgePropertiesBuilder, InterfaceBuilder, VtepPropertiesBuilder,
};
use net::ipv4::UnicastIpv4Addr;
use std::net::IpAddr;
use std::time::SystemTime;
use tracing::{debug, error, info, warn};

use crate::frr::frrmi::FrrMi;
use crate::models::internal::interfaces::interface::InterfaceType;
use crate::processor::confbuild::build_internal_config;

/// Alias for a config generation number
pub type GenId = i64;
use crate::processor::proc::apply_gw_config;
use crate::vpc_manager::{
    RequiredInformationBase, RequiredInformationBaseBuilder, RequiredInformationBaseBuilderError,
};

#[derive(Clone, Default, Debug)]
pub struct Underlay {
    pub vrf: VrfConfig, /* default vrf */
}
impl Underlay {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating underlay configuration...");

        // validate interfaces
        self.vrf
            .interfaces
            .iter_by_name()
            .try_for_each(|iface| iface.validate())?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
/// Configuration metadata. Every config object stored by the dataplane has metadata
pub struct GwConfigMeta {
    pub created: SystemTime,           /* time when config was built (received) */
    pub applied: Option<SystemTime>,   /* last time when config was applied successfully */
    pub unapplied: Option<SystemTime>, /* time when config was un-applied */
    pub is_applied: bool,              /* True if the config is currently applied */
}
impl GwConfigMeta {
    fn new() -> Self {
        Self {
            created: SystemTime::now(),
            applied: None,
            unapplied: None,
            is_applied: false,
        }
    }
}

/// The configuration object as seen by the gRPC server
#[derive(Builder, Clone, Debug)]
pub struct ExternalConfig {
    pub genid: GenId,         /* configuration generation id (version) */
    pub device: DeviceConfig, /* goes as-is into the internal config */
    pub underlay: Underlay,   /* goes as-is into the internal config */
    pub overlay: Overlay,     /* VPCs and peerings -- get highly developed in internal config */
}

impl Default for ExternalConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalConfig {
    pub const BLANK_GENID: GenId = 0;

    pub fn new() -> Self {
        Self {
            genid: Self::BLANK_GENID,
            device: DeviceConfig::new(DeviceSettings::new("Unset")),
            underlay: Underlay::default(),
            overlay: Overlay::default(),
        }
    }

    pub fn validate(&self) -> ConfigResult {
        self.device.validate()?;
        self.underlay.validate()?;
        self.overlay.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct GwConfig {
    pub meta: GwConfigMeta,               /* config metadata */
    pub external: ExternalConfig,         /* external config: received */
    pub internal: Option<InternalConfig>, /* internal config: built by gw from internal */
}

impl GwConfig {
    /// Create a [`GwConfig`] object with a given [`ExternalConfig`].
    pub fn new(external: ExternalConfig) -> Self {
        Self {
            meta: GwConfigMeta::new(),
            external,
            internal: None,
        }
    }
    /// Create a blank [`GwConfig`] with an empty [`ExternalConfig`].
    /// Such a config has generation id 0 (from the empty [`ExternalConfig`]).
    pub fn blank() -> Self {
        Self::new(ExternalConfig::new())
    }

    /// Return the [`GenId`] of a [`GwConfig`] object.
    pub fn genid(&self) -> GenId {
        self.external.genid
    }

    /// Mark/unmark config as applied
    pub fn set_applied(&mut self, value: bool) {
        if value {
            self.meta.applied = Some(SystemTime::now());
            self.meta.unapplied.take();
        } else {
            self.meta.unapplied = Some(SystemTime::now());
        }
        self.meta.is_applied = value;
    }

    /// Validate a [`GwConfig`].
    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating external config with genid {} ..", self.genid());
        self.external.validate()
    }

    /// Build the [`InternalConfig`] for this [`GwConfig`].
    pub(crate) fn build_internal_config(&mut self) -> ConfigResult {
        /* build and set internal config */
        self.internal = Some(build_internal_config(self)?);
        Ok(())
    }

    /// Apply a [`GwConfig`].
    pub async fn apply(
        &mut self,
        frrmi: &mut FrrMi,
        netlink: &mut rtnetlink::Handle,
    ) -> ConfigResult {
        info!("Applying config with genid {}...", self.genid());
        if self.internal.is_none() {
            debug!("Config has no internal config...");
            self.build_internal_config()?;
        }

        /* Apply this gw config */
        apply_gw_config(self, frrmi, netlink).await?;
        self.meta.applied = Some(SystemTime::now());
        self.meta.is_applied = true;
        Ok(())
    }
}

// This is very hacky, but I need it to validate the design.  Will break this down soon.
impl TryFrom<&InternalConfig> for RequiredInformationBase {
    type Error = RequiredInformationBaseBuilderError;

    fn try_from(config: &InternalConfig) -> Result<Self, Self::Error> {
        let mut rib = RequiredInformationBaseBuilder::default();
        let mut interfaces = MultiIndexInterfaceSpecMap::default();
        let mut vrfs = MultiIndexVrfPropertiesSpecMap::default();
        let mut vteps = MultiIndexVtepPropertiesSpecMap::default();
        let mut associations = MultiIndexInterfaceAssociationSpecMap::default();
        for config in config.vrfs.iter_by_name() {
            if config.default {
                continue;
            }
            let mut vrf = InterfaceSpecBuilder::default();
            let mut vtep = InterfaceSpecBuilder::default();
            let mut bridge = InterfaceSpecBuilder::default();
            for iface in config.interfaces.iter_by_name() {
                match &iface.iftype {
                    InterfaceType::Loopback
                    | InterfaceType::Ethernet(_)
                    | InterfaceType::Vlan(_) => {}
                    InterfaceType::Bridge(bridge_config) => {
                        let mut properties = BridgePropertiesSpecBuilder::default();
                        properties.vlan_filtering(bridge_config.vlan_filtering);
                        properties.vlan_protocol(bridge_config.vlan_protocol);
                        #[allow(clippy::expect_used)]
                        // we _just_ put together all the needed fields.
                        let properties = properties.build().expect("programmer error");
                        bridge.properties(InterfacePropertiesSpec::Bridge(properties));
                        bridge.name(iface.name.clone());
                        bridge.admin_state(AdminState::Up);
                    }
                    InterfaceType::Vtep(vtep_config) => {
                        let mut properties = VtepPropertiesSpecBuilder::default();
                        let Some(vni) = vtep_config.vni else {
                            continue;
                        };
                        let Some(mac) = vtep_config.mac else {
                            continue;
                        };
                        let Ok(mac) = SourceMac::new(mac) else {
                            error!("vtep given multicast mac: {mac}");
                            continue;
                        };
                        properties.vni(vni);
                        vtep.name(iface.name.clone());
                        vtep.mac(Some(mac));
                        vtep.admin_state(AdminState::Up);
                        match vtep_config.local {
                            IpAddr::V4(ip) => {
                                let Ok(local) = UnicastIpv4Addr::new(ip) else {
                                    error!("multicast vtep local specified: {ip}");
                                    continue;
                                };
                                properties.local(local);
                            }
                            IpAddr::V6(ip) => {
                                warn!("unable to configure vtep with ipv6 local: {ip}");
                                continue;
                            }
                        }
                        if let Some(ttl) = vtep_config.ttl {
                            properties.ttl(ttl);
                        }
                        #[allow(clippy::expect_used)] // we _just_ filled out all the fields
                        let properties = properties.build().expect("programmer error");
                        vtep.properties(InterfacePropertiesSpec::Vtep(properties));
                    }
                    InterfaceType::Vrf(vrf_config) => {
                        let mut vrf_properties = VrfPropertiesSpecBuilder::default();
                        vrf_properties.route_table_id(vrf_config.table_id);
                        let vrf_properties = match vrf_properties.build() {
                            Ok(spec) => spec,
                            Err(err) => {
                                // we _just_ set the route table id
                                error!("failed to build vrf properties: {err}");
                                unreachable!("failed to build vrf properties");
                            }
                        };
                        vrf.properties(InterfacePropertiesSpec::Vrf(vrf_properties));
                        vrf.admin_state(AdminState::Up);
                        vrf.name(iface.name.clone());
                    }
                }
            }
            match (vrf.build(), bridge.build(), vtep.build()) {
                (Ok(vrf), Ok(bridge), Ok(vtep)) => {
                    match interfaces.try_insert(vrf.clone()) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("{e}")
                        }
                    }
                    match interfaces.try_insert(bridge.clone()) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("{e}")
                        }
                    }
                    match interfaces.try_insert(vtep.clone()) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("{e}")
                        }
                    }
                    match &vrf.properties {
                        InterfacePropertiesSpec::Vrf(props) => {
                            match vrfs.try_insert(props.clone()) {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("{e}")
                                }
                            }
                        }
                        _ => unreachable!(),
                    };
                    match &vtep.properties {
                        InterfacePropertiesSpec::Vtep(props) => {
                            match vteps.try_insert(props.clone()) {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("{e}")
                                }
                            }
                        }
                        _ => unreachable!(),
                    };

                    let vrf_in_nothing = InterfaceAssociationSpec {
                        name: vrf.name.clone(),
                        controller_name: None,
                    };
                    let bridge_in_vrf = InterfaceAssociationSpec {
                        name: bridge.name.clone(),
                        controller_name: Some(vrf.name.clone()),
                    };
                    let vtep_in_bridge = InterfaceAssociationSpec {
                        name: vtep.name.clone(),
                        controller_name: Some(bridge.name.clone()),
                    };
                    match associations.try_insert(vrf_in_nothing) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("{e}");
                        }
                    }
                    match associations.try_insert(bridge_in_vrf) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("{e}");
                        }
                    }
                    match associations.try_insert(vtep_in_bridge) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("{e}");
                        }
                    }
                }
                (Err(e), _, _) => {
                    warn!("{e}");
                    continue;
                }
                (_, Err(e), _) => {
                    warn!("{e}");
                    continue;
                }
                (_, _, Err(e)) => {
                    warn!("{e}");
                    continue;
                }
            }
        }
        rib.interfaces(interfaces);
        rib.vteps(vteps);
        rib.vrfs(vrfs);
        rib.associations(associations);
        rib.build()
    }
}
