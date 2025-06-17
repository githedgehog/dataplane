// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router configuration

#![allow(unused)]

mod interface;
mod vrf;

use net::vxlan::Vni;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::format,
};
use tracing::{debug, error};

use crate::RouterError;
use crate::interfaces::iftable::IfTable;
use crate::interfaces::interface::IfIndex;
use crate::interfaces::interface::RouterInterfaceConfig;
use crate::rib::VrfTable;
use crate::rib::vrf::{RouterVrfConfig, VrfId};
use crate::routingdb::RoutingDb;

use crate::config::interface::ReconfigInterfacePlan;
use crate::config::vrf::ReconfigVrfPlan;

//////////////////////////////////////////////////////////////////////////////////
/// The main configuration object for a router
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
pub struct RouterConfig {
    genid: i64, /* not using mgmt GenId to avoid circ dependencies */
    vrfs: BTreeMap<VrfId, RouterVrfConfig>,
    interfaces: BTreeMap<IfIndex, RouterInterfaceConfig>,
}

/// Builder methods
impl RouterConfig {
    pub fn new(genid: i64) -> Self {
        Self {
            genid,
            vrfs: BTreeMap::new(),
            interfaces: BTreeMap::new(),
        }
    }
    pub fn add_vrf(&mut self, vrfconfig: RouterVrfConfig) {
        self.vrfs.insert(vrfconfig.vrfid, vrfconfig);
    }
    pub fn add_interface(&mut self, ifconfig: RouterInterfaceConfig) {
        self.interfaces.insert(ifconfig.ifindex, ifconfig);
    }
    pub fn validate(&self) -> Result<(), RouterError> {
        let mut num_vnis = 0;
        let vnis = self
            .vrfs()
            .filter_map(|vrf| {
                if vrf.vni.is_some() {
                    num_vnis += 1;
                }
                vrf.vni
            })
            .collect::<BTreeSet<Vni>>();
        if vnis.len() != num_vnis {
            return Err(RouterError::InvalidConfig("Duplicated vnis"));
        }
        Ok(())
    }
}

/// Lookup and iterators
impl RouterConfig {
    //////////////////////////////////////////////////////////////////////////////////
    /// Get the config for a Vrf with a given [`VrfId`]
    //////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    fn get_vrf(&self, vrfid: VrfId) -> Option<&RouterVrfConfig> {
        self.vrfs.get(&vrfid)
    }

    //////////////////////////////////////////////////////////////////////////////////
    /// Mutably get the config for a Vrf with a given [`VrfId`]
    //////////////////////////////////////////////////////////////////////////////////
    #[cfg(test)]
    #[must_use]
    fn get_vrf_mut(&mut self, vrfid: VrfId) -> Option<&mut RouterVrfConfig> {
        self.vrfs.get_mut(&vrfid)
    }

    //////////////////////////////////////////////////////////////////////////////////
    /// Iterate over the [`RouterVrfConfig`]s in this [`RouterConfig`]
    //////////////////////////////////////////////////////////////////////////////////
    fn vrfs(&self) -> impl Iterator<Item = &RouterVrfConfig> {
        self.vrfs.values()
    }

    //////////////////////////////////////////////////////////////////////////////////
    /// Get the config for an interface with a given [`IfIndex`]
    //////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    fn get_interface(&self, ifindex: IfIndex) -> Option<&RouterInterfaceConfig> {
        self.interfaces.get(&ifindex)
    }

    //////////////////////////////////////////////////////////////////////////////////
    /// Mutably get the config for an interface with a given [`IfIndex`]
    //////////////////////////////////////////////////////////////////////////////////
    #[cfg(test)]
    #[must_use]
    fn get_interface_mut(&mut self, ifindex: IfIndex) -> Option<&mut RouterInterfaceConfig> {
        self.interfaces.get_mut(&ifindex)
    }

    //////////////////////////////////////////////////////////////////////////////////
    /// Iterate over the [`RouterInterfaceConfig`]s in this [`RouterConfig`]
    //////////////////////////////////////////////////////////////////////////////////
    fn interfaces(&self) -> impl Iterator<Item = &RouterInterfaceConfig> {
        self.interfaces.values()
    }

    //////////////////////////////////////////////////////////////////////////////////
    /// Apply a configuration
    //////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn apply(&self, db: &mut RoutingDb) -> Result<(), RouterError> {
        let genid = self.genid;
        self.validate()?; /* validate the config */
        ReconfigVrfPlan::generate(self, &mut db.vrftable).apply(&mut db.vrftable)?;
        let iftabler = db.iftw.enter().unwrap_or_else(|| unreachable!());
        let reconfig_ifaces = ReconfigInterfacePlan::generate(self, &iftabler);
        drop(iftabler);
        reconfig_ifaces.apply(&mut db.iftw, &mut db.vrftable)?;
        debug!("Successfully applied router config for generation {genid}");
        self.verify(&db)?;
        Ok(())
    }
}

/// Verification
impl RouterConfig {
    fn verify_vrf(vrf_cfg: &RouterVrfConfig, vrftable: &VrfTable) -> Result<(), RouterError> {
        debug!("Verifying vrf {}...", &vrf_cfg.name);
        let vrf = vrftable.get_vrf(vrf_cfg.vrfid)?;
        if vrf.as_config() != *vrf_cfg {
            error!("Vrf {} has not been correctly reconfigured!:", vrf.name);
            error!("Config:\n{vrf_cfg:#?}");
            error!("Vrf:\n{vrf}");
            return Err(RouterError::VerifyFailure(format!(
                "Vrf with id {}",
                vrf.vrfid
            )));
        }
        if vrf.vni.is_some() {
            vrftable.check_vni(vrf.vrfid)?;
        }
        Ok(())
    }
    fn verify_vrfs(&self, db: &RoutingDb) -> Result<(), RouterError> {
        for vrf_cfg in self.vrfs() {
            Self::verify_vrf(vrf_cfg, &db.vrftable)?;
        }
        Ok(())
    }
    fn verify_interface(
        ifconfig: &RouterInterfaceConfig,
        iftable: &IfTable,
    ) -> Result<(), RouterError> {
        debug!("Verifying interface {}...", &ifconfig.name);
        let iface = iftable.get_interface(ifconfig.ifindex).ok_or_else(|| {
            RouterError::VerifyFailure(format!("interface {}: no such interface", ifconfig.ifindex))
        })?;
        let ifindex = ifconfig.ifindex;
        let built = iface.as_config();
        if built != *ifconfig {
            error!("Verification of interface {ifindex} failed!");
            error!("Requested config:\n{ifconfig:#?}");
            error!("Applied config:\n{built:#?}");
            return Err(RouterError::VerifyFailure(format!(
                "interface with ifindex {ifindex}"
            )));
        }
        Ok(())
    }
    fn verify_interfaces(&self, db: &RoutingDb) -> Result<(), RouterError> {
        let iftable = &*db.iftw.enter().unwrap_or_else(|| unreachable!());
        for ifconfig in self.interfaces() {
            Self::verify_interface(ifconfig, iftable)?;
        }
        Ok(())
    }
    fn verify(&self, db: &RoutingDb) -> Result<(), RouterError> {
        let genid = self.genid;
        debug!("Verifying config {genid}...");
        self.verify_vrfs(db)?;
        self.verify_interfaces(db)?;
        debug!("Successfully verified router config for generation {genid}");
        Ok(())
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use tracing_test::traced_test;
    use tracing::debug;
    use net::{route::RouteTableId, vxlan::Vni};
    use net::eth::mac::Mac;
    use crate::{config::RouterConfig, interfaces::interface::{AttachConfig, RouterInterfaceConfig}, rib::vrf::RouterVrfConfig};
    use crate::interfaces::interface::IfState;
    use crate::interfaces::interface::IfType;
    use crate::interfaces::interface::IfDataEthernet;

    use crate::RouterError;
    use crate::routingdb::RoutingDb;
    use crate::interfaces::iftablerw::IfTableWriter;
    use crate::fib::fibtable::FibTableWriter;
    use crate::atable::resolver::AtResolver;


    fn mk_vni(vni: u32) -> Vni {
        vni.try_into().expect("Bad vni")
    }
    fn mk_tableid(id: u32) -> RouteTableId {
        id.try_into().expect("Bad table-id")
    }

    fn add_router_vrf_configs(config: &mut RouterConfig) {
        // N.B. default VRF is automatically created

        // VRF for VPC-1
        let vrf = RouterVrfConfig::new(100, "AAAAA-vrf")
            .set_description("VRF for VPC-1")
            .set_tableid(mk_tableid(1000))
            .set_vni(mk_vni(3000));
        config.add_vrf(vrf);

        // VRF for VPC-2
        let vrf = RouterVrfConfig::new(101, "BBBBB-vrf")
            .set_description("VRF for VPC-2")
            .set_tableid(mk_tableid(1001))
            .set_vni(mk_vni(4000));
        config.add_vrf(vrf);

        // VRF for VPC-2
        let vrf = RouterVrfConfig::new(102, "CCCCC-vrf")
            .set_description("VRF for VPC-3")
            .set_tableid(mk_tableid(1002))
            .set_vni(mk_vni(6000));
        config.add_vrf(vrf);

    }
    fn add_router_interface_configs(config: &mut RouterConfig) {
        let mut ifconfig = RouterInterfaceConfig::new("Loopback", 1);
        ifconfig.set_description("main loopback interface");
        ifconfig.set_iftype(IfType::Loopback);
        ifconfig.set_admin_state(IfState::Up);
        config.add_interface(ifconfig);

        let mut ifconfig = RouterInterfaceConfig::new("Eth0", 10);
        ifconfig.set_description("Interface to Spine-1");
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x2]),
        }));
        ifconfig.set_attach_cfg(Some(AttachConfig::VRF(100)));
        config.add_interface(ifconfig);

        let mut ifconfig = RouterInterfaceConfig::new("Eth1", 11);
        ifconfig.set_description("Interface to Spine-2");
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x2]),
        }));
        config.add_interface(ifconfig);

    }
    fn build_router_config() -> RouterConfig {
        let mut config = RouterConfig::new(1);
        add_router_vrf_configs(&mut config);
        add_router_interface_configs(&mut config);
        config
    }
    fn create_routing_database() -> RoutingDb {
        let (iftw, _iftr) = IfTableWriter::new();
        let (fibtw, _fibtr) = FibTableWriter::new();
        let (_resolver, atabler) = AtResolver::new(false);
        RoutingDb::new(fibtw, iftw, atabler)
    }
    fn test_apply_config(config: &RouterConfig, db: &mut RoutingDb) -> Result<(), RouterError> {
        config.apply(db)?;
        let iftr = db.iftw.enter().unwrap();
        println!("\n{}", &db.vrftable);
        println!("\n{}", *iftr);
        println!("\n ████████ SUCCESSFULLY applied and verified config {} ███████\n", config.genid);
        Ok(())
    }

    #[traced_test]
    #[test]
    fn test_config_initial() {
        let mut db = create_routing_database();
        let mut config = build_router_config();
        test_apply_config(&config, &mut db).expect("Should succeed");
    }

    #[traced_test]
    #[test]
    fn test_config_invalid() {
        let mut db = create_routing_database();
        let mut config = build_router_config();

        // modify the config to make it invalid: let two vrfs have the same vni
        let conf1 = config.get_vrf(100).expect("Should find vrf config");
        assert!(conf1.vni.is_some());
        let duped_vni = conf1.vni.clone();

        let conf2 = config.get_vrf_mut(101).expect("Should find vrf config");
        conf2.reset_vni(duped_vni);

        let result = test_apply_config(&config, &mut db);
        assert!(result.is_err_and(|e| matches!(e, RouterError::InvalidConfig(_))));
    }

    #[traced_test]
    #[test]
    fn test_config_reapply() {
        let mut db = create_routing_database();
        let mut config = build_router_config();
        test_apply_config(&config, &mut db).expect("Should succeed");
        config.genid = 2;
        test_apply_config(&config, &mut db).expect("Should succeed");
    }

    #[traced_test]
    #[test]
    fn test_config_reconfig_vrf_name_and_vni() {
        let mut db = create_routing_database();
        let mut config = build_router_config();
        test_apply_config(&config, &mut db).expect("Should succeed");

        config.genid = 3;
        let new_vni = mk_vni(666);
        let vrfid = 100;
        debug!("━━━━Test: Change name of vrf {vrfid} and its vni to {new_vni}");
        let vrf = config.get_vrf_mut(100).expect("Should find it");
        vrf.set_name("CHANGED");
        vrf.reset_vni(Some(new_vni));

        test_apply_config(&config, &mut db).expect("Should succeed");
    }

    #[traced_test]
    #[test]
    fn test_config_reconfig_vnis() {
        let mut db = create_routing_database();
        let mut config = build_router_config();
        test_apply_config(&config, &mut db).expect("Should succeed");

        config.genid = 4;
        let new_vni = mk_vni(6000);
        debug!("━━━━━━━━ Test: Remove vni {new_vni} from one vrf and associate it to another");
        let vrf = config.get_vrf_mut(101).expect("Should find it");
        vrf.reset_vni(Some(mk_vni(6000)));
        let vrf = config.get_vrf_mut(102).expect("Should find it");
        vrf.reset_vni(None);

        test_apply_config(&config, &mut db).expect("Should succeed");
    }

    #[traced_test]
    #[test]
    fn test_config_swap_vrf_vnis() {
        let mut db = create_routing_database();
        let mut config = build_router_config();
        test_apply_config(&config, &mut db).expect("Should succeed");

        debug!("━━━━━━━━ Test: Swap the vnis of two vrfs");
        config.genid = 5;
        let vrf1 = db.vrftable.get_vrf(100).expect("Should find vrf");
        let vrf2 = db.vrftable.get_vrf(101).expect("Should find vrf");
        let vni1 = vrf1.vni.expect("Should have vni");
        let vni2 = vrf2.vni.expect("Should have vni");

        let vrf = config.get_vrf_mut(100).expect("Should find config");
        vrf.reset_vni(Some(vni2));

        let vrf = config.get_vrf_mut(101).expect("Should find config");
        vrf.reset_vni(Some(vni1));
        test_apply_config(&config, &mut db).expect("Should succeed");
    }


    #[traced_test]
    #[test]
    fn test_config_change_interface() {
        let mut db = create_routing_database();
        let mut config = build_router_config();
        test_apply_config(&config, &mut db).expect("Should succeed");

        debug!("━━━━━━━━ Test: Change interface name, mac, admin state and attach it to another vrf");
        config.genid = 6;
        let ifconfig = config.get_interface_mut(10).expect("Should find config");
        ifconfig.set_name("CHANGED-NAME");
        ifconfig.set_description("Interface with changed config");
        ifconfig.set_admin_state(IfState::Down);
        ifconfig.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xFF, 0xaa, 0xbb, 0xcc, 0xdd]),
        }));
        ifconfig.set_attach_cfg(Some(AttachConfig::VRF(101)));
        test_apply_config(&config, &mut db).expect("Should succeed");

        debug!("━━━━━━━━ Test: Detach interface");
        config.genid = 7;
        let ifconfig = config.get_interface_mut(10).expect("Should find config");
        ifconfig.set_attach_cfg(None);
        test_apply_config(&config, &mut db).expect("Should succeed");
    }
}
