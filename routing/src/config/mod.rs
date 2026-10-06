// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router configuration

mod interface;
mod vrf;
mod vtep;

use crate::RouterError;
use crate::evpn::Vtep;
use crate::interfaces::iftable::IfTable;
use crate::interfaces::interface::RouterInterfaceConfig;
use crate::rib::VrfTable;
use crate::rib::vrf::{RouterVrfConfig, VrfId};
use crate::routingdb::RoutingDb;
use config::GenId;
use net::interface::InterfaceIndex;
use net::vxlan::Vni;
use std::collections::{BTreeMap, BTreeSet};
use tracing::{debug, error};

use crate::config::interface::ReconfigInterfacePlan;
use crate::config::vrf::ReconfigVrfPlan;
use crate::config::vtep::apply_vtep_config;

/// Alias for FRR config. Currently, FRR config is received as a string.
pub type FrrConfig = String;

//////////////////////////////////////////////////////////////////////////////////
/// The main configuration object for a router
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
pub struct RouterConfig {
    genid: GenId,
    vrfs: BTreeMap<VrfId, RouterVrfConfig>,
    interfaces: BTreeMap<InterfaceIndex, RouterInterfaceConfig>,
    vtep: Option<Vtep>,
    frr_cfg: Option<FrrConfig>,
}

/// Builder methods
impl RouterConfig {
    #[must_use]
    pub fn new(genid: GenId) -> Self {
        Self {
            genid,
            vrfs: BTreeMap::new(),
            interfaces: BTreeMap::new(),
            vtep: None,
            frr_cfg: None,
        }
    }
    #[must_use]
    pub fn genid(&self) -> GenId {
        self.genid
    }
    pub fn add_vrf(&mut self, vrfconfig: RouterVrfConfig) {
        self.vrfs.insert(vrfconfig.vrfid, vrfconfig);
    }
    pub fn add_interface(&mut self, ifconfig: RouterInterfaceConfig) {
        self.interfaces.insert(ifconfig.ifindex, ifconfig);
    }
    pub fn set_vtep(&mut self, vtep: Vtep) {
        self.vtep = Some(vtep);
    }
    pub fn set_frr_config(&mut self, frr_cfg: FrrConfig) {
        self.frr_cfg = Some(frr_cfg);
    }
    #[must_use]
    pub fn get_frr_config(&self) -> &Option<FrrConfig> {
        &self.frr_cfg
    }
    pub fn validate(&self) -> Result<(), RouterError> {
        // check for duplicate vnis
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
        // Check vtep if there
        if num_vnis > 0 && self.vtep.is_none() {
            return Err(RouterError::InvalidConfig("Vtep is not set up"));
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
    pub(crate) fn get_interface(&self, ifindex: InterfaceIndex) -> Option<&RouterInterfaceConfig> {
        self.interfaces.get(&ifindex)
    }

    //////////////////////////////////////////////////////////////////////////////////
    /// Mutably get the config for an interface with a given [`IfIndex`]
    //////////////////////////////////////////////////////////////////////////////////
    #[cfg(test)]
    #[must_use]
    fn get_interface_mut(&mut self, ifindex: InterfaceIndex) -> Option<&mut RouterInterfaceConfig> {
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

        // validate the config
        self.validate()?;

        // build and apply vrf reconfiguration plan
        ReconfigVrfPlan::generate(self, &db.vrftable).apply(&mut db.vrftable, &mut db.iftw)?;

        // build and apply interface reconfiguration
        let iftable = db.iftw.enter().unwrap_or_else(|| unreachable!());
        let reconfig_ifaces = ReconfigInterfacePlan::generate(self, &iftable);
        drop(iftable);
        reconfig_ifaces.apply(&mut db.iftw, &db.vrftable)?;

        // store and apply vtep configuration (infallible)
        apply_vtep_config(self.vtep.as_ref(), db);

        debug!("Successfully applied router config for generation {genid}");
        self.verify(db)?;
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
    fn verify_vteps(&self, db: &RoutingDb) -> Result<(), RouterError> {
        debug!("Verifying vtep status");
        // the fib of a vrf must have the vtep if and only if the vrf has a vni
        let vtep = self.vtep.as_ref();
        let mut inconsistent_vrfs = vec![];
        for vrf in db.vrftable.values() {
            let wanted = vtep.filter(|_| vrf.vni.is_some());
            let current = vrf.get_vtep();
            if current.as_ref() != wanted {
                error!(
                    "BUG: Vrf {} (vni: {:?}) has vtep {current:?}, expected {wanted:?}",
                    vrf.name, vrf.vni
                );
                inconsistent_vrfs.push(vrf.vrfid);
            }
        }
        if !inconsistent_vrfs.is_empty() {
            return Err(RouterError::VtepInfoInconsistency(inconsistent_vrfs));
        }
        debug!("Vtep information is consistent in all VRFs");
        Ok(())
    }
    fn verify(&self, db: &RoutingDb) -> Result<(), RouterError> {
        let genid = self.genid;
        debug!("Verifying router config for config generation {genid}...");
        self.verify_vrfs(db)?;
        self.verify_interfaces(db)?;
        self.verify_vteps(db)?;
        debug!("Successfully verified router config for generation {genid}");
        Ok(())
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use std::str::FromStr;
    use tracing_test::traced_test;
    use tracing::debug;
    use net::{route::RouteTableId, vxlan::Vni};
    use net::eth::mac::SourceMac;
    use net::ip::UnicastIpAddr;
    use net::interface::{InterfaceName, InterfaceIndex};
    use crate::{config::RouterConfig, evpn::Vtep, interfaces::interface::AttachConfig, rib::vrf::RouterVrfConfig};
    use crate::interfaces::interface::IfState;
    use crate::interfaces::interface::IfType;
    use crate::interfaces::interface::IfDataEthernet;
    use crate::interfaces::tests::build_test_interface_cfg;

    use crate::RouterError;
    use crate::routingdb::RoutingDb;
    use crate::interfaces::iftablerw::IfTableWriter;
    use crate::fib::fibtable::FibTableWriter;
    use crate::atable::resolver::AtResolver;


    pub(super) fn mk_vni(vni: u32) -> Vni {
        vni.try_into().expect("Bad vni")
    }
    pub(super) fn mk_tableid(id: u32) -> RouteTableId {
        id.try_into().expect("Bad table-id")
    }

    fn add_router_vrf_configs(config: &mut RouterConfig) {
        // N.B. default VRF is automatically created

        // VRF for VPC-1
        let vrf = RouterVrfConfig::new(100, "AAAAA-vrf")
            .set_vpcname("VRF for VPC-1")
            .set_tableid(mk_tableid(1000))
            .set_vni(Some(mk_vni(3000)));
        config.add_vrf(vrf);

        // VRF for VPC-2
        let vrf = RouterVrfConfig::new(101, "BBBBB-vrf")
            .set_vpcname("VRF for VPC-2")
            .set_tableid(mk_tableid(1001))
            .set_vni(Some(mk_vni(4000)));
        config.add_vrf(vrf);

        // VRF for VPC-2
        let vrf = RouterVrfConfig::new(102, "CCCCC-vrf")
            .set_vpcname("VRF for VPC-3")
            .set_tableid(mk_tableid(1002))
            .set_vni(Some(mk_vni(6000)));
        config.add_vrf(vrf);

    }
    fn add_router_interface_configs(config: &mut RouterConfig) {
        let mut ifconfig = build_test_interface_cfg("Loopback", 1);
        ifconfig.set_description("main loopback interface");
        ifconfig.set_iftype(IfType::Loopback);
        ifconfig.set_admin_state(IfState::Up);
        config.add_interface(ifconfig);

        let mut ifconfig = build_test_interface_cfg("Eth0", 10);
        ifconfig.set_description("Interface to Spine-1");
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_iftype(IfType::Ethernet(IfDataEthernet::new(
            SourceMac::try_from("00:aa:00:00:00:02").unwrap()
        )));
        ifconfig.set_attach_cfg(Some(AttachConfig::Vrf(100)));
        config.add_interface(ifconfig);

        let mut ifconfig = build_test_interface_cfg("Eth1", 11);
        ifconfig.set_description("Interface to Spine-2");
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_iftype(IfType::Ethernet(IfDataEthernet::new(
            SourceMac::try_from("00:bb:00:00:00:02").unwrap()
        )));
        config.add_interface(ifconfig);

    }
    fn add_router_vtep_config(config: &mut RouterConfig) {
        let vtep_ip = UnicastIpAddr::from_str("7.0.0.100").unwrap();
        let vtep_mac = SourceMac::try_from("00:ca:fe:be:ff:44").expect("Bad mac");
        let vtep = Vtep::new(vtep_ip, vtep_mac);
        config.set_vtep(vtep);
    }
    fn build_router_config() -> RouterConfig {
        let mut config = RouterConfig::new(1);
        add_router_vrf_configs(&mut config);
        add_router_interface_configs(&mut config);
        add_router_vtep_config(&mut config);
        config
    }
    pub(super) fn create_routing_database() -> RoutingDb {
        let (iftw, _iftr) = IfTableWriter::new();
        let (fibtw, _fibtr) = FibTableWriter::new();
        let (_resolver, atabler) = AtResolver::new(false);
        RoutingDb::new(fibtw, iftw, atabler)
    }
    fn test_apply_config(config: &RouterConfig, db: &mut RoutingDb) -> Result<(), RouterError> {
        config.apply(db)?;
        let iftr = db.iftw.enter().unwrap();
        println!("\n{}", db.vrftable);
        println!("\n{}", *iftr);
        println!("\n ████████ SUCCESSFULLY applied and verified config {} ███████\n", config.genid);
        Ok(())
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_config_initial() {
        let mut db = create_routing_database();
        let config = build_router_config();
        test_apply_config(&config, &mut db).expect("Should succeed");
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_config_invalid() {
        let mut db = create_routing_database();
        let mut config = build_router_config();

        // modify the config to make it invalid: let two vrfs have the same vni
        let conf1 = config.get_vrf(100).expect("Should find vrf config");
        assert!(conf1.vni.is_some());
        let duped_vni = conf1.vni;

        let conf2 = config.get_vrf_mut(101).expect("Should find vrf config");
        conf2.reset_vni(duped_vni);

        let result = test_apply_config(&config, &mut db);
        assert!(result.is_err_and(|e| matches!(e, RouterError::InvalidConfig(_))));
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_config_reapply() {
        let mut db = create_routing_database();
        let mut config = build_router_config();
        test_apply_config(&config, &mut db).expect("Should succeed");
        config.genid = 2;
        test_apply_config(&config, &mut db).expect("Should succeed");
    }

    #[cfg_attr(not(emulated), traced_test)]
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

    #[cfg_attr(not(emulated), traced_test)]
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

    #[cfg_attr(not(emulated), traced_test)]
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


    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_config_change_interface() {
        let mut db = create_routing_database();
        let mut config = build_router_config();
        test_apply_config(&config, &mut db).expect("Should succeed");

        debug!("━━━━━━━━ Test: Change interface name, mac, admin state and attach it to another vrf");
        config.genid = 6;
        let idx = InterfaceIndex::try_new(10).unwrap();
        let ifconfig = config.get_interface_mut(idx).expect("Should find config");
        ifconfig.set_name(&InterfaceName::try_from("CHANGED-NAME").unwrap());
        ifconfig.set_description("Interface with changed config");
        ifconfig.set_admin_state(IfState::Down);
        ifconfig.set_iftype(IfType::Ethernet(IfDataEthernet::new(
            SourceMac::try_from("00:ff:aa:bb:cc:dd").unwrap()
        )));
        ifconfig.set_attach_cfg(Some(AttachConfig::Vrf(101)));
        test_apply_config(&config, &mut db).expect("Should succeed");

        debug!("━━━━━━━━ Test: Detach interface");
        config.genid = 7;
        let ifconfig = config.get_interface_mut(idx).expect("Should find config");
        ifconfig.set_attach_cfg(None);
        test_apply_config(&config, &mut db).expect("Should succeed");
    }

    /// Build a config with two VRFs: 100 and 101, with the given vnis and vtep
    fn build_vtep_test_config(genid: i64, vni1: Option<Vni>, vni2: Option<Vni>, vtep: Option<&Vtep>) -> RouterConfig {
        let mut config = RouterConfig::new(genid);
        config.add_vrf(RouterVrfConfig::new(100, "vrf-1").set_tableid(mk_tableid(1000)).set_vni(vni1));
        config.add_vrf(RouterVrfConfig::new(101, "vrf-2").set_tableid(mk_tableid(1001)).set_vni(vni2));
        if let Some(vtep) = vtep {
            config.set_vtep(vtep.clone());
        }
        config
    }

    /// Check that the db stores the given vtep and that the fib of each VRF has it iff the VRF has a vni
    pub(super) fn check_vteps(db: &RoutingDb, vtep: Option<&Vtep>) {
        assert_eq!(db.vtep.as_ref(), vtep, "Stored vtep does not match the config");
        for vrf in db.vrftable.values() {
            if vrf.vni.is_some() {
                assert_eq!(vrf.get_vtep().as_ref(), vtep, "Wrong vtep in vrf {} (vni: {:?})", vrf.vrfid, vrf.vni);
            } else {
                assert!(vrf.get_vtep().is_none(), "Found vtep in vrf {} without vni", vrf.vrfid);
            }
        }
    }

    /// Apply the config and check that the fib of each VRF has the vtep if and only if the VRF has a vni
    fn apply_and_check_vteps(config: &RouterConfig, db: &mut RoutingDb) {
        test_apply_config(config, db).expect("Should succeed");
        check_vteps(db, config.vtep.as_ref());
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_config_vtep() {
        // Create a routing database with 2 vrfs
        // Add a sequence of vni & vtep configuration changes and verify consistency:
        // VRFs with vni should get the vtep info as configured. VRFs without vni
        // should not get the vtep.

        let mut db = create_routing_database();
        let vni1 = Some(mk_vni(3000));
        let vni2 = Some(mk_vni(4000));
        let vtep1 = Vtep::new(UnicastIpAddr::from_str("7.0.0.100").unwrap(), SourceMac::try_from("00:ca:fe:be:ff:44").unwrap());
        let vtep2 = Vtep::new(UnicastIpAddr::from_str("7.0.0.200").unwrap(), SourceMac::try_from("00:ca:fe:be:ff:55").unwrap());

        debug!("━━━━━━━━ Test: initial config: vrf-1 has vni, vrf-2 does not");
        apply_and_check_vteps(&build_vtep_test_config(1, vni1, None, Some(&vtep1)), &mut db);

        debug!("━━━━━━━━ Test: reapply the same config");
        apply_and_check_vteps(&build_vtep_test_config(2, vni1, None, Some(&vtep1)), &mut db);

        debug!("━━━━━━━━ Test: change the vtep");
        apply_and_check_vteps(&build_vtep_test_config(3, vni1, None, Some(&vtep2)), &mut db);

        debug!("━━━━━━━━ Test: vrf-2 gets a vni, vtep unchanged");
        apply_and_check_vteps(&build_vtep_test_config(4, vni1, vni2, Some(&vtep2)), &mut db);

        debug!("━━━━━━━━ Test: vrf-1 loses its vni, vtep unchanged");
        apply_and_check_vteps(&build_vtep_test_config(5, None, vni2, Some(&vtep2)), &mut db);

        debug!("━━━━━━━━ Test: vrf-1 gets back a vni and vtep changes");
        apply_and_check_vteps(&build_vtep_test_config(6, vni1, vni2, Some(&vtep1)), &mut db);

        debug!("━━━━━━━━ Test: a config with vnis but without vtep is rejected");
        let config = build_vtep_test_config(7, vni1, vni2, None);
        let result = test_apply_config(&config, &mut db);
        assert!(result.is_err_and(|e| matches!(e, RouterError::InvalidConfig(_))));

        debug!("━━━━━━━━ Test: remove vnis and vtep");
        apply_and_check_vteps(&build_vtep_test_config(8, None, None, None), &mut db);

        debug!("━━━━━━━━ Test: vtep without vnis");
        apply_and_check_vteps(&build_vtep_test_config(9, None, None, Some(&vtep1)), &mut db);

        debug!("━━━━━━━━ Test: vnis added, vtep unchanged");
        apply_and_check_vteps(&build_vtep_test_config(10, vni1, vni2, Some(&vtep1)), &mut db);
    }
}

#[cfg(test)]
mod vtep_config_property {
    // Property test: apply random sequences of vrf / vni / vtep configs.
    // Every valid config must be applied and verified; every invalid one must be
    // rejected leaving the vtep state of the last applied config untouched.

    use super::tests::{check_vteps, create_routing_database, mk_tableid, mk_vni};
    use crate::RouterError;
    use crate::config::RouterConfig;
    use crate::evpn::Vtep;
    use crate::rib::vrf::RouterVrfConfig;
    use bolero::{Driver, ValueGenerator};
    use net::eth::mac::SourceMac;
    use net::ip::UnicastIpAddr;
    use std::collections::BTreeSet;
    use std::ops::Bound::Included;
    use std::str::FromStr;

    const NUM_VRFS: u8 = 3;
    const NUM_VNIS: u8 = 3;
    const NUM_VTEPS: u8 = 2;
    const MAX_STEPS: u8 = 10;

    fn vtep_pool() -> Vec<Vtep> {
        [
            ("7.0.0.100", "00:ca:fe:ba:be:44"),
            ("7.0.0.200", "00:de:ad:be:ef:55"),
        ]
        .iter()
        .map(|(ip, mac)| {
            Vtep::new(
                UnicastIpAddr::from_str(ip).unwrap(),
                SourceMac::try_from(*mac).unwrap(),
            )
        })
        .collect()
    }

    /// A configuration choice for a vrf
    #[derive(Debug, Clone, Copy)]
    enum VrfChoice {
        Absent,  // not configured
        NoVni,   // a vrf without Vni
        Vni(u8), // a vrf with some Vni
    }

    /// A certain configuration, valid or not
    #[derive(Debug, Clone)]
    struct VtepStep {
        vrfs: Vec<VrfChoice>,
        vtep: Option<u8>,
    }

    impl VtepStep {
        /// A config is valid iff the configured vnis are unique and vrf has a vtep iff it has a vni
        fn is_valid(&self) -> bool {
            let vnis: Vec<u8> = self
                .vrfs
                .iter()
                .filter_map(|c| match c {
                    VrfChoice::Vni(n) => Some(*n),
                    _ => None,
                })
                .collect();
            let unique: BTreeSet<u8> = vnis.iter().copied().collect();
            unique.len() == vnis.len() && (vnis.is_empty() || self.vtep.is_some())
        }
        fn build_config(&self, genid: i64, vteps: &[Vtep]) -> RouterConfig {
            let mut config = RouterConfig::new(genid);
            for (n, choice) in (0u32..).zip(&self.vrfs) {
                let vni = match choice {
                    VrfChoice::Absent => continue,
                    VrfChoice::NoVni => None,
                    VrfChoice::Vni(v) => Some(mk_vni(3000 + u32::from(*v))),
                };
                config.add_vrf(
                    RouterVrfConfig::new(100 + n, &format!("vrf-{n}"))
                        .set_tableid(mk_tableid(1000 + n))
                        .set_vni(vni),
                );
            }
            if let Some(v) = self.vtep {
                config.set_vtep(vteps[usize::from(v)].clone());
            }
            config
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    /// A sequence of config changes on a vrf wrt to a vtep/vni
    struct VtepStepSequences;

    impl ValueGenerator for VtepStepSequences {
        type Output = Vec<VtepStep>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<VtepStep>> {
            let len = driver.gen_u8(Included(&1), Included(&MAX_STEPS))?;
            let mut out = Vec::with_capacity(usize::from(len));
            for _ in 0..len {
                let mut vrfs = Vec::with_capacity(usize::from(NUM_VRFS));
                for _ in 0..NUM_VRFS {
                    // choose a config for a vrf
                    let choice = match driver.gen_u8(Included(&0), Included(&(NUM_VNIS + 1)))? {
                        0 => VrfChoice::Absent,
                        1 => VrfChoice::NoVni,
                        n => VrfChoice::Vni(n - 2),
                    };
                    vrfs.push(choice);
                }
                // choose a vtep
                let vtep = match driver.gen_u8(Included(&0), Included(&NUM_VTEPS))? {
                    0 => None,
                    n => Some(n - 1),
                };
                // store the vrf + vtep config step
                out.push(VtepStep { vrfs, vtep });
            }
            Some(out)
        }
    }

    #[test]
    fn test_config_vtep_fuzz() {
        let vteps = vtep_pool();
        assert_eq!(vteps.len(), usize::from(NUM_VTEPS));
        bolero::check!()
            .with_generator(VtepStepSequences)
            .cloned()
            .for_each(|steps: Vec<VtepStep>| {
                let mut db = create_routing_database();
                let mut applied_vtep: Option<Vtep> = None;
                for (genid, step) in (1i64..).zip(&steps) {
                    let config = step.build_config(genid, &vteps);
                    let result = config.apply(&mut db);
                    if step.is_valid() {
                        if let Err(e) = result {
                            panic!("Valid config rejected at step {genid}: {e}\n{step:?}\n{steps:?}");
                        }
                        applied_vtep = config.vtep.clone();
                    } else {
                        assert!(
                            matches!(result, Err(RouterError::InvalidConfig(_))),
                            "Invalid config not rejected at step {genid}: {result:?}\n{step:?}\n{steps:?}"
                        );
                    }
                    check_vteps(&db, applied_vtep.as_ref());
                }
            });
    }
}
