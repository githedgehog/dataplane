// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interfaces module

pub(crate) mod iftable;
pub(crate) mod iftablerw;
pub(crate) mod interface;

#[cfg(test)]
pub mod tests {

    use crate::RouterError;
    use crate::RouterVrfConfig;
    use crate::VrfId;
    use crate::fib::fibtable::FibTableWriter;
    use crate::interfaces::iftable::IfTable;
    use crate::interfaces::iftablerw::{IfTableReader, IfTableWriter};
    use crate::interfaces::interface::{
        IfDataDot1q, IfDataEthernet, IfState, IfType, RouterInterfaceConfig,
    };
    use crate::rib::VrfTable;
    use net::eth::mac::SourceMac;
    use net::interface::Mtu;
    use net::interface::address::IfAddr;
    use net::interface::{InterfaceIndex, InterfaceName};
    use net::vlan::Vid;
    use std::net::IpAddr;
    use std::str::FromStr;

    pub(crate) fn build_test_interface_cfg(ifname: &str, ifindex: u32) -> RouterInterfaceConfig {
        let ifindex = InterfaceIndex::try_new(ifindex).expect("bad ifindex");
        let ifname = InterfaceName::try_from(ifname).expect("Illegal ifname");
        RouterInterfaceConfig::new(ifname, ifindex)
    }

    // build sample interface configs to build a sample iftable
    fn build_interface_configs() -> Vec<RouterInterfaceConfig> {
        let mut configs = vec![];

        /* create loopback */
        let mut ifconfig = build_test_interface_cfg("Loopback", 1);
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_description("Main loopback interface");
        ifconfig.set_iftype(IfType::Loopback);
        configs.push(ifconfig);

        /* create Eth0 */
        let mut ifconfig = build_test_interface_cfg("eth0", 2);
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_description("Uplink to the Moon");
        ifconfig.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: SourceMac::try_from("00:aa:00:00:00:01").unwrap(),
        }));
        configs.push(ifconfig);

        /* create Eth1 */
        let mut ifconfig = build_test_interface_cfg("eth1", 3);
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_description("Downlink from Mars");
        ifconfig.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: SourceMac::try_from("00:bb:00:00:00:02").unwrap(),
        }));
        configs.push(ifconfig);

        /* create Eth2 */
        let mut ifconfig = build_test_interface_cfg("eth2", 4);
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_description("Downlink from Sun");
        ifconfig.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: SourceMac::try_from("00:cc:00:00:00:03").unwrap(),
        }));
        configs.push(ifconfig);

        /* create vlan.100 */
        let mut ifconfig = build_test_interface_cfg("eth1.100", 5);
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_description("External customer 1");
        ifconfig.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: SourceMac::try_from("00:bb:00:00:00:02").unwrap(),
            vlanid: Vid::new(100).unwrap(),
        }));
        configs.push(ifconfig);

        /* create vlan.200 */
        let mut ifconfig = build_test_interface_cfg("eth1.200", 6);
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_description("External customer 2");
        ifconfig.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: SourceMac::try_from("00:bb:00:00:00:02").unwrap(),
            vlanid: Vid::new(200).unwrap(),
        }));
        configs.push(ifconfig);

        configs
    }

    // create a test interface table
    fn populate_test_iftable() -> IfTable {
        let mut iftable = IfTable::new();
        let ifconfigs = build_interface_configs();

        // add the interfaces to the iftable from the configs
        for config in &ifconfigs {
            iftable.add_interface(config).expect("Should not fail");
        }
        assert_eq!(iftable.len(), ifconfigs.len());
        iftable
    }

    // create a test interface table and display it
    pub fn build_test_iftable() -> IfTable {
        let iftable = populate_test_iftable();
        println!("{iftable}");
        iftable
    }

    // Build a left-right iftable for the test iftable built above
    pub fn build_test_iftable_left_right() -> (IfTableWriter, IfTableReader) {
        let iftable = build_test_iftable();
        IfTableWriter::new_with_data(iftable)
    }

    #[test]
    fn test_iftable_basic() {
        const VRFID: VrfId = 123;
        const IF_NAME: &str = "ethernet";
        const IF_DESC: &str = "My interface";
        const IF_ADDRESS: &str = "10.0.1.1";
        const IF_MAC: &str = "00:aa:00:00:00:01";

        let mut iftable = IfTable::new();

        // create interface config
        let ifindex = 1;
        let mut config = build_test_interface_cfg(IF_NAME, ifindex);
        let ifindex = config.ifindex;
        config.set_description(IF_DESC);
        config.set_mtu(Some(Mtu::MIN));
        config.set_admin_state(IfState::Up);
        config.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: SourceMac::try_from(IF_MAC).unwrap(),
        }));

        // add interface to table
        iftable.add_interface(&config).unwrap();
        assert_eq!(iftable.len(), 1);
        assert!(
            !iftable
                .get_interface(ifindex)
                .unwrap()
                .is_attached_to_vrf(VRFID)
        );

        // attach to vrf
        iftable.attach_iface_to_vrf(ifindex, VRFID).unwrap();

        // update adm/oper state
        iftable.set_admin_state(ifindex, IfState::Down).unwrap();
        iftable.set_oper_state(ifindex, IfState::Up).unwrap();

        // Add same address twice
        let address = IpAddr::from_str(IF_ADDRESS).expect("Bad address");
        let ifaddr = IfAddr::new(address, 24).unwrap();
        iftable.add_ifaddr(ifindex, ifaddr).unwrap();
        iftable.add_ifaddr(ifindex, ifaddr).unwrap();

        // get interface from the table and check
        let interface = iftable.get_interface(config.ifindex).unwrap();
        assert_eq!(interface.ifindex, ifindex);
        assert_eq!(interface.name.to_string().as_str(), IF_NAME);
        assert_eq!(interface.admin_state, IfState::Down);
        assert_eq!(interface.oper_state, IfState::Up);
        assert_eq!(
            interface.description.as_ref().map(|d| d.as_str()),
            Some(IF_DESC)
        );
        assert!(interface.has_address(ifaddr.address()));
        assert_eq!(&interface.get_mac().unwrap().to_string(), IF_MAC);
        assert!(interface.is_attached_to_vrf(VRFID));
        assert_eq!(interface.vrf_attachment(), Some(VRFID));
        let _ = interface;

        // remove address
        iftable.del_ifaddr(ifindex, ifaddr).unwrap();
        let r = iftable.del_ifaddr(ifindex, ifaddr);
        assert!(r.is_err_and(|e| matches!(e, RouterError::NoSuchAddress(_))));

        // detach
        iftable.detach_from_vrf(ifindex).unwrap();

        // toggle states
        iftable.set_admin_state(ifindex, IfState::Up).unwrap();
        iftable.set_oper_state(ifindex, IfState::Down).unwrap();

        // check
        let interface = iftable.get_interface_mut(config.ifindex).unwrap();
        assert_eq!(interface.admin_state, IfState::Up);
        assert_eq!(interface.oper_state, IfState::Down);
        assert!(!interface.is_attached_to_vrf(VRFID));
        assert!(!interface.has_address(ifaddr.address()));

        // attempt add interface with same ifindex
        let r = iftable.add_interface(&config);
        assert!(r.is_err_and(|e| matches!(e, RouterError::InterfaceExists(_))));

        // remove interface
        iftable.del_interface(ifindex).unwrap();
        assert!(iftable.get_interface(ifindex).is_none());
        let r = iftable.del_interface(ifindex);
        assert!(r.is_err_and(|e| matches!(e, RouterError::NoSuchInterface(_))));
        assert_eq!(iftable.len(), 0);
    }

    #[track_caller]
    fn compare(reference: &IfTable, reader: &IfTableReader) {
        let wrapped = reader.enter().unwrap();
        similar_asserts::assert_eq!(&*wrapped, reference);
    }

    #[test]
    fn test_iftable_wrapped() {
        const VRFID: VrfId = 123;
        const IF_NAME: &str = "ethernet-1";
        const IF_NAME_MOD: &str = "FastEthernet-1";
        const IF_DESC: &str = "My interface";
        const IF_ADDRESS: &str = "10.0.1.1";
        const IF_MAC: &str = "00:aa:00:00:00:01";
        const IF_MAC_MOD: &str = "00:bb:00:00:00:02";

        let vrfconfig = RouterVrfConfig::new(VRFID, "some vrf");
        let (fibtw, _fibtr) = FibTableWriter::new();
        let mut vrftable = VrfTable::new(fibtw);
        vrftable.add_vrf(&vrfconfig).unwrap();

        // iftables: iftable acts as reference
        let mut iftable = IfTable::new();
        let (mut iftw, iftr) = IfTableWriter::new();

        // one interface
        let ifindex = 1;
        let mut config = build_test_interface_cfg(IF_NAME, ifindex);
        let ifindex = config.ifindex;
        config.set_description(IF_DESC);
        config.set_mtu(Some(Mtu::MIN));
        config.set_admin_state(IfState::Up);
        config.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: SourceMac::try_from(IF_MAC).unwrap(),
        }));

        // test interface additions
        iftable.add_interface(&config).unwrap();
        iftw.add_interface(config.clone()).unwrap();
        compare(&iftable, &iftr);

        // test addition reject: both reject
        assert!(iftable.add_interface(&config).is_err());
        assert!(iftw.add_interface(config.clone()).is_err());

        // test attach to vrf
        iftable.attach_iface_to_vrf(ifindex, VRFID).unwrap();
        iftw.attach_interface_to_vrf(ifindex, VRFID, &vrftable)
            .unwrap();
        compare(&iftable, &iftr);

        // test modify interface config or properties
        config.set_description("modified config".into());
        config.set_mtu(Some(Mtu::MAX));
        config.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: SourceMac::try_from(IF_MAC_MOD).unwrap(),
        }));
        iftable.mod_interface(&config).unwrap();
        iftw.mod_interface(config.clone()).unwrap();
        compare(&iftable, &iftr);

        // test add address
        let address = IpAddr::from_str(IF_ADDRESS).expect("Bad address");
        let ifaddr = IfAddr::new(address, 24).unwrap();
        iftable.add_ifaddr(ifindex, ifaddr).unwrap();
        iftw.add_ip_address(ifindex, ifaddr).unwrap();
        compare(&iftable, &iftr);

        // test add duplicate address: neither fail but don't add twice
        iftable.add_ifaddr(ifindex, ifaddr).unwrap();
        iftw.add_ip_address(ifindex, ifaddr).unwrap();
        compare(&iftable, &iftr);

        // test address removal
        iftable.del_ifaddr(ifindex, ifaddr).unwrap();
        iftw.del_ip_address(ifindex, ifaddr).unwrap();
        compare(&iftable, &iftr);

        // test removal non-existent address
        let r1 = iftable.del_ifaddr(ifindex, ifaddr);
        let r2 = iftw.del_ip_address(ifindex, ifaddr);
        assert!(r1.is_err());
        assert_eq!(r1, r2);
        compare(&iftable, &iftr);

        // test set admin state
        iftable.set_admin_state(ifindex, IfState::Down).unwrap();
        iftw.set_iface_admin_state(ifindex, IfState::Down).unwrap();
        compare(&iftable, &iftr);

        // test set oper state
        iftable.set_oper_state(ifindex, IfState::Up).unwrap();
        iftw.set_iface_oper_state(ifindex, IfState::Up).unwrap();
        compare(&iftable, &iftr);

        // test detach from vrf
        iftable.detach_from_vrf(ifindex).unwrap();
        iftw.detach_interface(ifindex).unwrap();
        compare(&iftable, &iftr);

        // test update of interface name
        let new_name = InterfaceName::try_from(IF_NAME_MOD).expect("Illegal ifname");
        // refresh the config since we updated admin state without modifying the config
        let mut config = iftable.get_interface(ifindex).unwrap().as_config();
        config.set_name(&new_name);
        iftable.mod_interface(&config).unwrap();
        iftw.update_name(ifindex, &new_name).unwrap();
        compare(&iftable, &iftr);

        // test detach reject
        let r1 = iftable.detach_from_vrf(ifindex);
        let r2 = iftw.detach_interface(ifindex);
        assert!(r1.is_err());
        assert_eq!(r1, r2);
        compare(&iftable, &iftr);

        // test interface removal
        iftable.del_interface(ifindex).unwrap();
        iftw.del_interface(ifindex).unwrap();
        compare(&iftable, &iftr);

        // test interface removal reject
        let r1 = iftable.del_interface(ifindex);
        let r2 = iftw.del_interface(ifindex);
        assert_eq!(r1, r2);
        compare(&iftable, &iftr);

        // test non existent interface update
        let r1 = iftable.mod_interface(&config);
        let r2 = iftw.mod_interface(config.clone());
        assert_eq!(r1, r2);
        compare(&iftable, &iftr);
    }

    #[test]
    fn test_interface_config_from_interface() {
        use std::collections::HashMap;

        let iftable = populate_test_iftable();
        let recovered: HashMap<InterfaceIndex, RouterInterfaceConfig> = iftable
            .values()
            .map(|iface| (iface.ifindex, iface.as_config()))
            .collect();

        // the configs used to populate the iftable
        let original: HashMap<InterfaceIndex, RouterInterfaceConfig> = build_interface_configs()
            .iter()
            .map(|conf| (conf.ifindex, conf.clone()))
            .collect();

        similar_asserts::assert_eq!(original, recovered);
    }
}

#[cfg(test)]
mod event_processing {
    use super::tests::build_test_iftable_left_right;
    use crate::Interface;
    use crate::interfaces::iftablerw::IfTableWriter;
    use crate::interfaces::interface::IfState;
    use crate::router::ctl::handle_ifevent;
    use interface_manager::monitor::EthEvent;
    use net::interface::InterfaceIndex;

    // generate event with the admin / oper states of the given interface
    fn gen_event(iface: &Interface) -> EthEvent {
        let ifup = match iface.admin_state {
            IfState::Up => true,
            IfState::Down | IfState::Unknown => false,
        };
        let ifrunning = match iface.oper_state {
            IfState::Up => true,
            IfState::Down | IfState::Unknown => false,
        };
        let iflowerup = false; // informational
        EthEvent::new(
            iface.ifindex,
            iface.name.clone(),
            ifup,
            iflowerup,
            ifrunning,
        )
    }

    // get interface (clone) from iftable reader
    fn get_interface(iftw: &IfTableWriter, ifindex: InterfaceIndex) -> Interface {
        iftw.enter()
            .unwrap()
            .get_interface(ifindex)
            .expect("Not found")
            .clone()
    }

    #[track_caller]
    fn compare_interface(reference: &Interface, updated: &Interface) {
        println!("Checking {reference}");
        similar_asserts::assert_eq!(reference, updated);
    }

    fn toggle(state: IfState) -> IfState {
        match state {
            IfState::Up => IfState::Down,
            IfState::Down => IfState::Up,
            IfState::Unknown => unreachable!(),
        }
    }
    fn toggle_adm(iface: &mut Interface) {
        iface.set_admin_state(toggle(iface.admin_state));
    }
    fn toggle_oper(iface: &mut Interface) {
        iface.set_oper_state(toggle(iface.oper_state));
    }

    // Initialize oper state of all interfaces to match their admin state
    fn init_oper_state(iftw: &mut IfTableWriter) {
        let iftable = unsafe { iftw.raw_write_handle().as_mut() };
        iftable
            .values_mut()
            .for_each(|iface| iface.set_oper_state(iface.admin_state));
        iftw.publish();
        println!("Updated oper state of all interfaces");
    }

    #[test]
    fn test_interface_event_process() {
        let (mut iftw, _) = build_test_iftable_left_right();
        init_oper_state(&mut iftw);

        let mut reference: Vec<Interface> = iftw.enter().unwrap().values().cloned().collect();
        let initial = reference.clone();

        for iface in reference.iter_mut() {
            // toggle admin state, generate event and check
            toggle_adm(iface);
            let event = gen_event(iface);
            handle_ifevent(&event, &mut iftw);
            let updated = get_interface(&iftw, iface.ifindex);
            compare_interface(&iface, &updated);

            // toggle admin state BACK
            toggle_adm(iface);
            let event = gen_event(iface);
            handle_ifevent(&event, &mut iftw);
            let updated = get_interface(&iftw, iface.ifindex);
            compare_interface(&iface, &updated);

            // toggle oper state, generate event and check
            toggle_oper(iface);
            let event = gen_event(iface);
            handle_ifevent(&event, &mut iftw);
            let updated = get_interface(&iftw, iface.ifindex);
            compare_interface(&iface, &updated);

            // toggle admin state BACK
            toggle_oper(iface);
            let event = gen_event(iface);
            handle_ifevent(&event, &mut iftw);
            let updated = get_interface(&iftw, iface.ifindex);
            compare_interface(&iface, &updated);
        }

        // all interfaces should remain as they were (this is for test correctness)
        similar_asserts::assert_eq!(initial, reference);

        // also via writer
        let last: Vec<Interface> = iftw.enter().unwrap().values().cloned().collect();
        similar_asserts::assert_eq!(initial, last);
    }
}
