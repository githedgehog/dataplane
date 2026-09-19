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

    // create a test interface table
    fn populate_test_iftable() -> IfTable {
        let mut iftable = IfTable::new();

        /* create loopback */
        let mut lo = build_test_interface_cfg("Loopback", 1);
        lo.set_admin_state(IfState::Up);
        lo.set_description("Main loopback interface");
        lo.set_iftype(IfType::Loopback);

        /* create Eth0 */
        let mut eth0 = build_test_interface_cfg("eth0", 2);
        eth0.set_admin_state(IfState::Up);
        eth0.set_description("Uplink to the Moon");
        eth0.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: SourceMac::try_from("00:aa:00:00:00:01").unwrap(),
        }));

        /* create Eth1 */
        let mut eth1 = build_test_interface_cfg("eth1", 3);
        eth1.set_admin_state(IfState::Up);
        eth1.set_description("Downlink from Mars");
        eth1.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: SourceMac::try_from("00:bb:00:00:00:02").unwrap(),
        }));

        /* create Eth2 */
        let mut eth2 = build_test_interface_cfg("eth2", 4);
        eth2.set_admin_state(IfState::Up);
        eth2.set_description("Downlink from Sun");
        eth2.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: SourceMac::try_from("00:cc:00:00:00:03").unwrap(),
        }));

        /* create vlan.100 */
        let mut vlan100 = build_test_interface_cfg("eth1.100", 5);
        vlan100.set_admin_state(IfState::Up);
        vlan100.set_description("External customer 1");
        vlan100.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: SourceMac::try_from("00:bb:00:00:00:02").unwrap(),
            vlanid: Vid::new(100).unwrap(),
        }));

        /* create vlan.200 */
        let mut vlan200 = build_test_interface_cfg("eth1.200", 6);
        vlan200.set_admin_state(IfState::Up);
        vlan200.set_description("External customer 2");
        vlan200.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: SourceMac::try_from("00:bb:00:00:00:02").unwrap(),
            vlanid: Vid::new(200).unwrap(),
        }));

        /* Add the interfaces to the iftable */
        iftable.add_interface(&lo).expect("Should not fail");
        iftable.add_interface(&eth0).expect("Should not fail");
        iftable.add_interface(&eth1).expect("Should not fail");
        iftable.add_interface(&eth2).expect("Should not fail");
        iftable.add_interface(&vlan100).expect("Should not fail");
        iftable.add_interface(&vlan200).expect("Should not fail");

        assert_eq!(iftable.len(), 6);

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
}
