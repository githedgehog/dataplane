// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interfaces module

pub mod iftable;
pub mod iftablerw;
pub mod interface;

#[cfg(test)]
pub mod tests {
    use crate::RouterError;
    use crate::fib::fibtype::{FibId, FibWriter};
    use crate::interfaces::iftable::IfTable;
    use crate::interfaces::iftablerw::{IfTableReader, IfTableWriter};
    use crate::interfaces::interface::{
        IfDataDot1q, IfDataEthernet, IfState, IfType, RouterInterfaceConfig,
    };
    use crate::rib::vrf::{RouterVrfConfig, Vrf};
    use net::eth::mac::Mac;
    use net::interface::InterfaceIndex;
    use net::vlan::Vid;
    use std::net::IpAddr;
    use std::str::FromStr;

    // create a test interface table
    fn populate_test_iftable() -> IfTable {
        let mut iftable = IfTable::new();

        /* create loopback */
        let lo_idx = InterfaceIndex::try_new(1).unwrap();
        let mut lo = RouterInterfaceConfig::new("Loopback", lo_idx);
        lo.set_admin_state(IfState::Up);
        lo.set_description("Main loopback interface");
        lo.set_iftype(IfType::Loopback);

        /* create Eth0 */
        let eth0_idx = InterfaceIndex::try_new(2).unwrap();
        let mut eth0 = RouterInterfaceConfig::new("eth0", eth0_idx);
        eth0.set_admin_state(IfState::Up);
        eth0.set_description("Uplink to the Moon");
        eth0.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
        }));

        /* create Eth1 */
        let eth1_idx = InterfaceIndex::try_new(3).unwrap();
        let mut eth1 = RouterInterfaceConfig::new("eth1", eth1_idx);
        eth1.set_admin_state(IfState::Up);
        eth1.set_description("Downlink from Mars");
        eth1.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x2]),
        }));

        /* create Eth2 */
        let eth2_idx = InterfaceIndex::try_new(4).unwrap();
        let mut eth2 = RouterInterfaceConfig::new("eth2", eth2_idx);
        eth2.set_admin_state(IfState::Up);
        eth2.set_description("Downlink from Sun");
        eth2.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x3]),
        }));

        /* create vlan.100 */
        let vlan100_idx = InterfaceIndex::try_new(5).unwrap();
        let mut vlan100 = RouterInterfaceConfig::new("eth1.100", vlan100_idx);
        vlan100.set_admin_state(IfState::Up);
        vlan100.set_description("External customer 1");
        vlan100.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x2]),
            vlanid: Vid::new(100).unwrap(),
        }));

        /* create vlan.200 */
        let vlan200_idx = InterfaceIndex::try_new(6).unwrap();
        let mut vlan200 = RouterInterfaceConfig::new("eth1.200", vlan200_idx);
        vlan200.set_admin_state(IfState::Up);
        vlan200.set_description("External customer 2");
        vlan200.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x2]),
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
        println!("{}", &iftable);
        iftable
    }

    // Build a left-right iftable for the test iftable built above
    pub fn build_test_iftable_left_right() -> (IfTableWriter, IfTableReader) {
        let iftable = build_test_iftable();
        IfTableWriter::new_with_data(iftable)
    }

    #[test]
    fn test_interface_basic() {
        /* create interface table  */
        let mut iftable = build_test_iftable();

        /* Create a fib for the vrf created next */
        let (fibw, _fibr) = FibWriter::new(FibId::Id(0));

        /* Create a VRF for that fib */
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);
        vrf.set_fibw(fibw);

        /* lookup interface with non-existent index */
        let idx100 = InterfaceIndex::try_new(100).unwrap();
        let iface = iftable.get_interface(idx100);
        assert!(iface.is_none());

        /* Lookup interface by ifindex 2 */
        let idx2 = InterfaceIndex::try_new(2).unwrap();
        let iface = iftable.get_interface_mut(idx2);
        assert!(iface.is_some());
        let eth0 = iface.unwrap();
        assert_eq!(eth0.name, "eth0", "We should get eth0");
        assert_eq!(eth0.ifindex, idx2, "eth0 has ifindex 2");

        /* Add an ip address (the interface is in the iftable) */
        let address = IpAddr::from_str("10.0.0.1").expect("Bad address");
        eth0.add_ifaddr(&(address, 24));
        assert!(eth0.has_address(&address));
    }

    #[test]
    fn test_iftable_api() {
        /* create interface table */
        let mut iftable = IfTable::new();

        /* create Eth0 */
        let eth0_idx = InterfaceIndex::try_new(2).unwrap();
        let mut eth0 = RouterInterfaceConfig::new("eth0", eth0_idx);
        eth0.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
        }));

        /* add to interface table */
        iftable.add_interface(&eth0).expect("Should succeed");
        assert_eq!(iftable.len(), 1, "Eth0 should be there");

        /* test get_mac */
        let iface = iftable.get_interface(eth0_idx).expect("Should be there");
        assert_eq!(
            Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
            iface.get_mac().unwrap()
        );

        /* Add interface again -- idempotence */
        let mut eth0 = RouterInterfaceConfig::new("eth0", eth0_idx);
        eth0.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
        }));
        let iface = iftable.add_interface(&eth0);
        assert!(iface.is_err_and(|e| matches!(e, RouterError::InterfaceExists(_))));
        assert_eq!(iftable.len(), 1, "Only eth0 should be there");

        /* Delete eth0 by index */
        iftable.del_interface(eth0_idx);
        assert_eq!(iftable.len(), 0, "No interface should be there");
    }
}
