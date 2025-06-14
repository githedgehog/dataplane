// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interfaces module

pub mod iftable;
pub mod iftablerw;
pub mod interface;

#[cfg(test)]
pub mod tests {
    use crate::display::IfTableAddress;
    use crate::fib::fibtype::{FibId, FibWriter};
    use crate::interfaces::iftable::IfTable;
    use crate::interfaces::interface::{
        Attachment, IfDataDot1q, IfDataEthernet, IfState, IfType, Interface,
    };
    use crate::rib::vrf::Vrf;
    use net::eth::mac::Mac;
    use net::vlan::Vid;
    use std::net::IpAddr;
    use std::str::FromStr;

    // create a test interface table
    fn populate_test_iftable() -> IfTable {
        let mut iftable = IfTable::new();

        /* create loopback */
        let mut lo = Interface::new("Loopback", 1);
        lo.set_admin_state(IfState::Up);
        lo.set_oper_state(IfState::Up);
        lo.set_description("Main loopback interface");
        lo.set_iftype(IfType::Loopback);

        /* create Eth0 */
        let mut eth0 = Interface::new("eth0", 2);
        eth0.set_admin_state(IfState::Up);
        eth0.set_oper_state(IfState::Up);
        eth0.set_description("Uplink to the Moon");
        eth0.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
        }));

        /* create Eth1 */
        let mut eth1 = Interface::new("eth1", 3);
        eth1.set_admin_state(IfState::Up);
        eth1.set_oper_state(IfState::Up);
        eth1.set_description("Downlink from Mars");
        eth1.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x2]),
        }));

        /* create Eth2 */
        let mut eth2 = Interface::new("eth2", 4);
        eth2.set_admin_state(IfState::Up);
        eth2.set_oper_state(IfState::Up);
        eth2.set_description("Downlink from Sun");
        eth2.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x3]),
        }));

        /* create vlan.100 */
        let mut vlan100 = Interface::new("eth1.100", 5);
        vlan100.set_admin_state(IfState::Up);
        vlan100.set_oper_state(IfState::Up);
        vlan100.set_description("External customer 1");
        vlan100.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x2]),
            vlanid: Vid::new(100).unwrap(),
        }));

        /* create vlan.200 */
        let mut vlan200 = Interface::new("eth1.200", 6);
        vlan200.set_admin_state(IfState::Up);
        vlan200.set_oper_state(IfState::Up);
        vlan200.set_description("External customer 2");
        vlan200.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x2]),
            vlanid: Vid::new(200).unwrap(),
        }));

        /* Add the interfaces to the iftable */
        iftable.add_interface(lo);
        iftable.add_interface(eth0);
        iftable.add_interface(eth1);
        iftable.add_interface(eth2);
        iftable.add_interface(vlan100);
        iftable.add_interface(vlan200);

        assert_eq!(iftable.len(), 6);

        iftable
    }

    // create a test interface table and display it
    pub fn build_test_iftable() -> IfTable {
        let iftable = populate_test_iftable();
        println!("{}", &iftable);
        iftable
    }

    #[test]
    fn test_interface_basic() {
        /* create interface table  */
        let mut iftable = build_test_iftable();

        /* Create a fib for the vrf created next */
        let (fibw, fibr) = FibWriter::new(FibId::Id(0));

        /* Create a VRF for that fib */
        #[allow(clippy::arc_with_non_send_sync)]
        let vrf = Vrf::new("default-vrf", 0, Some(fibw));

        /* lookup interface with non-existent index */
        let iface = iftable.get_interface(100);
        assert!(iface.is_none());

        {
            /* Lookup interface by ifindex 2 */
            let iface = iftable.get_interface_mut(2);
            assert!(iface.is_some());
            let eth0 = iface.unwrap();
            assert_eq!(eth0.name, "eth0", "We should get eth0");
            assert_eq!(eth0.ifindex, 2, "eth0 has ifindex 2");

            /* Add an ip address (the interface is in the iftable) */
            let address = IpAddr::from_str("10.0.0.1").expect("Bad address");
            eth0.add_ifaddr(&(address, 24));
            assert!(eth0.has_address(&address));

            /* Attach eth0 to the VRF */
            let e = eth0.attach(&vrf);
            assert_eq!(e, Ok(()));
            assert!(matches!(eth0.attachment, Some(Attachment::VRF(_))));
            if let Some(Attachment::VRF(r)) = &eth0.attachment {
                assert_eq!(r.get_id(), fibr.get_id());
            } else {
                unreachable!()
            }
        }
        // Need a separate scope. Display for interfaces borrows interfaces
        // hence, we can't have a mutable reference to them.
        println!("{}", &iftable);

        /* Detach */
        let eth0 = iftable.get_interface_mut(2).expect("Should find it");

        eth0.detach();
        assert!(eth0.attachment.is_none());
    }

    #[test]
    fn test_iftable_api() {
        /* create interface table */
        let mut iftable = IfTable::new();

        /* create Eth0 */
        let mut eth0 = Interface::new("eth0", 2);
        eth0.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
        }));

        /* test get_mac */
        assert_eq!(
            Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
            eth0.get_mac().unwrap()
        );

        /* add to interface table */
        iftable.add_interface(eth0);
        assert_eq!(iftable.len(), 1, "Eth0 should be there");

        /* Add interface again -- idempotence */
        let mut eth0 = Interface::new("eth0", 2);
        eth0.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
        }));
        iftable.add_interface(eth0);
        assert_eq!(iftable.len(), 1, "Only eth0 should be there");

        /* Delete eth0 by index */
        iftable.del_interface(2);
        assert_eq!(iftable.len(), 0, "No interface should be there");
    }

    #[test]
    fn test_iftable_map() {
        let mut iftable = IfTable::new();

        let mut iface = Interface::new("eth0", 2);
        iface.set_iftype(IfType::Ethernet(IfDataEthernet {
            mac: Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
        }));
        iftable.add_interface(iface);

        /* add some vlan interfaces */
        for n in 1..10 {
            let mut iface = Interface::new(format!("eth0.{n}").as_str(), 2 + n);
            iface.set_iftype(IfType::Dot1q(IfDataDot1q {
                mac: Mac::from([0x0, 0xaa, 0x0, 0x0, 0x0, 0x1]),
                vlanid: Vid::new(n.try_into().unwrap()).unwrap(),
            }));
            iftable.add_interface(iface);
        }
        println!("{}", &iftable);
        println!("{}", IfTableAddress(&iftable));

        /* delete the vlan interfaces */
        for n in 1..10 {
            iftable.del_interface(2 + n);
        }
        assert_eq!(iftable.len(), 1);
    }
}
