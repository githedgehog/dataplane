// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State objects for network interfaces and interface table.

use crate::errors::RouterError;
use crate::vrf::Vrf;
use net::eth::mac::Mac;
use net::vlan::Vid;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::RwLock;

/// A type to uniquely identify a network interface
pub type IfIndex = u32;

/// An Ipv4 or Ipv6 address and mask configured on an interface
type IfAddress = (IpAddr, u8);

#[allow(dead_code)]
/// Specific data for ethernet interfaces
pub struct IfDataEthernet {
    pub mac: Mac,
}

/// Specific data for vlan (sub)interfaces
#[allow(dead_code)]
pub struct IfDataDot1q {
    pub mac: Mac,
    pub vlanid: Vid,
}

/// Type that contains data specific to the type of interface
#[allow(dead_code)]
pub enum IfType {
    Unknown,
    Ethernet(IfDataEthernet),
    Dot1q(IfDataDot1q),
    Loopback,
    Vxlan, /* It is not clear if we'll model it like this */
}

#[allow(dead_code)]
#[derive(Default, Eq, PartialEq)]
pub enum IfState {
    #[default]
    Unknown = 0,
    Down = 1,
    Up = 2,
}

#[allow(dead_code)]
/// An object representing a network interface and its state
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub ifindex: IfIndex,
    pub iftype: IfType,
    pub admin_state: IfState,
    pub oper_state: IfState,
    pub addresses: HashSet<IfAddress>,
    pub vrf: Option<Arc<RwLock<Vrf>>>,
}

#[allow(dead_code)]
impl Interface {
    //////////////////////////////////////////////////////////////////
    /// Create a new interface object.
    /// This simply creates in-memory state to represent the interface
    //////////////////////////////////////////////////////////////////
    pub fn new(name: &str, ifindex: u32) -> Self {
        Self {
            name: name.to_owned(),
            description: None,
            ifindex,
            iftype: IfType::Unknown,
            admin_state: IfState::Unknown,
            oper_state: IfState::Unknown,
            addresses: HashSet::new(),
            vrf: None,
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Set Iftype - this should be a one-time kind of thing
    //////////////////////////////////////////////////////////////////
    pub fn set_iftype(&mut self, iftype: IfType) {
        self.iftype = iftype;
    }

    //////////////////////////////////////////////////////////////////
    /// Set the description of an interface
    //////////////////////////////////////////////////////////////////
    pub fn set_description<T: AsRef<str>>(&mut self, description: T) {
        self.description = Some(description.as_ref().to_string());
    }

    //////////////////////////////////////////////////////////////////
    /// Set the operational state of an interface
    //////////////////////////////////////////////////////////////////
    pub fn set_oper_state(&mut self, state: IfState) {
        if self.oper_state != state {
            self.oper_state = state;
            // Todo: log change
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Set the administrative state of an interface
    //////////////////////////////////////////////////////////////////
    pub fn set_admin_state(&mut self, state: IfState) {
        if self.admin_state != state {
            self.admin_state = state;
            // Todo: log change
        }
    }
    // Todo: decide if set_oper_state() and set_admin_state() will be
    // the ones to trigger the enforcement of the new state
    // (e.g. by requesting the interface manager to bring up/down
    // interfaces in kernel), or, instead, they just update the
    // interface object seen by the rest of the routing system.

    //////////////////////////////////////////////////////////////////
    /// Attach an interface to a VRF. It is assumed that both the
    /// interface and the VRF exist.
    //////////////////////////////////////////////////////////////////
    pub fn attach(&mut self, vrf: &Arc<RwLock<Vrf>>) -> Result<(), RouterError> {
        if let Some(exist_vrf) = &self.vrf {
            if !Arc::ptr_eq(exist_vrf, vrf) {
                Err(RouterError::AlreadyAttached)
            } else {
                Ok(())
            }
        } else {
            self.vrf = Some(vrf.clone());
            Ok(())
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Detach an interface from its VRF (whichever it is)
    //////////////////////////////////////////////////////////////////
    pub fn detach(&mut self) {
        self.vrf.take();
    }

    //////////////////////////////////////////////////////////////////
    /// Get the VRF that an interface is attached to, or None otherwise
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf(&self) -> Option<&RwLock<Vrf>> {
        self.vrf.as_deref()
    }

    //////////////////////////////////////////////////////////////////
    /// Get the name of the VRF that an interface is attached to or None
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf_name(&self) -> Option<String> {
        self.get_vrf()
            .map(|vrf| vrf.read().expect("RWlock-error").name.to_owned())
    }

    //////////////////////////////////////////////////////////////////
    /// Add (assign) an IP address to an interface
    //////////////////////////////////////////////////////////////////
    pub fn add_ifaddr(&mut self, ifaddr: &IfAddress) {
        self.addresses.insert(*ifaddr);
    }

    //////////////////////////////////////////////////////////////////
    /// Del (unassign) an IP address from an interface
    //////////////////////////////////////////////////////////////////
    pub fn del_ifaddr(&mut self, ifaddr: &IfAddress) {
        self.addresses.remove(ifaddr);
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if an interface has a certain IP address assigned
    /// (regardless of the mask)
    //////////////////////////////////////////////////////////////////
    pub fn has_address(&self, address: &IpAddr) -> bool {
        for (addr, _) in &self.addresses {
            if addr == address {
                return true;
            }
        }
        false
    }

    //////////////////////////////////////////////////////////////////
    /// Get mac address of interface, if any
    //////////////////////////////////////////////////////////////////
    pub fn get_mac(&self) -> Option<&Mac> {
        match &self.iftype {
            IfType::Ethernet(inner) => Some(&inner.mac),
            IfType::Dot1q(inner) => Some(&inner.mac),
            _ => None,
        }
    }
}

/// A table of network interface objects, keyed by some ifindex (u32)
pub struct IfTable(pub(crate) HashMap<u32, Interface>);

#[allow(dead_code)]
#[allow(clippy::new_without_default)]
impl IfTable {
    //////////////////////////////////////////////////////////////////
    /// Create an interface table. All interfaces should live here.
    //////////////////////////////////////////////////////////////////
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(HashMap::new())
        // TODO: set a fast hasher
    }

    //////////////////////////////////////////////////////////////////
    /// Add an interface to the table
    //////////////////////////////////////////////////////////////////
    pub fn add_interface(&mut self, iface: Interface) {
        self.0.insert(iface.ifindex, iface);
    }

    //////////////////////////////////////////////////////////////////
    /// Remove an interface from the table
    //////////////////////////////////////////////////////////////////
    pub fn del_interface(&mut self, ifindex: u32) {
        self.0.remove(&ifindex);
    }

    //////////////////////////////////////////////////////////////////
    /// Get interface entry from IfTable
    //////////////////////////////////////////////////////////////////
    pub fn get_interface(&self, ifindex: u32) -> Option<&Interface> {
        self.0.get(&ifindex)
    }

    //////////////////////////////////////////////////////////////////
    /// Get interface entry from IfTable, mutably
    //////////////////////////////////////////////////////////////////
    pub fn get_interface_mut(&mut self, ifindex: u32) -> Option<&mut Interface> {
        self.0.get_mut(&ifindex)
    }

    //////////////////////////////////////////////////////////////////
    /// Assign an Ip address to an interface
    //////////////////////////////////////////////////////////////////
    pub fn add_ifaddr(&mut self, ifindex: IfIndex, ifaddr: &IfAddress) -> Result<(), RouterError> {
        if let Some(iface) = self.0.get_mut(&ifindex) {
            iface.add_ifaddr(ifaddr);
            Ok(())
        } else {
            Err(RouterError::NoSuchInterface(ifindex))
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Un-assign an Ip address from an interface.
    //////////////////////////////////////////////////////////////////
    pub fn del_ifaddr(&mut self, ifindex: IfIndex, ifaddr: &IfAddress) {
        if let Some(iface) = self.0.get_mut(&ifindex) {
            iface.del_ifaddr(&(ifaddr.0, ifaddr.1));
        }
        // if interface does not exist or the address was not configured,
        // we'll do nothing
    }

    //////////////////////////////////////////////////////////////////
    /// Detach all interfaces attached to some VRF
    //////////////////////////////////////////////////////////////////
    pub fn detach_vrf_interfaces(&mut self, vrf: &Arc<RwLock<Vrf>>) {
        for iface in self.0.values_mut() {
            #[allow(clippy::collapsible_if)]
            if let Some(if_vrf) = &iface.vrf {
                if Arc::ptr_eq(if_vrf, vrf) {
                    iface.detach();
                }
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::{IfDataDot1q, IfDataEthernet, IfState, IfTable, IfType, Interface, Vrf};
    use net::eth::mac::Mac;
    use net::vlan::Vid;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::{Arc, RwLock};

    // create a test interface table
    pub fn build_test_iftable() -> IfTable {
        /* create interface table */
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
        eth1.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x2]),
            vlanid: Vid::new(100).unwrap(),
        }));

        /* create vlan.100 */
        let mut vlan100 = Interface::new("eth1.100", 4);
        vlan100.set_admin_state(IfState::Up);
        vlan100.set_oper_state(IfState::Up);
        vlan100.set_description("External customer 1");
        vlan100.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x2]),
            vlanid: Vid::new(100).unwrap(),
        }));

        /* create vlan.200 */
        let mut vlan200 = Interface::new("eth1.200", 5);
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
        iftable.add_interface(vlan100);
        iftable.add_interface(vlan200);

        assert_eq!(iftable.0.len(), 5);

        iftable
    }

    #[test]
    fn interface_basic() {
        /* create interface table  */
        let mut iftable = build_test_iftable();

        /* lookup interface with non-existent index */
        let iface = iftable.get_interface_mut(100);
        assert!(iface.is_none());

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

        /* Suppose a VRF exists already, somewhere... */
        let vrf = Arc::new(RwLock::new(Vrf::new("default-vrf", 0)));

        /* Attach to VRF */
        let e = eth0.attach(&vrf);
        assert_eq!(e, Ok(()));

        assert!(eth0.get_vrf().is_some());
        assert!(Arc::ptr_eq(eth0.vrf.as_ref().unwrap(), &vrf));

        /* Detach */
        eth0.detach();
        assert!(eth0.vrf.is_none());
    }
}
