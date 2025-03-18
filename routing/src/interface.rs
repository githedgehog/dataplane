// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State objects for network interfaces and interface table.

#![allow(clippy::collapsible_if)]

use crate::fib::fibtype::FibId;
use ahash::RandomState;
use dplane_rpc::log::warn;
use net::eth::mac::Mac;
use net::vlan::Vid;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

use crate::errors::RouterError;
use crate::fib::fibtype::FibReader;
use crate::vrf::Vrf;
use tracing::error;

/// A type to uniquely identify a network interface
pub type IfIndex = u32;

/// An Ipv4 or Ipv6 address and mask configured on an interface
type IfAddress = (IpAddr, u8);

#[allow(dead_code)]
#[derive(Clone)]
/// Specific data for ethernet interfaces
pub struct IfDataEthernet {
    pub mac: Mac,
}

#[allow(dead_code)]
#[derive(Clone)]
/// Specific data for vlan (sub)interfaces
pub struct IfDataDot1q {
    pub mac: Mac,
    pub vlanid: Vid,
}

/// Type that contains data specific to the type of interface
#[derive(Clone)]
#[allow(dead_code)]
pub enum IfType {
    Unknown,
    Ethernet(IfDataEthernet),
    Dot1q(IfDataDot1q),
    Loopback,
    Vxlan, /* It is not clear if we'll model it like this */
}

#[allow(dead_code)]
#[derive(Clone, Default, Eq, PartialEq)]
pub enum IfState {
    #[default]
    Unknown = 0,
    Down = 1,
    Up = 2,
}

#[derive(Clone)]
pub enum Attachment {
    VRF(FibReader),
    BD,
}

#[derive(Clone)]
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
    pub attachment: Option<Attachment>,
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
            attachment: None,
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
    //////////////////////////////////////////////////////////////////
    /// Attach an interface to a VRF. The interface is attached to a
    /// FibReader so that IP packets received on that interface can
    /// be readily forwarded performing an LPM operation on the
    /// corresponding FIB.
    //////////////////////////////////////////////////////////////////
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn attach(&mut self, vrf: &Arc<RwLock<Vrf>>) -> Result<(), RouterError> {
        if let Ok(vrf) = vrf.read() {
            if let Some(fibw) = &vrf.fibw {
                if let Some(id) = fibw.get_id() {
                    if self.is_attached_to_fib(&id) {
                        Ok(())
                    } else if self.attachment.is_some() {
                        Err(RouterError::AlreadyAttached)
                    } else {
                        // create attachment object with a Fibreader
                        self.attachment = Some(Attachment::VRF(fibw.as_fibreader()));
                        Ok(())
                    }
                } else {
                    error!(
                        "Failed to attach interface {} to VRF {}: can't get fib id",
                        self.name, vrf.name
                    );
                    Err(RouterError::Internal)
                }
            } else {
                error!(
                    "Can't attach interface {} to vrf {} since it has no FIB",
                    self.name, vrf.name
                );
                Err(RouterError::Internal)
            }
        } else {
            error!("Poisoned lock");
            Err(RouterError::Internal)
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Detach an interface from its VRF, unconditionally
    //////////////////////////////////////////////////////////////////
    pub fn detach(&mut self) {
        self.attachment.take();
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if an interface is attached to a Fib with the given Id
    //////////////////////////////////////////////////////////////////
    pub fn is_attached_to_fib(&self, fibid: &FibId) -> bool {
        if let Some(Attachment::VRF(fibr)) = &self.attachment {
            fibr.get_id() == Some(fibid.clone())
        } else {
            false
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Detach interface from VRF if the associated fib has the given id
    //////////////////////////////////////////////////////////////////
    pub fn detach_from_fib(&mut self, fibid: &FibId) {
        self.attachment.take_if(|attachment| {
            if let Attachment::VRF(fibr) = &attachment {
                fibr.get_id() == Some(fibid.clone())
            } else {
                false
            }
        });
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

#[derive(Clone)]
/// A table of network interface objects, keyed by some ifindex (u32)
pub struct IfTable {
    by_index: HashMap<u32, Rc<RefCell<Interface>>, RandomState>,
}

#[allow(dead_code)]
#[allow(clippy::new_without_default)]
impl IfTable {
    //////////////////////////////////////////////////////////////////
    /// Create an interface table. All interfaces should live here.
    //////////////////////////////////////////////////////////////////
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            by_index: HashMap::with_hasher(RandomState::with_seed(0)),
        }
    }

    pub fn len(&self) -> usize {
        self.by_index.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_index.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&IfIndex, &Rc<RefCell<Interface>>)> {
        self.by_index.iter()
    }
    pub fn values(&self) -> impl Iterator<Item = &Rc<RefCell<Interface>>> {
        self.by_index.values()
    }

    //////////////////////////////////////////////////////////////////
    /// Add an interface to the table
    //////////////////////////////////////////////////////////////////
    pub fn add_interface(&mut self, iface: Interface) {
        let ifindex = iface.ifindex;
        let rc_if = Rc::new(RefCell::new(iface));
        self.by_index.insert(ifindex, rc_if);
    }

    //////////////////////////////////////////////////////////////////
    /// Remove an interface from the table
    //////////////////////////////////////////////////////////////////
    pub fn del_interface(&mut self, ifindex: u32) {
        self.by_index.remove(&ifindex);
    }

    //////////////////////////////////////////////////////////////////
    /// Get interface entry from IfTable
    //////////////////////////////////////////////////////////////////
    pub fn get_interface(&self, ifindex: u32) -> Option<&Rc<RefCell<Interface>>> {
        self.by_index.get(&ifindex)
    }
    //////////////////////////////////////////////////////////////////
    /// Assign an Ip address to an interface
    //////////////////////////////////////////////////////////////////
    pub fn add_ifaddr(&mut self, ifindex: IfIndex, ifaddr: &IfAddress) -> Result<(), RouterError> {
        if let Some(iface) = self.by_index.get_mut(&ifindex) {
            iface.borrow_mut().add_ifaddr(ifaddr);
            Ok(())
        } else {
            Err(RouterError::NoSuchInterface(ifindex))
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Un-assign an Ip address from an interface.
    //////////////////////////////////////////////////////////////////
    pub fn del_ifaddr(&mut self, ifindex: IfIndex, ifaddr: &IfAddress) {
        if let Some(iface) = self.by_index.get_mut(&ifindex) {
            iface.borrow_mut().del_ifaddr(&(ifaddr.0, ifaddr.1));
        }
        // if interface does not exist or the address was not configured,
        // we'll do nothing
    }

    //////////////////////////////////////////////////////////////////
    /// Detach all interfaces attached to some VRF
    //////////////////////////////////////////////////////////////////
    pub fn detach_vrf_interfaces(&mut self, vrf: &Arc<RwLock<Vrf>>) {
        if let Ok(vrf) = vrf.read() {
            if let Some(fibw) = &vrf.fibw {
                if let Some(fibid) = fibw.as_fibreader().get_id() {
                    for interface in self.by_index.values() {
                        interface.borrow_mut().detach_from_fib(&fibid);
                    }
                }
            }
        } else {
            vrf.clear_poison();
            warn!("Poisoned lock in VRF");
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::fib::fibtype::FibWriter;

    use super::{IfDataDot1q, IfDataEthernet, IfState, IfTable, IfType, Interface, Vrf};
    use crate::fib::fibtype::FibId;
    use crate::interface::Attachment;
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

        /* create Eth2 */
        let mut eth2 = Interface::new("eth2", 4);
        eth2.set_admin_state(IfState::Up);
        eth2.set_oper_state(IfState::Up);
        eth2.set_description("Downlink from Sun");
        eth2.set_iftype(IfType::Dot1q(IfDataDot1q {
            mac: Mac::from([0x0, 0xbb, 0x0, 0x0, 0x0, 0x3]),
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
        iftable.add_interface(eth2);
        iftable.add_interface(vlan100);
        iftable.add_interface(vlan200);

        assert_eq!(iftable.len(), 5);

        iftable
    }

    #[test]
    fn interface_basic() {
        /* create interface table  */
        let iftable = build_test_iftable();

        /* lookup interface with non-existent index */
        let iface = iftable.get_interface(100);
        assert!(iface.is_none());

        /* Lookup interface by ifindex 2 */
        let iface = iftable.get_interface(2);
        assert!(iface.is_some());
        let mut eth0 = iface.unwrap().borrow_mut();
        assert_eq!(eth0.name, "eth0", "We should get eth0");
        assert_eq!(eth0.ifindex, 2, "eth0 has ifindex 2");

        /* Add an ip address (the interface is in the iftable) */
        let address = IpAddr::from_str("10.0.0.1").expect("Bad address");
        eth0.add_ifaddr(&(address, 24));
        assert!(eth0.has_address(&address));

        /* Create a fib */
        let (fibw, fibr) = FibWriter::new(FibId::Id(0));

        /* Create a VRF for that fib */
        #[allow(clippy::arc_with_non_send_sync)]
        let vrf = Arc::new(RwLock::new(Vrf::new("default-vrf", 0, Some(fibw))));

        /* Attach eth0 to the VRF */
        let e = eth0.attach(&vrf);
        assert_eq!(e, Ok(()));
        assert!(matches!(eth0.attachment, Some(Attachment::VRF(_))));
        if let Some(Attachment::VRF(r)) = &eth0.attachment {
            assert_eq!(r.get_id(), fibr.get_id());
        } else {
            unreachable!()
        }

        /* Detach */
        eth0.detach();
        assert!(eth0.attachment.is_none());
    }
}
