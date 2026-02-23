// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarder object. This object contains all of the rules to port-forward the traffic
//! received from a VPC to other VPCs, for a given protocol.

#![allow(unused)]

use super::lpmmap::LpmMap;
use super::objects::PortFwEntry;
use super::rangeset::{PrefixMap, RangeSet, RangeSetError};
use crate::portfw::PortRange;
use lpm::prefix::{IpPrefix, Ipv4Prefix, Ipv6Prefix, Prefix};
use net::ip::UnicastIpAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZero;
use std::sync::Arc;
#[allow(unused)]
use tracing::{debug, warn};

#[derive(Default)]
pub(crate) struct PortForwarder(LpmMap<Arc<PortFwEntry>>);

impl PortForwarder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_rule(&mut self, entry: Arc<PortFwEntry>) -> Result<(), RangeSetError> {
        self.0.insert(entry.ext_prefix, entry.ext_ports, entry)
    }

    pub fn remove_rule(&mut self, entry: &PortFwEntry) -> Option<Arc<PortFwEntry>> {
        self.0.remove(entry.ext_prefix, entry.ext_ports)
    }

    pub fn get_rule(&self, prefix: Prefix, range: PortRange) -> Option<&Arc<PortFwEntry>> {
        self.0.get(prefix, range)
    }

    #[must_use]
    pub fn lookup(&self, address: IpAddr, port: NonZero<u16>) -> Option<&Arc<PortFwEntry>> {
        self.0.lookup_cumulative(address, port)
    }

    #[cfg(test)]
    #[must_use]
    pub fn translate(
        &self,
        address: IpAddr,
        port: NonZero<u16>,
    ) -> Option<(UnicastIpAddr, NonZero<u16>)> {
        self.lookup(address, port)
            .and_then(|rule| rule.map_address_port(address, port))
    }

    #[must_use]
    pub fn lookup_and_translate(
        &self,
        address: IpAddr,
        port: NonZero<u16>,
    ) -> Option<(UnicastIpAddr, NonZero<u16>, &Arc<PortFwEntry>)> {
        let rule = self.lookup(address, port)?;
        let (new_ip, new_port) = rule.map_address_port(address, port)?;
        Some((new_ip, new_port, rule))
    }

    pub fn iter(&self) -> impl Iterator<Item = &PortFwEntry> {
        self.0
            .iter()
            .flat_map(|(_, range)| range.iter().map(|(_, _, rule)| rule.as_ref()))
    }

    pub fn len(&self) -> usize {
        self.0.iter().map(|(_, rangeset)| rangeset.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        !self.0.iter().any(|(_, rangeset)| !rangeset.is_empty())
    }
}

#[cfg(test)]
mod test {
    use crate::portfw::{PortFwEntry, PortFwKey};
    use net::ip::NextHeader;
    use net::packet::VpcDiscriminant;
    use std::num::NonZero;
    use std::sync::Arc;

    use super::{PortForwarder, PrefixMap};
    use lpm::prefix::Prefix;
    use std::net::IpAddr;
    use std::str::FromStr;
    use tracing_test::traced_test;

    fn rule(from: &str, to: &str, p1: (u16, u16), p2: (u16, u16)) -> Arc<PortFwEntry> {
        let key = PortFwKey::new(
            VpcDiscriminant::from_vni(2000.try_into().unwrap()),
            NextHeader::TCP,
        );
        PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str(from).unwrap(),
            Prefix::from_str(to).unwrap(),
            p1,
            p2,
            None,
            None,
        )
        .unwrap()
        .arced()
    }

    #[test]
    fn test_port_forwarder_rule_insertion() {
        let mut pf = PortForwarder::default();

        // insert rule: should succeed
        let r = rule(
            "70.71.72.0/24",
            "192.168.1.0/24",
            (3000, 3022),
            (1000, 1022),
        );
        pf.insert_rule(r).unwrap();

        // insert rule, same prefixes, overlapping ports: FAIL
        let r = rule(
            "70.71.72.0/24",
            "192.168.1.0/24",
            (3022, 3022),
            (1022, 1022),
        );
        assert!(pf.insert_rule(r).is_err());

        // insert rule, prefix overlaps, but not the ports: should succeed
        let r = rule(
            "70.71.72.0/27",
            "192.168.2.0/27",
            (4022, 4022),
            (1033, 1033),
        );
        assert!(pf.insert_rule(r).is_ok());

        // insert rule: prefix overlaps, but not the ports: should succeed
        let r = rule("70.71.0.0/16", "192.168.0.0/16", (999, 999), (888, 888));
        assert!(pf.insert_rule(r).is_ok());
    }

    #[test]
    fn test_port_forwarder_rule_removal() {
        let mut pf = PortForwarder::default();
        // insert rules
        let r1 = rule(
            "70.71.72.0/24",
            "192.168.1.0/24",
            (3000, 3000),
            (1000, 1000),
        );
        pf.insert_rule(r1.clone()).unwrap();
        let r2 = rule(
            "70.71.72.0/24",
            "192.168.1.0/24",
            (3001, 3001),
            (1001, 1001),
        );
        pf.insert_rule(r2.clone()).unwrap();
        let r3 = rule(
            "70.71.72.0/24",
            "192.168.1.0/24",
            (4000, 4010),
            (2050, 2060),
        );
        pf.insert_rule(r3.clone()).unwrap();

        // check we can look them up by prefix and port range
        assert_eq!(pf.get_rule(r1.ext_prefix, r1.ext_ports), Some(&r1));
        assert_eq!(pf.get_rule(r2.ext_prefix, r2.ext_ports), Some(&r2));
        assert_eq!(pf.get_rule(r3.ext_prefix, r3.ext_ports), Some(&r3));

        assert_eq!(pf.len(), 3);
        assert!(!pf.is_empty());

        pf.remove_rule(r1.as_ref()).unwrap();
        assert_eq!(pf.get_rule(r1.ext_prefix, r1.ext_ports), None);
        assert_eq!(pf.get_rule(r2.ext_prefix, r2.ext_ports), Some(&r2));
        assert_eq!(pf.get_rule(r3.ext_prefix, r3.ext_ports), Some(&r3));

        assert_eq!(pf.len(), 2);
        assert!(!pf.is_empty());

        pf.remove_rule(r2.as_ref()).unwrap();
        assert_eq!(pf.get_rule(r1.ext_prefix, r1.ext_ports), None);
        assert_eq!(pf.get_rule(r2.ext_prefix, r2.ext_ports), None);
        assert_eq!(pf.get_rule(r3.ext_prefix, r3.ext_ports), Some(&r3));

        assert_eq!(pf.len(), 1);
        assert!(!pf.is_empty());

        pf.remove_rule(r3.as_ref()).unwrap();
        assert_eq!(pf.get_rule(r1.ext_prefix, r1.ext_ports), None);
        assert_eq!(pf.get_rule(r2.ext_prefix, r2.ext_ports), None);
        assert_eq!(pf.get_rule(r3.ext_prefix, r3.ext_ports), None);

        assert_eq!(pf.len(), 0);
        assert!(pf.is_empty());
    }

    fn check(pf: &PortForwarder, dst_ip: &str, dst_port: u16) -> Option<(String, u16)> {
        let dst_ip = IpAddr::from_str(dst_ip).unwrap();
        let dst_port = NonZero::new(dst_port).unwrap();
        let Some(rule) = pf.lookup(dst_ip, dst_port) else {
            println!("{dst_ip}:{dst_port} hits NO rule");
            return None;
        };
        println!("{dst_ip}:{dst_port} hits rule {rule}");
        let (new_ip, new_port) = pf.translate(dst_ip, dst_port).unwrap();
        println!("{dst_ip}:{dst_port} -> {new_ip}:{new_port}");
        Some((new_ip.to_string(), new_port.get()))
    }

    #[test]
    fn test_port_forwarder() {
        let mut pf = PortForwarder::default();
        let r = rule(
            "70.71.72.0/24",
            "192.168.1.0/24",
            (3000, 3022),
            (1000, 1022),
        );
        pf.insert_rule(r).unwrap();

        let r = rule(
            "70.71.72.0/24",
            "192.168.1.0/24",
            (3023, 3023),
            (5000, 5000),
        );
        pf.insert_rule(r).unwrap();

        let r = rule(
            "70.71.71.0/27",
            "192.168.2.0/27",
            (4000, 4010),
            (1000, 1010),
        );
        pf.insert_rule(r).unwrap();

        assert_eq!(
            check(&pf, "70.71.72.0", 3000),
            Some(("192.168.1.0".to_string(), 1000))
        );
        assert_eq!(
            check(&pf, "70.71.72.3", 3003),
            Some(("192.168.1.3".to_string(), 1003))
        );
        assert_eq!(
            check(&pf, "70.71.72.255", 3022),
            Some(("192.168.1.255".to_string(), 1022))
        );

        assert_eq!(
            check(&pf, "70.71.72.1", 3023),
            Some(("192.168.1.1".to_string(), 5000))
        );

        assert_eq!(check(&pf, "70.71.72.0", 2999), None);
        assert_eq!(check(&pf, "70.71.72.0", 3024), None);
        assert_eq!(check(&pf, "70.71.71.255", 4000), None);
        assert_eq!(
            check(&pf, "70.71.71.1", 4000),
            Some(("192.168.2.1".to_string(), 1000))
        );
    }
}
