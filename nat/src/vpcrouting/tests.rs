// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Overlay routing test

#[cfg(test)]
mod test {
    use crate::portfw::PortRange;
    use crate::vpcrouting::routing::{Action, OvelayRoute};
    use crate::vpcrouting::routing::{EgressVpcPolicyMap, IngressKey, IngressMap};
    use crate::vpcrouting::routing::{OverlayRouting, PacketSummary};
    use crate::vpcrouting::routing::{VpcRoutingError, VpcRoutingTable};

    use lpm::prefix::Prefix;
    use net::ip::NextHeader;
    use net::packet::VpcDiscriminant;
    use net::vxlan::Vni;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::net::IpAddr;
    use std::num::NonZero;
    use std::str::FromStr;
    use tracing_test::traced_test;

    fn hash_value<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }
    fn mk_ingress_key(vni: u32, proto: Option<NextHeader>) -> IngressKey {
        IngressKey::new(
            VpcDiscriminant::from_vni(Vni::new_checked(vni).unwrap()),
            proto,
        )
    }

    #[test]
    fn test_ingress_map_keys() {
        let k1 = mk_ingress_key(3000, Some(NextHeader::TCP));
        println!("key: {k1} hash {}", hash_value(&k1));

        let k2 = mk_ingress_key(3000, Some(NextHeader::UDP));
        println!("key: {k2} hash {}", hash_value(&k2));

        let icmp = mk_ingress_key(3000, Some(NextHeader::ICMP));
        let reference = hash_value(&icmp);

        let other = mk_ingress_key(3000, Some(NextHeader::ICMP6));
        assert_eq!(hash_value(&other), reference);

        let other = mk_ingress_key(3000, Some(NextHeader::GRE));
        assert_eq!(hash_value(&other), reference);

        let other = mk_ingress_key(3000, Some(NextHeader::ESP));
        assert_eq!(hash_value(&other), reference);

        let other = mk_ingress_key(3000, Some(NextHeader::AH));
        assert_eq!(hash_value(&other), reference);
    }

    fn disc(vni: u32) -> VpcDiscriminant {
        VpcDiscriminant::from_vni(Vni::new_checked(vni).unwrap())
    }
    fn mk_port(port: u16) -> NonZero<u16> {
        NonZero::new(port).unwrap()
    }
    fn mk_route(
        dst_vni: u32,
        prefix: &str,
        proto: Option<NextHeader>,
        ports: Option<(u16, u16)>,
        action: Action,
    ) -> OvelayRoute {
        OvelayRoute::new(
            disc(dst_vni),
            Prefix::from_str(prefix).unwrap(),
            proto,
            ports.map(|(first, last)| PortRange::new(first, last).unwrap()),
            action,
        )
    }
    fn mk_route_insert(
        imap: &mut IngressMap,
        src_vni: u32,
        dst_vni: u32,
        prefix: &str,
        proto: Option<NextHeader>,
        ports: Option<(u16, u16)>,
        action: Action,
    ) -> Result<(), VpcRoutingError> {
        let route = mk_route(dst_vni, prefix, proto, ports, action);
        imap.insert_route(disc(src_vni), &route.into())
    }
    fn mk_route_insert_default(
        imap: &mut IngressMap,
        src_vni: u32,
        dst_vni: u32,
        prefix: &str,
        proto: Option<NextHeader>,
        ports: Option<(u16, u16)>,
        action: Action,
    ) -> Result<(), VpcRoutingError> {
        let route = mk_route(dst_vni, prefix, proto, ports, action);
        imap.set_default(disc(src_vni), route)
    }

    #[test]
    fn test_vpc_routing_table() {
        let mut table = VpcRoutingTable::new();
        let route = mk_route(
            4000,
            "192.168.90.0/24",
            None,
            Some((20, 30)),
            Action::Forward,
        );
        table.insert_route(route.into()).unwrap();

        let route = mk_route(
            4000,
            "192.168.80.0/24",
            Some(NextHeader::TCP),
            Some((100, 200)),
            Action::PortForward,
        );
        table.insert_route(route.into()).unwrap();

        let route = mk_route(
            4000,
            "192.168.80.0/24",
            Some(NextHeader::TCP),
            Some((201, 300)),
            Action::PortForward,
        );
        table.insert_route(route.into()).unwrap();

        let route = mk_route(
            4000,
            "192.168.80.0/24",
            Some(NextHeader::TCP),
            Some((301, 400)),
            Action::PortForward,
        );
        table.insert_route(route.into()).unwrap();

        let route = mk_route(
            4000,
            "192.168.0.0/16",
            None,
            Some((1000, 2000)),
            Action::PortForward,
        );
        table.insert_route(route.into()).unwrap();
        table.rt.resolve_overlaps().unwrap();

        println!("{table:#?}");
    }

    #[test]
    fn test_ingress_map_1() {
        let mut imap = IngressMap::new();

        let route = mk_route(
            4000,
            "192.168.80.0/24",
            Some(NextHeader::TCP),
            Some((301, 400)),
            Action::PortForward,
        );
        imap.insert_route(disc(3000), &route.into()).unwrap();

        let route = mk_route(
            4000,
            "192.168.0.0/17",
            Some(NextHeader::TCP),
            Some((401, 500)),
            Action::PortForward,
        );
        imap.insert_route(disc(3000), &route.into()).unwrap();

        let route = mk_route(4000, "192.168.0.0/16", None, None, Action::StaticNat);
        imap.insert_route(disc(3000), &route.into()).unwrap();

        let route = mk_route(4000, "192.168.0.0/16", None, None, Action::StaticNat);
        imap.insert_route(disc(3000), &route.into()).unwrap();

        let route = mk_route(
            5000,
            "192.168.70.0/24",
            Some(NextHeader::TCP),
            Some((501, 1500)),
            Action::PortForward,
        );
        imap.insert_route(disc(3000), &route.into()).unwrap();

        //imap.resolve_overlaps();
        println!("{imap}");
    }

    #[test]
    fn test_ingress_map_overlap() {
        let mut imap = IngressMap::new();

        let route = mk_route(4000, "192.168.80.0/24", None, None, Action::Masquerade);
        imap.insert_route(disc(3000), &route.into()).unwrap();

        let route = mk_route(4000, "192.168.90.0/24", None, None, Action::Masquerade);
        imap.insert_route(disc(3000), &route.into()).unwrap();

        println!("{imap}");
    }

    #[allow(clippy::too_many_lines)]
    fn build_ingress_map() -> IngressMap {
        let mut imap = IngressMap::new();

        // 3000 -> 4000
        mk_route_insert(
            &mut imap,
            3000,
            4000,
            "20.10.90.0/24",
            Some(NextHeader::TCP),
            Some((2222, 2222)),
            Action::PortForward,
        )
        .unwrap();

        mk_route_insert(
            &mut imap,
            3000,
            4000,
            "20.10.90.0/24",
            Some(NextHeader::TCP),
            Some((80, 80)),
            Action::PortForward,
        )
        .unwrap();

        mk_route_insert(
            &mut imap,
            3000,
            4000,
            "20.10.90.0/24",
            Some(NextHeader::UDP),
            Some((2053, 2053)),
            Action::PortForward,
        )
        .unwrap();

        mk_route_insert(
            &mut imap,
            3000,
            4000,
            "192.168.70.0/24",
            None,
            None,
            Action::Forward,
        )
        .unwrap();

        mk_route_insert(
            &mut imap,
            3000,
            4000,
            "192.168.80.0/24",
            Some(NextHeader::UDP),
            Some((2053, 2053)),
            Action::Forward,
        )
        .unwrap();

        // 3000 -> 2000
        mk_route_insert(
            &mut imap,
            3000,
            2000,
            "30.10.128.0/27",
            None,
            None,
            Action::StaticNat,
        )
        .unwrap();

        mk_route_insert(
            &mut imap,
            3000,
            2000,
            "20.10.128.0/27",
            Some(NextHeader::TCP),
            Some((22, 22)),
            Action::PortForward,
        )
        .unwrap();

        mk_route_insert(
            &mut imap,
            3000,
            2000,
            "192.168.128.0/24",
            None,
            None,
            Action::Forward,
        )
        .unwrap();

        // 3000 -> 8000
        mk_route_insert_default(
            &mut imap,
            3000,
            8000,
            "0.0.0.0/0",
            None,
            None,
            Action::Forward,
        )
        .unwrap();

        // 3000 -> 1000
        mk_route_insert(
            &mut imap,
            3000,
            1000,
            "10.0.0.0/16",
            None,
            None,
            Action::Forward,
        )
        .unwrap();

        // fails due to insertion of /16 and all ports
        mk_route_insert(
            &mut imap,
            3000,
            1000,
            "10.0.0.1/32",
            Some(NextHeader::TCP),
            Some((180, 180)),
            Action::PortForward,
        )
        .unwrap();

        mk_route_insert(
            &mut imap,
            3000,
            1000,
            "10.0.1.0/24",
            None,
            None,
            Action::Forward,
        )
        .unwrap();

        mk_route_insert(
            &mut imap,
            3000,
            1000,
            "10.0.1.0/25",
            None,
            None,
            Action::StaticNat,
        )
        .unwrap();

        mk_route_insert(
            &mut imap,
            3000,
            1000,
            "10.0.1.128/25",
            None,
            None,
            Action::Drop,
        )
        .unwrap();

        println!("{imap}");
        imap
    }

    #[test]
    #[traced_test]
    fn test_ingress_map_lookup() {
        let imap = build_ingress_map();

        let dst_addr = IpAddr::from_str("20.10.90.1").unwrap();
        let proto = NextHeader::TCP;
        let dst_port = Some(mk_port(2222));
        let route = imap.lookup(disc(3000), proto, dst_addr, dst_port).unwrap();
        println!("hit route: {route}");

        let dst_addr = IpAddr::from_str("192.168.128.1").unwrap();
        let proto = NextHeader::TCP;
        let dst_port = Some(mk_port(2223));
        let route = imap.lookup(disc(3000), proto, dst_addr, dst_port).unwrap();
        println!("hit route: {route}");

        let dst_addr = IpAddr::from_str("192.168.128.1").unwrap();
        let proto = NextHeader::UDP;
        let dst_port = Some(mk_port(53));
        let route = imap.lookup(disc(3000), proto, dst_addr, dst_port).unwrap();
        println!("hit route: {route}");

        let dst_addr = IpAddr::from_str("192.168.128.1").unwrap();
        let proto = NextHeader::ICMP;
        let dst_port = None;
        let route = imap.lookup(disc(3000), proto, dst_addr, dst_port).unwrap();
        println!("hit route: {route}");

        let dst_addr = IpAddr::from_str("192.168.128.1").unwrap();
        let proto = NextHeader::GRE;
        let dst_port = None;
        let route = imap.lookup(disc(3000), proto, dst_addr, dst_port).unwrap();
        println!("hit route: {route}");

        let dst_addr = IpAddr::from_str("8.8.8.8").unwrap();
        let proto = NextHeader::GRE;
        let dst_port = None;
        let route = imap.lookup(disc(3000), proto, dst_addr, dst_port).unwrap();
        println!("hit route: {route}");
    }

    #[test]
    fn test_egress_vpc_policy_map() {
        let mut policy_map = EgressVpcPolicyMap::new();

        let prefix = Prefix::from_str("192.168.50.0/24").unwrap();
        policy_map.insert(disc(3000), prefix, disc(4000), Action::Forward);
        policy_map.insert(disc(3000), prefix, disc(2000), Action::StaticNat);
        policy_map.insert(disc(3000), prefix, disc(6000), Action::Masquerade);

        let prefix = Prefix::from_str("192.168.50.0/27").unwrap();
        policy_map.insert(disc(3000), prefix, disc(5000), Action::StaticNat);
        policy_map.insert(disc(3000), prefix, disc(2000), Action::Masquerade);

        let prefix = Prefix::from_str("192.168.50.128/27").unwrap();
        policy_map.insert(disc(3000), prefix, disc(5000), Action::Forward);
        policy_map.insert(disc(3000), prefix, disc(9000), Action::StaticNat);

        let prefix = Prefix::from_str("192.168.60.0/24").unwrap();
        policy_map.insert(disc(3000), prefix, disc(4000), Action::Masquerade);

        let prefix = Prefix::from_str("192.168.50.140/32").unwrap();
        policy_map.insert(disc(3000), prefix, disc(4000), Action::Drop);

        let address = IpAddr::from_str("192.168.50.1").unwrap();
        let (_, policy) = policy_map.lookup(disc(3000), address, disc(4000)).unwrap();
        assert_eq!(policy.action, Action::Forward);

        let address = IpAddr::from_str("192.168.50.1").unwrap();
        let (_, policy) = policy_map.lookup(disc(3000), address, disc(2000)).unwrap();
        assert_eq!(policy.action, Action::Masquerade);

        let address = IpAddr::from_str("192.168.50.1").unwrap();
        let (_, policy) = policy_map.lookup(disc(3000), address, disc(6000)).unwrap();
        assert_eq!(policy.action, Action::Masquerade);

        let address = IpAddr::from_str("192.168.50.1").unwrap();
        let (_, policy) = policy_map.lookup(disc(3000), address, disc(5000)).unwrap();
        assert_eq!(policy.action, Action::StaticNat);

        let address = IpAddr::from_str("192.168.50.129").unwrap();
        let (_, policy) = policy_map.lookup(disc(3000), address, disc(5000)).unwrap();
        assert_eq!(policy.action, Action::Forward);

        let address = IpAddr::from_str("192.168.50.140").unwrap();
        let (_, policy) = policy_map.lookup(disc(3000), address, disc(4000)).unwrap();
        assert_eq!(policy.action, Action::Drop);

        let address = IpAddr::from_str("192.168.50.128").unwrap();
        let (_, policy) = policy_map.lookup(disc(3000), address, disc(5000)).unwrap();
        assert_eq!(policy.action, Action::Forward);

        let address = IpAddr::from_str("192.168.50.128").unwrap();
        let (_, policy) = policy_map.lookup(disc(3000), address, disc(9000)).unwrap();
        assert_eq!(policy.action, Action::StaticNat);

        println!("{policy_map}");
    }

    fn build_egress_vpc_policy_map() -> EgressVpcPolicyMap {
        let mut policy_map = EgressVpcPolicyMap::new();

        let prefix = Prefix::from_str("192.168.50.0/24").unwrap();
        policy_map.insert(disc(3000), prefix, disc(4000), Action::Forward);

        let prefix = Prefix::from_str("192.168.50.128/25").unwrap();
        policy_map.insert(disc(3000), prefix, disc(2000), Action::StaticNat);

        let prefix = Prefix::from_str("192.168.50.13/32").unwrap();
        policy_map.insert(disc(3000), prefix, disc(6000), Action::Masquerade);

        let prefix = Prefix::from_str("192.168.60.0/24").unwrap();
        policy_map.insert(disc(3000), prefix, disc(4000), Action::Forward);

        let prefix = Prefix::from_str("192.168.50.128/27").unwrap();
        policy_map.insert(disc(3000), prefix, disc(4000), Action::Drop);

        let prefix = Prefix::from_str("192.168.60.0/24").unwrap();
        policy_map.insert(disc(3000), prefix, disc(4000), Action::StaticNat);

        let prefix = Prefix::from_str("192.168.60.0/24").unwrap();
        policy_map.insert(disc(3000), prefix, disc(2000), Action::Masquerade);

        let prefix = Prefix::from_str("192.168.60.0/24").unwrap();
        policy_map.insert(disc(3000), prefix, disc(8000), Action::Forward);

        println!("{policy_map}");
        policy_map
    }

    #[test]
    //#[traced_test]
    fn test_complete_vpc_routing() {
        let imap = build_ingress_map();
        let emap = build_egress_vpc_policy_map();
        let ort = OverlayRouting::new(1, imap, emap);

        // ======== /
        let s = PacketSummary {
            src_vpcd: disc(3000),
            src_addr: IpAddr::from_str("192.168.50.200").unwrap(),
            dst_addr: IpAddr::from_str("20.10.90.100").unwrap(),
            proto: NextHeader::UDP,
            src_port: Some(mk_port(12356)),
            dst_port: Some(mk_port(2053)),
        };
        let (dst_vpcd, local, remote) = ort.lookup(&s).unwrap();
        println!("{s} -> {dst_vpcd} {local} {remote}");
        assert_eq!(dst_vpcd, disc(4000));
        assert_eq!(local, Action::Forward);
        assert_eq!(remote, Action::PortForward);

        // ======== /
        let s = PacketSummary {
            src_vpcd: disc(3000),
            src_addr: IpAddr::from_str("192.168.50.200").unwrap(),
            dst_addr: IpAddr::from_str("20.10.90.100").unwrap(),
            proto: NextHeader::TCP,
            src_port: Some(mk_port(9999)),
            dst_port: Some(mk_port(2222)),
        };
        let (dst_vpcd, local, remote) = ort.lookup(&s).unwrap();
        println!("{s} -> {dst_vpcd} {local} {remote}");
        assert_eq!(dst_vpcd, disc(4000));
        assert_eq!(local, Action::Forward);
        assert_eq!(remote, Action::PortForward);

        // ======== /
        let s = PacketSummary {
            src_vpcd: disc(3000),
            src_addr: IpAddr::from_str("192.168.50.200").unwrap(),
            dst_addr: IpAddr::from_str("20.10.90.100").unwrap(),
            proto: NextHeader::TCP,
            src_port: Some(mk_port(9999)),
            dst_port: Some(mk_port(2221)),
        };
        assert!(ort.lookup(&s).is_none());

        // ======== /
        let s = PacketSummary {
            src_vpcd: disc(3000),
            src_addr: IpAddr::from_str("192.168.60.1").unwrap(),
            dst_addr: IpAddr::from_str("192.168.70.1").unwrap(),
            proto: NextHeader::ICMP,
            src_port: None,
            dst_port: None,
        };
        let (dst_vpcd, local, remote) = ort.lookup(&s).unwrap();
        println!("{s} -> {dst_vpcd} {local} {remote}");
        assert_eq!(dst_vpcd, disc(4000));
        assert_eq!(local, Action::StaticNat);
        assert_eq!(remote, Action::Forward);

        // ======== /
        let s = PacketSummary {
            src_vpcd: disc(3000),
            src_addr: IpAddr::from_str("192.168.60.1").unwrap(),
            dst_addr: IpAddr::from_str("192.168.128.1").unwrap(),
            proto: NextHeader::ICMP,
            src_port: None,
            dst_port: None,
        };
        let (dst_vpcd, local, remote) = ort.lookup(&s).unwrap();
        println!("{s} -> {dst_vpcd} {local} {remote}");
        assert_eq!(dst_vpcd, disc(2000));
        assert_eq!(local, Action::Masquerade);
        assert_eq!(remote, Action::Forward);

        // ======== /
        let s = PacketSummary {
            src_vpcd: disc(3000),
            src_addr: IpAddr::from_str("192.168.60.1").unwrap(),
            dst_addr: IpAddr::from_str("192.168.80.1").unwrap(),
            proto: NextHeader::UDP,
            src_port: Some(mk_port(44444)),
            dst_port: Some(mk_port(2053)),
        };
        let (dst_vpcd, local, remote) = ort.lookup(&s).unwrap();
        println!("{s} -> {dst_vpcd} {local} {remote}");
        assert_eq!(dst_vpcd, disc(4000));
        assert_eq!(local, Action::StaticNat);
        assert_eq!(remote, Action::Forward);

        // ======== /
        let s = PacketSummary {
            src_vpcd: disc(3000),
            src_addr: IpAddr::from_str("192.168.60.1").unwrap(),
            dst_addr: IpAddr::from_str("8.8.8.8").unwrap(),
            proto: NextHeader::UDP,
            src_port: Some(mk_port(44444)),
            dst_port: Some(mk_port(2053)),
        };
        let (dst_vpcd, local, remote) = ort.lookup(&s).unwrap();
        println!("{s} -> {dst_vpcd} {local} {remote}");
        assert_eq!(dst_vpcd, disc(8000));
        assert_eq!(local, Action::Forward);
        assert_eq!(remote, Action::Forward);

        let s = PacketSummary {
            src_vpcd: disc(3000),
            src_addr: IpAddr::from_str("192.168.50.1").unwrap(),
            dst_addr: IpAddr::from_str("8.8.8.8").unwrap(),
            proto: NextHeader::UDP,
            src_port: Some(mk_port(44444)),
            dst_port: Some(mk_port(2053)),
        };
        assert!(ort.lookup(&s).is_none());
    }
}
